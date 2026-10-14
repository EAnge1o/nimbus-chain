"""SPV 轻客户端：只下载区块头，用 Merkle 证明确认交易。

全节点要存下整条链的每一笔交易；轻客户端（SPV）只存 **80 字节的区块头**，
因此可以跑在手机上。它能得到的安全性来自两件事：

1. **区块头自带 PoW**：篡改任何区块头都要重做工作量证明；而且头部通过
   ``prev_block`` 串成一条链，改一处就要改其后所有块。
2. **Merkle 证明**：不需要交易列表，只需 ``log2(n)`` 个哈希就能证明「某笔交易
   确实被某一个区块头承诺过」。

本模块刻意**不信任**全节点提供的任何东西：难度 ``bits`` 由客户端按和历史
时间戳独立重算（与全节点共用 :func:`~nimbus_chain.block.compute_retarget_bits`），
时间戳必须大于本地 MTP，PoW 必须自行验证。全节点能骗它的唯一方式是提供一条
从头作假的 PoW 链——而那正是 PoW 要阻止的事情。

局限（诚实声明）：本实现只跟随**单条**头链，不做竞争头链的分叉选择；也不做
bloom filter 过滤，区块头由调用方成批喂进来。
"""

from __future__ import annotations

from .block import BlockHeader, compute_retarget_bits
from .chain import DEFAULT_PARAMS, ChainParams, create_genesis_block
from .merkle import MerkleProofError, verify_merkle_proof

__all__ = ["SPVError", "SPVClient"]

_MTP_WINDOW = 11


class SPVError(ValueError):
    """头链校验失败。"""


class SPVClient:
    """只保存区块头的链，可验证交易是否被某个已知区块承诺过。"""

    def __init__(self, params: ChainParams | None = None,
                 genesis_header: BlockHeader | None = None) -> None:
        self.params = params or DEFAULT_PARAMS
        if genesis_header is None:
            genesis_header = create_genesis_block(self.params).header
        self._headers: list[BlockHeader] = [genesis_header]
        self._by_hash: dict[bytes, int] = {genesis_header.hash(): 0}

    # -- 视图 ------------------------------------------------------------- #

    def __len__(self) -> int:
        return len(self._headers)

    @property
    def height(self) -> int:
        return len(self._headers) - 1

    @property
    def tip_header(self) -> BlockHeader:
        return self._headers[-1]

    @property
    def tip_hash(self) -> bytes:
        return self.tip_header.hash()

    def header_at_height(self, height: int) -> BlockHeader | None:
        if 0 <= height < len(self._headers):
            return self._headers[height]
        return None

    def height_of(self, block_hash: bytes) -> int | None:
        return self._by_hash.get(block_hash)

    def has_header(self, block_hash: bytes) -> bool:
        return block_hash in self._by_hash

    def local_bytes(self) -> int:
        """本地存储量：只有区块头。"""
        return len(self._headers) * 80

    # -- 共识规则（独立重算，不采信对端） -------------------------------- #

    def median_time_past(self) -> int:
        window = [header.timestamp for header in self._headers[-_MTP_WINDOW:]]
        return sorted(window)[len(window) // 2]

    def expected_bits_at(self, height: int) -> int:
        """第 ``height`` 个高度应有的 ``bits``（按本地已存头部重算）。"""
        if height <= 0 or height > len(self._headers):
            raise SPVError(f"cannot compute difficulty for height {height}")
        prev_header = self._headers[height - 1]
        interval = self.params.retarget_interval
        if interval <= 0 or height % interval != 0:
            return prev_header.bits

        first_index = height - 1 - (interval - 1)
        if first_index < 0:
            # 头部还不够长，无法重算；沿用父块难度（并在 check_header 里如实说明）
            return prev_header.bits
        actual_timespan = prev_header.timestamp - self._headers[first_index].timestamp
        return compute_retarget_bits(
            prev_header.bits,
            actual_timespan,
            interval=interval,
            target_block_time=self.params.target_block_time,
            max_adjustment_factor=self.params.max_adjustment_factor,
            pow_limit_bits=self.params.pow_limit_bits,
        )

    # -- 校验 ------------------------------------------------------------- #

    def check_header(self, header: BlockHeader) -> tuple[bool, str]:
        """只校验、不入链，返回 ``(是否合法, 原因)``。"""
        if header.hash() in self._by_hash:
            return False, "header is already known"
        if header.prev_block != self.tip_hash:
            return False, "header does not extend the current tip"
        if not header.has_valid_pow():
            return False, "proof of work is not satisfied"
        height = len(self._headers)
        expected = self.expected_bits_at(height)
        if header.bits != expected:
            return False, f"unexpected difficulty: got 0x{header.bits:08x}, want 0x{expected:08x}"
        if header.timestamp <= self.median_time_past():
            return False, "timestamp is not greater than median time past"
        return True, "ok"

    def add_header(self, header: BlockHeader) -> int:
        """校验并追加一个区块头，返回它的高度；失败抛 :class:`SPVError`。"""
        valid, reason = self.check_header(header)
        if not valid:
            raise SPVError(reason)
        block_hash = header.hash()
        self._headers.append(header)
        self._by_hash[block_hash] = len(self._headers) - 1
        return len(self._headers) - 1

    def sync(self, headers) -> int:
        """按顺序喂入一批区块头，返回成功追加的数量。"""
        added = 0
        for header in headers:
            self.add_header(header)
            added += 1
        return added

    def sync_from_chain(self, chain) -> int:
        """从全节点取主链的区块头（真实场景下这些头来自 P2P 的 ``getheaders``）。"""
        return self.sync([block.header for block in chain.main_blocks()[1:]])

    # -- 交易存在性证明 --------------------------------------------------- #

    def confirmations(self, block_hash: bytes) -> int:
        height = self._by_hash.get(block_hash)
        if height is None:
            return 0
        return self.height - height + 1

    def verify_transaction_inclusion(self, txid: bytes, block_hash: bytes,
                                     proof: list[tuple[bytes, str]]) -> bool:
        """用 Merkle 证明验证「``txid`` 属于区块 ``block_hash``」。

        关键在于：证明必须挂到**本地已通过 PoW 校验的区块头**上。若对端给出一个
        你从未验证过的 ``block_hash``，证明再漂亮也毫无意义。
        """
        height = self._by_hash.get(block_hash)
        if height is None:
            raise SPVError(f"unknown block header {block_hash[::-1].hex()}")
        header = self._headers[height]
        try:
            return verify_merkle_proof(txid, proof, header.merkle_root)
        except MerkleProofError:
            return False

    def stats(self) -> dict:
        return {
            "headers": len(self._headers),
            "height": self.height,
            "tip": self.tip_hash[::-1].hex(),
            "local_bytes": self.local_bytes(),
            "next_bits": f"0x{self.expected_bits_at(len(self._headers)):08x}",
        }

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"SPVClient(height={self.height}, local_bytes={self.local_bytes()})"

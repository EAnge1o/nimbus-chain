"""区块链：校验流水线、难度重定目标、累计工作量分叉选择与重组、UTXO 集。

这是整个项目最核心的模块。它把前面几层（密码学、脚本、交易、PoW）串成一条
真正的链，并回答三个关键问题：

1. **这个块能不能接上去？** —— 校验流水线：父块存在、PoW 达标、难度 ``bits``
   与规则一致、时间戳大于过去 11 个块的中位数、Merkle 根匹配、区块内无重复
   交易、且每条非 coinbase 输入都能在 UTXO 里找到、签名通过、coinbase 不超发。
2. **哪条链才是「真的」？** —— 不是最长，而是**累计工作量最大**。``block_work``
   把每个块的难度累加起来，短而高难度的分叉可以击败长而低难度的分叉。
3. **换链之后账本怎么算？** —— 每个已连接的块都保存一份 *undo* 记录（花了哪些
   UTXO、新建了哪些 UTXO）。重组时逐个断开并还原，再把新分支逐块连上；被挤出
   主链的非 coinbase 交易会被交还给调用方（通常是交易池）。

两条路径互相印证：扩展链尖时用**增量** UTXO 集，验证分叉块时用**全量重放**
算出的 UTXO 集；测试里会断言两者在所有情况下完全一致。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

from .block import (
    MAX_BLOCK_SIZE,
    POW_LIMIT_BITS,
    Block,
    BlockHeader,
    bits_to_target,
    block_work,
    compute_retarget_bits,
    mine,
    target_to_bits,
)
from .crypto import hash256  # noqa: F401  (便于下游从 chain 复用哈希工具)
from .merkle import merkle_root
from .script import p2pkh_script, verify_input
from .secp256k1 import PrivateKey
from .tx import (
    COINBASE_MATURITY,
    HALVING_INTERVAL,
    INITIAL_SUBSIDY,
    Transaction,
    TxOut,
    block_subsidy,
    checker_for,
    coinbase_transaction,
)

__all__ = [
    "ChainParams",
    "DEFAULT_PARAMS",
    "GENESIS_TIMESTAMP",
    "ChainError",
    "InvalidBlock",
    "UTXO",
    "BlockUndo",
    "AddBlockResult",
    "Chain",
    "create_genesis_block",
    "unique_extra_nonce",
]

GENESIS_TIMESTAMP = 1_767_225_600  # 2026-01-01T00:00:00Z，固定值保证创世哈希可复现
_GENESIS_EXTRA_NONCE = b"nimbus-chain genesis / zero-dependency blockchain"


class ChainError(ValueError):
    """链级别错误。"""


class InvalidBlock(ChainError):
    """区块未通过共识校验。"""


# --------------------------------------------------------------------------- #
# 链参数
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ChainParams:
    """共识参数。默认值面向「演示 + 教学」：难度足够低，挖块在秒级完成。"""

    retarget_interval: int = 16
    target_block_time: int = 600          # 期望出块间隔（秒）
    max_adjustment_factor: int = 4        # 单次难度调整的最大倍数（Bitcoin 同款）
    pow_limit_bits: int = POW_LIMIT_BITS  # 最松难度（初始与下限）
    coinbase_maturity: int = COINBASE_MATURITY
    halving_interval: int = HALVING_INTERVAL
    initial_subsidy: int = INITIAL_SUBSIDY

    @property
    def target_timespan(self) -> int:
        return self.retarget_interval * self.target_block_time


DEFAULT_PARAMS = ChainParams()


# --------------------------------------------------------------------------- #
# UTXO / undo 记录
# --------------------------------------------------------------------------- #


@dataclass
class UTXO:
    """一个未花费输出，外加「它是在哪个高度被谁创造的」这两个关键属性。

    没有 ``height`` / ``is_coinbase``，就没法实现 coinbase 成熟度规则——而这条
    规则是防住「同一份算力反复套现」的关键。
    """

    tx_out: TxOut
    height: int
    is_coinbase: bool

    @property
    def value(self) -> int:
        return self.tx_out.value


@dataclass
class BlockUndo:
    """连接一个块时对 UTXO 集所做的全部改动，用于重组时精确回滚。"""

    spent: list[tuple[tuple[bytes, int], UTXO]] = field(default_factory=list)
    created: list[tuple[bytes, int]] = field(default_factory=list)


@dataclass
class AddBlockResult:
    """``add_block`` 的返回值：块被接上、存为侧链，还是触发了重组。"""

    status: str                      # 'connected' | 'reorg' | 'side_chain' | 'duplicate'
    block_hash: bytes
    height: int
    connected: list[bytes] = field(default_factory=list)
    disconnected: list[bytes] = field(default_factory=list)
    reaccepted: list[Transaction] = field(default_factory=list)
    branch_work: int | None = None

    @property
    def is_reorg(self) -> bool:
        return self.status == "reorg"


# --------------------------------------------------------------------------- #
# 创世块
# --------------------------------------------------------------------------- #


def _genesis_script_pubkey() -> bytes:
    """创世 coinbase 付给私钥为 1 的地址（固定的「水龙头」，便于演示花费）。"""
    return p2pkh_script(PrivateKey(1).public_key().hash160())


@lru_cache(maxsize=None)
def create_genesis_block(params: ChainParams = DEFAULT_PARAMS,
                         script_pubkey: bytes | None = None,
                         timestamp: int = GENESIS_TIMESTAMP) -> Block:
    """构造并挖出创世块。

    创世块的 PoW 是真挖出来的（而不是硬编码一个 nonce），所以它和普通块遵守
    完全相同的规则；``lru_cache`` 保证同一套参数只会挖一次。
    """
    script = script_pubkey or _genesis_script_pubkey()
    coinbase = coinbase_transaction(0, params.initial_subsidy, script, _GENESIS_EXTRA_NONCE)
    header = BlockHeader(
        version=1,
        prev_block=b"\x00" * 32,
        merkle_root=merkle_root([coinbase.txid()]),
        timestamp=timestamp,
        bits=params.pow_limit_bits,
        nonce=0,
    )
    return mine(Block(header, [coinbase]))


def unique_extra_nonce(prev_hash: bytes, timestamp: int, txids: list[bytes]) -> bytes:
    """为 coinbase 生成区块唯一的标记。

    没有它，同一高度、同一收款地址的两个竞争区块会产生**完全相同**的 coinbase
    交易，从而共享同一个 txid——交易索引会被覆盖，``confirmations`` 会给出错误
    答案，UTXO 的键也会在两条分支间撞车。真实矿工靠 extranonce 解决，这里用
    「父块哈希 + 时间戳 + 交易集合」的哈希派生，既唯一又可复现。
    """
    seed = hash256(prev_hash + timestamp.to_bytes(4, "little") + b"".join(txids))
    return b"nimbus/" + seed[:10]


# --------------------------------------------------------------------------- #
# 链
# --------------------------------------------------------------------------- #


class Chain:
    """一条链：主链、侧链索引、UTXO 集、undo 记录、交易索引。"""

    def __init__(self, params: ChainParams | None = None, genesis: Block | None = None) -> None:
        self.params = params or DEFAULT_PARAMS
        self.genesis = genesis or create_genesis_block(self.params)
        if not self.genesis.has_valid_pow():
            raise InvalidBlock("genesis block does not satisfy proof of work")

        genesis_hash = self.genesis.block_hash()
        self._index: dict[bytes, Block] = {genesis_hash: self.genesis}
        self._height: dict[bytes, int] = {genesis_hash: 0}
        self._work: dict[bytes, int] = {genesis_hash: block_work(self.genesis.header.bits)}
        self._main_hashes: list[bytes] = [genesis_hash]
        self._undo: dict[bytes, BlockUndo] = {}
        self._tx_index: dict[bytes, tuple[bytes, int, int]] = {}

        self.utxo: dict[tuple[bytes, int], UTXO] = {}
        undo = self._apply_block(self.genesis, 0, self.utxo, validate=True)
        self._undo[genesis_hash] = undo
        self._tx_index[self.genesis.transactions[0].txid()] = (genesis_hash, 0, 0)
        self.reorg_count = 0

    # -- 基本视图 --------------------------------------------------------- #

    @property
    def tip_hash(self) -> bytes:
        return self._main_hashes[-1]

    @property
    def tip(self) -> Block:
        return self._index[self.tip_hash]

    @property
    def height(self) -> int:
        return len(self._main_hashes) - 1

    @property
    def total_work(self) -> int:
        return self._work[self.tip_hash]

    @property
    def genesis_hash(self) -> bytes:
        return self._main_hashes[0]

    def known(self, block_hash: bytes) -> bool:
        return block_hash in self._index

    def get_block(self, block_hash: bytes) -> Block | None:
        return self._index.get(block_hash)

    def height_of(self, block_hash: bytes) -> int | None:
        return self._height.get(block_hash)

    def work_of(self, block_hash: bytes) -> int | None:
        return self._work.get(block_hash)

    def is_on_main_chain(self, block_hash: bytes) -> bool:
        return block_hash in set(self._main_hashes)

    def main_blocks(self) -> list[Block]:
        return [self._index[block_hash] for block_hash in self._main_hashes]

    def block_at_height(self, height: int) -> Block | None:
        if 0 <= height < len(self._main_hashes):
            return self._index[self._main_hashes[height]]
        return None

    # -- 交易查询 --------------------------------------------------------- #

    def get_transaction(self, txid: bytes) -> Transaction | None:
        entry = self._tx_index.get(txid)
        if entry is None:
            return None
        block_hash, _, index = entry
        return self._index[block_hash].transactions[index]

    def transaction_location(self, txid: bytes) -> tuple[bytes, int, int] | None:
        return self._tx_index.get(txid)

    def confirmations(self, txid: bytes) -> int:
        entry = self._tx_index.get(txid)
        if entry is None:
            return 0
        return self.height - entry[1] + 1

    def find_transactions_by_op_return(self, payload: bytes) -> list[Transaction]:
        """按 ``OP_RETURN`` 载荷找交易（存证应用用它把哈希映射回交易）。"""
        found = []
        for block in self.main_blocks():
            for tx in block.transactions:
                if payload in tx.data_carrier_outputs():
                    found.append(tx)
        return found

    # -- UTXO 视图 -------------------------------------------------------- #

    def utxos_for_script(self, script_pubkey: bytes) -> list[tuple[tuple[bytes, int], UTXO]]:
        return [(key, entry) for key, entry in self.utxo.items()
                if entry.tx_out.script_pubkey == script_pubkey]

    def balance(self, script_pubkey: bytes) -> int:
        return sum(entry.value for _, entry in self.utxos_for_script(script_pubkey))

    def spendable_utxos(self, script_pubkey: bytes, at_height: int | None = None) -> list[tuple[tuple[bytes, int], UTXO]]:
        """可花费的 UTXO（默认按当前链尖高度过滤 coinbase 成熟度）。"""
        height = self.height if at_height is None else at_height
        return [
            (key, entry) for key, entry in self.utxos_for_script(script_pubkey)
            if not entry.is_coinbase or height - entry.height >= self.params.coinbase_maturity
        ]

    def replay_utxo_set(self, tip_hash: bytes | None = None) -> dict[tuple[bytes, int], UTXO]:
        """从创世块全量重放，独立算出一份 UTXO 集（用于与增量集对照）。"""
        target = tip_hash or self.tip_hash
        view: dict[tuple[bytes, int], UTXO] = {}
        for height, block in enumerate(self._ancestors(target)):
            self._apply_block(block, height, view, validate=False)
        return view

    def _ancestors(self, tip_hash: bytes) -> list[Block]:
        hashes = []
        cursor = tip_hash
        while True:
            hashes.append(cursor)
            if cursor == self.genesis_hash:
                break
            cursor = self._index[cursor].header.prev_block
        hashes.reverse()
        return [self._index[block_hash] for block_hash in hashes]

    # -- 难度与时间 ------------------------------------------------------- #

    def median_time_past(self, block_hash: bytes) -> int:
        """过去 11 个块时间戳的中位数（Bitcoin 的 MTP 规则）。"""
        times: list[int] = []
        cursor = block_hash
        while len(times) < 11:
            block = self._index.get(cursor)
            if block is None:
                break
            times.append(block.header.timestamp)
            if cursor == self.genesis_hash:
                break
            cursor = block.header.prev_block
        times.sort()
        return times[len(times) // 2]

    def expected_bits(self, prev_hash: bytes, prev_height: int) -> int:
        """第 ``prev_height + 1`` 个块应当使用的 ``bits``。

        只在 ``height % retarget_interval == 0`` 时重定目标；其余高度沿用父块的
        bits。重定目标用「窗口内首尾时间戳之差」对比期望时长，并做 4 倍钳制，
        最后不超过 ``pow_limit_bits``。
        """
        prev_bits = self._index[prev_hash].header.bits
        interval = self.params.retarget_interval
        height = prev_height + 1
        if interval <= 0 or height % interval != 0:
            return prev_bits

        last = self._index[prev_hash]
        first = last
        for _ in range(interval - 1):
            parent = self._index.get(first.header.prev_block)
            if parent is None:
                return prev_bits
            first = parent

        actual_timespan = last.header.timestamp - first.header.timestamp
        return compute_retarget_bits(
            prev_bits,
            actual_timespan,
            interval=interval,
            target_block_time=self.params.target_block_time,
            max_adjustment_factor=self.params.max_adjustment_factor,
            pow_limit_bits=self.params.pow_limit_bits,
        )

    def subsidy(self, height: int) -> int:
        return block_subsidy(height, self.params.halving_interval, self.params.initial_subsidy)

    def next_block_bits(self) -> int:
        return self.expected_bits(self.tip_hash, self.height)

    # -- 出块 ------------------------------------------------------------- #

    def assemble_block(self, prev_hash: bytes, timestamp: int, transactions: list[Transaction],
                       script_pubkey: bytes, *, coinbase_value: int | None = None,
                       bits: int | None = None, extra_nonce: bytes | None = None) -> Block:
        """在**指定父块**上组装区块：算手续费、填 coinbase、算 Merkle 根。

        只组装、不校验、不挖矿——调用方可以传 ``coinbase_value`` / ``bits`` 故意
        造出不合法的区块来测试校验流水线，也可以直接给 ``add_block``。
        """
        prev = self._index.get(prev_hash)
        if prev is None:
            raise InvalidBlock(f"unknown parent for block assembly: {prev_hash[::-1].hex()}")
        height = self._height[prev_hash] + 1

        if coinbase_value is None:
            view = self.utxo if prev_hash == self.tip_hash else self.replay_utxo_set(prev_hash)
            fees = 0
            for tx in transactions:
                total_in = 0
                for tx_in in tx.inputs:
                    entry = view.get(tx_in.outpoint())
                    if entry is None:
                        raise InvalidBlock("candidate transaction references an unknown utxo")
                    total_in += entry.value
                if total_in < tx.total_out():
                    raise InvalidBlock("candidate transaction spends more than its inputs")
                fees += total_in - tx.total_out()
            coinbase_value = self.subsidy(height) + fees

        if extra_nonce is None:
            extra_nonce = unique_extra_nonce(prev_hash, timestamp, [tx.txid() for tx in transactions])
        coinbase = coinbase_transaction(height, coinbase_value, script_pubkey, extra_nonce)
        body = [coinbase, *transactions]
        header = BlockHeader(
            version=1,
            prev_block=prev_hash,
            merkle_root=merkle_root([tx.txid() for tx in body]),
            timestamp=timestamp,
            bits=self.expected_bits(prev_hash, height - 1) if bits is None else bits,
        )
        return Block(header, body)

    def build_candidate(self, transactions: list[Transaction], script_pubkey: bytes,
                        timestamp: int | None = None, extra_nonce: bytes | None = None) -> Block:
        """在当前链尖上组装一个待挖的区块。

        ``timestamp`` 默认取「父块时间戳 + 期望出块间隔」，从而在演示环境里保持
        难度稳定；真实矿工应当用墙上时钟。
        """
        if timestamp is None:
            timestamp = self.tip.header.timestamp + self.params.target_block_time
        return self.assemble_block(self.tip_hash, timestamp, transactions, script_pubkey,
                                   extra_nonce=extra_nonce)

    def build_and_mine(self, transactions: list[Transaction], script_pubkey: bytes,
                       timestamp: int | None = None, extra_nonce: bytes | None = None) -> Block:
        return mine(self.build_candidate(transactions, script_pubkey, timestamp, extra_nonce))

    # -- 校验流水线 ------------------------------------------------------- #

    def _validate_header(self, block: Block, prev: Block, height: int) -> None:
        prev_hash = prev.block_hash()
        if block.header.prev_block != prev_hash:
            raise InvalidBlock("prev_block does not match the parent")
        if not block.transactions:
            raise InvalidBlock("block has no transactions")
        if block.size() > MAX_BLOCK_SIZE:
            raise InvalidBlock("block exceeds maximum size")
        if not block.has_valid_pow():
            raise InvalidBlock("proof of work is not satisfied")
        if block.header.bits != self.expected_bits(prev_hash, height - 1):
            raise InvalidBlock("difficulty bits do not match the consensus rule")
        if block.header.timestamp <= self.median_time_past(prev_hash):
            raise InvalidBlock("timestamp is not greater than median time past")
        if not block.merkle_root_matches():
            raise InvalidBlock("merkle root does not match the transactions")

        txids = [tx.txid() for tx in block.transactions]
        if len(set(txids)) != len(txids):
            raise InvalidBlock("block contains duplicate transactions")
        if not block.transactions[0].is_coinbase():
            raise InvalidBlock("first transaction must be a coinbase")
        for tx in block.transactions[1:]:
            if tx.is_coinbase():
                raise InvalidBlock("block contains more than one coinbase transaction")

    def _apply_block(self, block: Block, height: int, view: dict[tuple[bytes, int], UTXO],
                     *, validate: bool) -> BlockUndo:
        """把区块对 UTXO 集的影响施加到 ``view`` 上，并返回 undo 记录。

        ``validate=True`` 时同时做签名验证、coinbase 成熟度与不超发检查。
        """
        params = self.params
        undo = BlockUndo()
        fees = 0

        for tx in block.transactions[1:]:
            if validate:
                tx.validate_structure()
            total_in = 0
            spent_in_this_tx: list[tuple[bytes, int]] = []
            for input_index, tx_in in enumerate(tx.inputs):
                key = tx_in.outpoint()
                if key in spent_in_this_tx:
                    raise InvalidBlock(f"transaction {tx.txid_hex()} spends the same outpoint twice")
                entry = view.get(key)
                if entry is None:
                    raise InvalidBlock(
                        f"input references a missing or already-spent utxo "
                        f"{key[0][::-1].hex()}:{key[1]} (tx {tx.txid_hex()})")
                if entry.is_coinbase and height - entry.height < params.coinbase_maturity:
                    raise InvalidBlock(
                        f"immature coinbase spend: {key[0][::-1].hex()}:{key[1]} created at "
                        f"{entry.height}, spent at {height}, maturity {params.coinbase_maturity}")
                if validate and not verify_input(tx_in.script_sig, entry.tx_out.script_pubkey,
                                                checker_for(tx, input_index)):
                    raise InvalidBlock(f"script verification failed for {tx.txid_hex()}")
                total_in += entry.value
                spent_in_this_tx.append(key)
                undo.spent.append((key, entry))
                del view[key]

            if total_in < tx.total_out():
                raise InvalidBlock(f"transaction {tx.txid_hex()} spends more than its inputs")
            fees += total_in - tx.total_out()

            txid = tx.txid()
            for index, tx_out in enumerate(tx.outputs):
                if tx_out.is_spendable():
                    key = (txid, index)
                    view[key] = UTXO(tx_out, height, False)
                    undo.created.append(key)

        coinbase = block.transactions[0]
        if validate:
            coinbase.validate_structure()
            allowed = self.subsidy(height) + fees
            if coinbase.total_out() > allowed:
                raise InvalidBlock(
                    f"coinbase pays {coinbase.total_out()} sat but only {allowed} are allowed")

        coinbase_txid = coinbase.txid()
        for index, tx_out in enumerate(coinbase.outputs):
            if tx_out.is_spendable():
                key = (coinbase_txid, index)
                view[key] = UTXO(tx_out, height, True)
                undo.created.append(key)
        return undo

    # -- 连接 / 断开 / 重组 ----------------------------------------------- #

    def _connect(self, block_hash: bytes) -> None:
        block = self._index[block_hash]
        height = self._height[block_hash]
        view = dict(self.utxo)
        undo = self._apply_block(block, height, view, validate=False)
        self.utxo = view
        self._undo[block_hash] = undo
        for index, tx in enumerate(block.transactions):
            self._tx_index[tx.txid()] = (block_hash, height, index)
        self._main_hashes.append(block_hash)

    def _disconnect(self, block_hash: bytes) -> None:
        block = self._index[block_hash]
        undo = self._undo.pop(block_hash)
        for key, entry in undo.spent:
            self.utxo[key] = entry          # 先还原被花掉的
        for key in undo.created:
            self.utxo.pop(key, None)        # 再删掉新建的
        for tx in block.transactions:
            self._tx_index.pop(tx.txid(), None)
        self._main_hashes.pop()

    def _reorganize(self, new_tip_hash: bytes) -> AddBlockResult:
        """切换到累计工作量更大的分支，并返还被挤出主链的交易。"""
        to_disconnect: list[bytes] = []
        new_branch: list[bytes] = []
        old_cursor = self.tip_hash
        new_cursor = new_tip_hash

        while self._height[old_cursor] > self._height[new_cursor]:
            to_disconnect.append(old_cursor)
            old_cursor = self._index[old_cursor].header.prev_block
        while self._height[new_cursor] > self._height[old_cursor]:
            new_branch.append(new_cursor)
            new_cursor = self._index[new_cursor].header.prev_block
        while old_cursor != new_cursor:
            to_disconnect.append(old_cursor)
            old_cursor = self._index[old_cursor].header.prev_block
            new_branch.append(new_cursor)
            new_cursor = self._index[new_cursor].header.prev_block

        reaccepted: list[Transaction] = []
        for block_hash in to_disconnect:
            for tx in self._index[block_hash].transactions[1:]:
                reaccepted.append(tx)
            self._disconnect(block_hash)

        connected: list[bytes] = []
        for block_hash in reversed(new_branch):
            self._connect(block_hash)
            connected.append(block_hash)

        if to_disconnect:
            self.reorg_count += 1

        return AddBlockResult(
            status="reorg" if to_disconnect else "connected",
            block_hash=new_tip_hash,
            height=self._height[new_tip_hash],
            connected=connected,
            disconnected=to_disconnect,
            reaccepted=reaccepted,
            branch_work=self._work[new_tip_hash],
        )

    # -- 对外入口 --------------------------------------------------------- #

    def add_block(self, block: Block) -> AddBlockResult:
        """把一个区块交给链处理：校验 → 存索引 → 视工作量决定是否重组。

        抛出 :class:`InvalidBlock` 表示这个块被拒绝；返回 ``side_chain`` 表示它
        合法但暂时不是主链（已保存，等待后续块堆出更高工作量）。
        """
        block_hash = block.block_hash()
        if block_hash in self._index:
            return AddBlockResult("duplicate", block_hash, self._height[block_hash])

        prev_hash = block.header.prev_block
        prev = self._index.get(prev_hash)
        if prev is None:
            raise InvalidBlock(f"orphan block: unknown parent {prev_hash[::-1].hex()}")
        prev_height = self._height[prev_hash]
        height = prev_height + 1

        self._validate_header(block, prev, height)

        # 链尖扩展走增量 UTXO；分叉块必须先重放父分支，才能拿到「父块当时」的账本
        if prev_hash == self.tip_hash:
            view = dict(self.utxo)
        else:
            view = self.replay_utxo_set(prev_hash)
        self._apply_block(block, height, view, validate=True)

        self._index[block_hash] = block
        self._height[block_hash] = height
        self._work[block_hash] = self._work[prev_hash] + block_work(block.header.bits)

        if self._work[block_hash] > self._work[self.tip_hash]:
            return self._reorganize(block_hash)
        return AddBlockResult("side_chain", block_hash, height,
                              branch_work=self._work[block_hash])

    # -- 持久化 ----------------------------------------------------------- #

    def to_dict(self) -> dict:
        return {
            "format": "nimbus-chain/1",
            "params": asdict(self.params),
            "genesis": self.genesis.to_hex(),
            "blocks": [block.to_hex() for block in self.main_blocks()[1:]],
        }

    def save(self, path: str | Path) -> None:
        """把主链序列化成 JSON 文本（教学项目选可读格式而不是二进制）。"""
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Chain":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        params = ChainParams(**payload["params"])
        chain = cls(params=params, genesis=Block.from_hex(payload["genesis"]))
        for hexed in payload["blocks"]:
            chain.add_block(Block.from_hex(hexed))
        return chain

    # -- 展示 ------------------------------------------------------------- #

    def stats(self) -> dict:
        return {
            "height": self.height,
            "tip": self.tip.block_hash_hex(),
            "total_work": self.total_work,
            "utxo_count": len(self.utxo),
            "known_blocks": len(self._index),
            "reorgs": self.reorg_count,
            "next_bits": f"0x{self.next_block_bits():08x}",
        }

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return (f"Chain(height={self.height}, utxos={len(self.utxo)}, "
                f"tip={self.tip.block_hash_hex()[:16]}…)")

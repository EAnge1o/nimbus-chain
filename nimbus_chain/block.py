"""区块、区块头、PoW 与 compact bits 难度编码。

区块头只有 80 字节，却承载了整条链的安全性：

    version(4) | prev_block(32) | merkle_root(32) | timestamp(4) | bits(4) | nonce(4)

* ``hash = SHA256d(header)``，要 ``<= target`` 才算满足 PoW。
* ``bits`` 是 Bitcoin 的 compact 编码（1 字节指数 + 3 字节尾数），本模块实现
  ``bits_to_target`` / ``target_to_bits`` 双向转换，并拒绝负数尾数与溢出。
* ``merkle_root`` 必须是区块内全部交易哈希的 Merkle 根——只要有一笔交易被改，
  根就变，PoW 随之失效。

``block_work`` 返回的是**工作量**（``2^256 / (target + 1)``）而不是难度倍数：
分叉选择比的不是链有多长，而是累计工作量有多大，这一点在 chain.py 里很关键。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import hash256
from .merkle import MerkleProofError, merkle_root, merkle_proof
from .tx import Transaction, read_varint, write_varint

__all__ = [
    "HEADER_SIZE",
    "MAX_BLOCK_SIZE",
    "POW_LIMIT_BITS",
    "BlockError",
    "BlockHeader",
    "Block",
    "bits_to_target",
    "target_to_bits",
    "block_work",
    "compute_retarget_bits",
    "mine",
]

HEADER_SIZE = 80
MAX_BLOCK_SIZE = 1_000_000
_UINT32_MAX = 0xFFFFFFFF

# 「最松」的目标（最大 target）。期望尝试次数 ≈ 2^32 / 0x0fffff ≈ 4096 次，
# 也就是单核 Python 挖一个块约 0.15 秒——这是演示用参数，不是主网参数。
POW_LIMIT_BITS = 0x1F0FFFFF


class BlockError(ValueError):
    """区块结构、PoW 或难度编码非法。"""


# --------------------------------------------------------------------------- #
# compact bits <-> target
# --------------------------------------------------------------------------- #


def bits_to_target(bits: int) -> int:
    """把 compact ``bits`` 展开成 256 位目标值。"""
    if not 0 <= bits <= _UINT32_MAX:
        raise BlockError(f"bits out of range: {bits}")
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        raise BlockError("negative target (sign bit set in mantissa)")
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target <= 0 or target >= (1 << 256):
        raise BlockError(f"target out of range for bits 0x{bits:08x}")
    return target


def target_to_bits(target: int) -> int:
    """把目标值压回 compact ``bits``（Bitcoin ``SetCompact`` 的逆运算）。"""
    if target <= 0:
        raise BlockError("target must be positive")
    size = (target.bit_length() + 7) // 8
    compact = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if compact & 0x00800000:
        # 尾数最高位会被读成负号，整体右移一字节
        compact >>= 8
        size += 1
    if size > 34:
        raise BlockError("target too large to encode")
    return (size << 24) | (compact & 0x007FFFFF)


def block_work(bits: int) -> int:
    """该难度下的期望哈希次数（累计工作量用得到）。"""
    target = bits_to_target(bits)
    return (1 << 256) // (target + 1)


def compute_retarget_bits(prev_bits: int, actual_timespan: int, *, interval: int,
                          target_block_time: int, max_adjustment_factor: int = 4,
                          pow_limit_bits: int = POW_LIMIT_BITS) -> int:
    """按「窗口首尾时间戳之差」重算难度。

    这是**全节点与轻客户端共用的唯一实现**——如果两边各写一份，某天其中一份改
    了钳制顺序，链就会静默分叉。规则：

    1. 实测跨度钳制在 ``[timespan/4, timespan*4]``（``max_adjustment_factor``）；
    2. 新目标 = 旧目标 × 实测 / 期望；
    3. 不得松于 ``pow_limit_bits``（难度下限）。

    参数刻意用标量而非配置对象，这样 ``block`` 层不必知道链参数长什么样。
    """
    timespan = interval * target_block_time
    if timespan <= 0:
        raise BlockError("target timespan must be positive")
    factor = max(1, max_adjustment_factor)
    actual = max(timespan // factor, min(actual_timespan, timespan * factor))
    target = bits_to_target(prev_bits) * actual // timespan
    limit = bits_to_target(pow_limit_bits)
    target = min(target, limit)
    if target <= 0:
        target = limit
    return target_to_bits(target)


# --------------------------------------------------------------------------- #
# 区块头 / 区块
# --------------------------------------------------------------------------- #


@dataclass
class BlockHeader:
    version: int
    prev_block: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int = 0

    def __post_init__(self) -> None:
        if len(self.prev_block) != 32:
            raise BlockError("prev_block must be 32 bytes")
        if len(self.merkle_root) != 32:
            raise BlockError("merkle_root must be 32 bytes")
        if not 0 <= self.timestamp <= _UINT32_MAX:
            raise BlockError("timestamp out of range")
        if not 0 <= self.nonce <= _UINT32_MAX:
            raise BlockError("nonce out of range")

    def serialize(self) -> bytes:
        return (self.version.to_bytes(4, "little") + self.prev_block + self.merkle_root
                + self.timestamp.to_bytes(4, "little") + self.bits.to_bytes(4, "little")
                + self.nonce.to_bytes(4, "little"))

    @classmethod
    def deserialize(cls, data: bytes) -> "BlockHeader":
        if len(data) != HEADER_SIZE:
            raise BlockError(f"header must be {HEADER_SIZE} bytes, got {len(data)}")
        return cls(
            int.from_bytes(data[0:4], "little"),
            data[4:36],
            data[36:68],
            int.from_bytes(data[68:72], "little"),
            int.from_bytes(data[72:76], "little"),
            int.from_bytes(data[76:80], "little"),
        )

    def hash(self) -> bytes:
        """区块哈希（``SHA256d(header)``），内部大端字节序。"""
        return hash256(self.serialize())

    def hash_hex(self) -> str:
        return self.hash()[::-1].hex()

    def target(self) -> int:
        return bits_to_target(self.bits)

    def has_valid_pow(self) -> bool:
        return int.from_bytes(self.hash(), "big") <= self.target()

    def work(self) -> int:
        return block_work(self.bits)

    def to_dict(self) -> dict:
        return {
            "hash": self.hash_hex(),
            "version": self.version,
            "prev_block": self.prev_block[::-1].hex(),
            "merkle_root": self.merkle_root[::-1].hex(),
            "timestamp": self.timestamp,
            "bits": f"0x{self.bits:08x}",
            "nonce": self.nonce,
            "difficulty": 2 ** 256 / (self.target() + 1),
        }


@dataclass
class Block:
    header: BlockHeader
    transactions: list[Transaction] = field(default_factory=list)

    # -- 标识 ------------------------------------------------------------- #

    def block_hash(self) -> bytes:
        return self.header.hash()

    def block_hash_hex(self) -> str:
        return self.header.hash_hex()

    # -- Merkle ----------------------------------------------------------- #

    def compute_merkle_root(self) -> bytes:
        return merkle_root([tx.txid() for tx in self.transactions])

    def merkle_root_matches(self) -> bool:
        if not self.transactions:
            return False
        try:
            return self.compute_merkle_root() == self.header.merkle_root
        except MerkleProofError:
            return False

    def merkle_proof_for(self, index: int) -> list[tuple[bytes, str]]:
        return merkle_proof([tx.txid() for tx in self.transactions], index)

    def transaction_index(self, txid: bytes) -> int | None:
        for index, tx in enumerate(self.transactions):
            if tx.txid() == txid:
                return index
        return None

    # -- 序列化 ----------------------------------------------------------- #

    def serialize(self) -> bytes:
        out = bytearray(self.header.serialize())
        out.extend(write_varint(len(self.transactions)))
        for tx in self.transactions:
            out.extend(tx.serialize())
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "Block":
        if len(data) < HEADER_SIZE:
            raise BlockError("truncated block header")
        header = BlockHeader.deserialize(data[:HEADER_SIZE])
        offset = HEADER_SIZE
        count, offset = read_varint(data, offset)
        transactions = []
        for _ in range(count):
            tx_start = offset
            tx = Transaction.deserialize(_take_transaction(data, tx_start))
            offset = _transaction_end(data, tx_start)
            transactions.append(tx)
        if offset != len(data):
            raise BlockError("trailing bytes after block")
        return cls(header, transactions)

    @classmethod
    def from_hex(cls, text: str) -> "Block":
        return cls.deserialize(bytes.fromhex(text))

    def to_hex(self) -> str:
        return self.serialize().hex()

    def size(self) -> int:
        return len(self.serialize())

    # -- PoW -------------------------------------------------------------- #

    def has_valid_pow(self) -> bool:
        return self.header.has_valid_pow()

    def is_coinbase_block(self) -> bool:
        return bool(self.transactions) and self.transactions[0].is_coinbase()

    # -- 展示 ------------------------------------------------------------- #

    def to_dict(self) -> dict:
        data = self.header.to_dict()
        data.update({
            "height_note": "height is assigned by the chain, not the header",
            "size": self.size(),
            "transactions": [tx.txid_hex() for tx in self.transactions],
            "coinbase": self.transactions[0].txid_hex() if self.transactions else None,
        })
        return data

    def describe(self) -> str:
        return (f"#{self.block_hash_hex()[:16]}… {len(self.transactions)} tx  "
                f"nonce={self.header.nonce}  bits=0x{self.header.bits:08x}")


def _take_transaction(data: bytes, offset: int) -> bytes:
    """从头开始截出「这一笔交易」的字节（先算长度再交给 Transaction.deserialize）。"""
    return _slice_transaction(data, offset)[0]


def _transaction_end(data: bytes, offset: int) -> int:
    return _slice_transaction(data, offset)[1]


def _slice_transaction(data: bytes, offset: int) -> tuple[bytes, int]:
    start = offset
    if offset + 4 > len(data):
        raise BlockError("truncated transaction version")
    offset += 4
    input_count, offset = read_varint(data, offset)
    for _ in range(input_count):
        if offset + 36 > len(data):
            raise BlockError("truncated transaction input")
        offset += 36
        size, offset = read_varint(data, offset)
        offset += size + 4
    output_count, offset = read_varint(data, offset)
    for _ in range(output_count):
        offset += 8
        size, offset = read_varint(data, offset)
        offset += size
    offset += 4
    if offset > len(data):
        raise BlockError("truncated transaction")
    return data[start:offset], offset


def mine(block: Block, max_tries: int | None = None) -> Block:
    """就地挖矿：递增 nonce 直到 ``SHA256d(header) <= target``。

    返回同一个 ``Block`` 对象（方便链式调用）。找不到解时抛 :class:`BlockError`。
    """
    target = block.header.target()
    nonce = block.header.nonce
    limit = _UINT32_MAX if max_tries is None else min(_UINT32_MAX, nonce + max_tries)
    while nonce <= limit:
        block.header.nonce = nonce
        if int.from_bytes(block.header.hash(), "big") <= target:
            return block
        nonce += 1
    raise BlockError("no valid nonce found within the search space")

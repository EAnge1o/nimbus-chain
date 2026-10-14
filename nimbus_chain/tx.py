"""交易（UTXO 模型）、序列化、sighash、coinbase 与减半。

Bitcoin 的账本不是"账户余额表"，而是一堆**未花费交易输出**（UTXO）：每笔交易
声明它花掉哪些旧输出（inputs），并创造哪些新输出（outputs）。这个模块实现：

* 字节级序列化 / 反序列化（varint、小端整数、长度前缀脚本）
* 交易哈希（``txid``）—— 对整笔交易的字节做双 SHA-256
* **legacy sighash**：签名时把全部输入的 scriptSig 清空、把当前输入的 scriptCode
  填回去，再拼上 4 字节 ``hash_type`` 做哈希。这是 P2PKH 签名能被验证的前提，
  也是最常被写错的地方。
* coinbase 交易构造（含 BIP34 区块高度）与减半规则
* 结构性校验：无空输入/输出、无重复花费、金额范围、余额守恒

有意未实现：SegWit 的 BIP143 sighash、``SIGHASH_SINGLE`` / ``SIGHASH_NONE``
（仅支持 ``SIGHASH_ALL``），遇到即抛错而不是悄悄算错。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import hash256
from .script import Checker, encode_num, is_provably_unspendable, serialize_script

__all__ = [
    "COIN",
    "MAX_MONEY",
    "COINBASE_PREV_TXID",
    "COINBASE_INDEX",
    "COINBASE_MATURITY",
    "HALVING_INTERVAL",
    "INITIAL_SUBSIDY",
    "SIGHASH_ALL",
    "TxValidationError",
    "TxIn",
    "TxOut",
    "Transaction",
    "block_subsidy",
    "coinbase_transaction",
    "checker_for",
]

COIN = 100_000_000
MAX_MONEY = 21_000_000 * COIN
COINBASE_PREV_TXID = b"\x00" * 32
COINBASE_INDEX = 0xFFFFFFFF
COINBASE_MATURITY = 100
HALVING_INTERVAL = 210_000
INITIAL_SUBSIDY = 50 * COIN
SIGHASH_ALL = 1

_HEX_PREV = b"\x00" * 32


class TxValidationError(ValueError):
    """交易结构或语义非法。"""


# --------------------------------------------------------------------------- #
# 序列化原语
# --------------------------------------------------------------------------- #


def write_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot be negative")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xFD" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xFE" + value.to_bytes(4, "little")
    return b"\xFF" + value.to_bytes(8, "little")


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise TxValidationError("truncated varint")
    prefix = data[offset]
    offset += 1
    if prefix < 0xFD:
        return prefix, offset
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[prefix]
    if offset + size > len(data):
        raise TxValidationError("truncated varint payload")
    return int.from_bytes(data[offset:offset + size], "little"), offset + size


def _write_script(script: bytes) -> bytes:
    return write_varint(len(script)) + script


def _read_script(data: bytes, offset: int) -> tuple[bytes, int]:
    size, offset = read_varint(data, offset)
    if offset + size > len(data):
        raise TxValidationError("truncated script")
    return data[offset:offset + size], offset + size


# --------------------------------------------------------------------------- #
# 输入 / 输出
# --------------------------------------------------------------------------- #


@dataclass
class TxIn:
    """交易输入：指向某个旧输出的 ``(txid, index)``，附带解锁脚本与 sequence。"""

    prev_txid: bytes
    prev_index: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF

    def __post_init__(self) -> None:
        if len(self.prev_txid) != 32:
            raise TxValidationError("prev_txid must be 32 bytes")
        if not 0 <= self.prev_index <= 0xFFFFFFFF:
            raise TxValidationError("prev_index out of range")
        if not 0 <= self.sequence <= 0xFFFFFFFF:
            raise TxValidationError("sequence out of range")

    def serialize(self) -> bytes:
        return (self.prev_txid + self.prev_index.to_bytes(4, "little")
                + _write_script(self.script_sig) + self.sequence.to_bytes(4, "little"))

    @classmethod
    def deserialize(cls, data: bytes, offset: int) -> tuple["TxIn", int]:
        if offset + 36 > len(data):
            raise TxValidationError("truncated transaction input")
        prev_txid = data[offset:offset + 32]
        prev_index = int.from_bytes(data[offset + 32:offset + 36], "little")
        offset += 36
        script_sig, offset = _read_script(data, offset)
        if offset + 4 > len(data):
            raise TxValidationError("truncated sequence")
        sequence = int.from_bytes(data[offset:offset + 4], "little")
        return cls(prev_txid, prev_index, script_sig, sequence), offset + 4

    def outpoint(self) -> tuple[bytes, int]:
        return self.prev_txid, self.prev_index

    def is_coinbase(self) -> bool:
        return self.prev_txid == COINBASE_PREV_TXID and self.prev_index == COINBASE_INDEX


@dataclass
class TxOut:
    """交易输出：金额（聪）+ 锁定脚本。"""

    value: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.value <= MAX_MONEY:
            raise TxValidationError(f"output value out of range: {self.value}")

    def serialize(self) -> bytes:
        return self.value.to_bytes(8, "little") + _write_script(self.script_pubkey)

    @classmethod
    def deserialize(cls, data: bytes, offset: int) -> tuple["TxOut", int]:
        if offset + 8 > len(data):
            raise TxValidationError("truncated transaction output")
        value = int.from_bytes(data[offset:offset + 8], "little")
        offset += 8
        script_pubkey, offset = _read_script(data, offset)
        return cls(value, script_pubkey), offset

    def is_spendable(self) -> bool:
        return not is_provably_unspendable(self.script_pubkey)


# --------------------------------------------------------------------------- #
# 交易
# --------------------------------------------------------------------------- #


@dataclass
class Transaction:
    version: int = 1
    inputs: list[TxIn] = field(default_factory=list)
    outputs: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    # -- 序列化 ----------------------------------------------------------- #

    def serialize(self) -> bytes:
        out = bytearray()
        out.extend(self.version.to_bytes(4, "little"))
        out.extend(write_varint(len(self.inputs)))
        for tx_in in self.inputs:
            out.extend(tx_in.serialize())
        out.extend(write_varint(len(self.outputs)))
        for tx_out in self.outputs:
            out.extend(tx_out.serialize())
        out.extend(self.locktime.to_bytes(4, "little"))
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "Transaction":
        version = int.from_bytes(data[0:4], "little") if len(data) >= 4 else None
        if version is None:
            raise TxValidationError("truncated transaction")
        offset = 4
        input_count, offset = read_varint(data, offset)
        inputs = []
        for _ in range(input_count):
            tx_in, offset = TxIn.deserialize(data, offset)
            inputs.append(tx_in)
        output_count, offset = read_varint(data, offset)
        outputs = []
        for _ in range(output_count):
            tx_out, offset = TxOut.deserialize(data, offset)
            outputs.append(tx_out)
        if offset + 4 > len(data):
            raise TxValidationError("truncated locktime")
        locktime = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        if offset != len(data):
            raise TxValidationError("trailing bytes after transaction")
        return cls(version, inputs, outputs, locktime)

    @classmethod
    def from_hex(cls, text: str) -> "Transaction":
        return cls.deserialize(bytes.fromhex(text))

    def to_hex(self) -> str:
        return self.serialize().hex()

    # -- 标识与统计 ------------------------------------------------------- #

    def txid(self) -> bytes:
        """交易哈希（内部大端字节序）。展示用 :meth:`txid_hex`。"""
        return hash256(self.serialize())

    def txid_hex(self) -> str:
        """人类可读的交易哈希：字节序反转后转十六进制（与区块浏览器一致）。"""
        return self.txid()[::-1].hex()

    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].is_coinbase()

    def total_out(self) -> int:
        return sum(tx_out.value for tx_out in self.outputs)

    def outpoints(self) -> list[tuple[bytes, int]]:
        return [tx_in.outpoint() for tx_in in self.inputs]

    def data_carrier_outputs(self) -> list[bytes]:
        """取出所有 ``OP_RETURN`` 输出携带的数据（存证应用靠它工作）。"""
        payloads = []
        for tx_out in self.outputs:
            if tx_out.script_pubkey[:1] == b"\x6a":
                from .script import extract_op_return
                data = extract_op_return(tx_out.script_pubkey)
                if data is not None:
                    payloads.append(data)
        return payloads

    # -- 签名 ------------------------------------------------------------- #

    def sighash(self, input_index: int, script_code: bytes, hash_type: int = SIGHASH_ALL) -> bytes:
        """计算 legacy sighash（32 字节摘要）。

        做法：复制整笔交易，把**所有**输入的 scriptSig 清空，只把 ``input_index``
        那个输入的 scriptSig 替换为 ``script_code``，然后拼上 4 字节小端
        ``hash_type`` 再做一次双 SHA-256。签名者与验证者必须按同一规则构造，
        否则签名验证必然失败。
        """
        if not 0 <= input_index < len(self.inputs):
            raise TxValidationError(f"input index {input_index} out of range")
        if hash_type != SIGHASH_ALL:
            raise TxValidationError(f"unsupported sighash type: {hash_type}")

        modified_inputs = [
            TxIn(tx_in.prev_txid, tx_in.prev_index,
                 script_code if index == input_index else b"", tx_in.sequence)
            for index, tx_in in enumerate(self.inputs)
        ]
        modified = Transaction(self.version, modified_inputs, list(self.outputs), self.locktime)
        return hash256(modified.serialize() + hash_type.to_bytes(4, "little"))

    # -- 校验 ------------------------------------------------------------- #

    def validate_structure(self) -> None:
        """结构与金额层面的自洽性检查（不涉及 UTXO 与签名）。"""
        if not self.inputs:
            raise TxValidationError("transaction has no inputs")
        if not self.outputs:
            raise TxValidationError("transaction has no outputs")
        if len(self.serialize()) > 1_000_000:
            raise TxValidationError("transaction exceeds maximum size")
        if self.total_out() > MAX_MONEY:
            raise TxValidationError("total output value exceeds MAX_MONEY")

        seen = set()
        for tx_in in self.inputs:
            outpoint = tx_in.outpoint()
            if outpoint in seen:
                raise TxValidationError(f"duplicate input spends {outpoint[0][::-1].hex()}:{outpoint[1]}")
            seen.add(outpoint)

        if self.is_coinbase():
            if not 1 <= len(self.inputs[0].script_sig) <= 100:
                raise TxValidationError("coinbase scriptSig must be 1..100 bytes")
        else:
            for tx_in in self.inputs:
                if tx_in.is_coinbase():
                    raise TxValidationError("extra coinbase input in a non-coinbase transaction")

    def describe(self) -> str:
        kind = "coinbase" if self.is_coinbase() else f"{len(self.inputs)} in / {len(self.outputs)} out"
        return f"{self.txid_hex()[:16]}…  {kind}  {self.total_out() / COIN:.8f} NBC"


# --------------------------------------------------------------------------- #
# 补贴 / coinbase
# --------------------------------------------------------------------------- #


def block_subsidy(height: int, halving_interval: int = HALVING_INTERVAL,
                  initial: int = INITIAL_SUBSIDY) -> int:
    """区块补贴：每 ``halving_interval`` 个区块减半，减到 0 为止。"""
    if height < 0:
        raise ValueError("height cannot be negative")
    halvings = height // halving_interval
    if halvings >= 64:
        return 0
    return initial >> halvings


def coinbase_transaction(height: int, value: int, script_pubkey: bytes,
                         extra_nonce: bytes = b"") -> Transaction:
    """构造 coinbase 交易：scriptSig = ``<height> <extra_nonce>``（BIP34）。"""
    script_sig = serialize_script([encode_num(height)]) + extra_nonce
    tx_in = TxIn(COINBASE_PREV_TXID, COINBASE_INDEX, script_sig, 0xFFFFFFFF)
    return Transaction(1, [tx_in], [TxOut(value, script_pubkey)], 0)


def checker_for(tx: Transaction, input_index: int) -> Checker:
    """为 ``tx`` 的第 ``input_index`` 个输入构造脚本执行上下文。"""
    tx_in = tx.inputs[input_index]
    return Checker(
        lambda script_code, hash_type: tx.sighash(input_index, script_code, hash_type),
        locktime=tx.locktime,
        sequence=tx_in.sequence,
    )

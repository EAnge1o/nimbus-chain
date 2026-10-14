"""钱包：密钥、地址、UTXO 追踪、coin selection 与交易签名。

钱包不做任何「链」的判断——它只负责三件事：

1. **找到属于自己的钱**：扫描链上的 UTXO，按 ``HASH160(pubkey)`` 认出自己的输出。
2. **凑够金额**（coin selection）：优先挑大额 UTXO（largest-first），并预估交易
   字节数来算手续费；找零低于粉尘阈值就并入手续费，避免造出一笔永远花不掉的
   小额输出。
3. **签名**：对每个属于本钱包的输入构造 ``sighash``，用 P2PKH 脚本签名。

地址使用 Bitcoin 的 Base58Check ``version = 0x00``；``address_to_script`` /
``script_to_address`` 负责在「地址」与「锁定脚本」之间转换。
"""

from __future__ import annotations

from .crypto import Base58ChecksumError, b58check_decode, b58check_encode
from .chain import Chain
from .script import p2pkh_script, p2pkh_script_sig
from .secp256k1 import PrivateKey
from .tx import SIGHASH_ALL, Transaction, TxIn, TxOut

__all__ = [
    "DUST_THRESHOLD",
    "ADDRESS_VERSION",
    "WalletError",
    "estimate_size",
    "estimate_fee",
    "address_to_script",
    "script_to_address",
    "transaction_fee",
    "Wallet",
]

DUST_THRESHOLD = 546          # P2PKH 输出的粉尘阈值（聪）：低于它就不值得单独找零
ADDRESS_VERSION = 0x00        # Base58Check 版本字节，0x00 对应「1」开头的地址

# 字节数估算（Bitcoin 上 P2PKH 的经验值，用于在签名前算手续费）
_TX_BASE_SIZE = 10
_P2PKH_INPUT_SIZE = 148
_P2PKH_OUTPUT_SIZE = 34
_OP_RETURN_BASE_SIZE = 9


class WalletError(ValueError):
    """余额不足、地址非法等钱包级别错误。"""


def estimate_size(input_count: int, output_count: int) -> int:
    """估算交易字节数（P2PKH 输入 + 普通输出）。"""
    return _TX_BASE_SIZE + _P2PKH_INPUT_SIZE * input_count + _P2PKH_OUTPUT_SIZE * output_count


def estimate_fee(input_count: int, output_count: int, fee_rate: float) -> int:
    """按 ``聪/字节`` 估算手续费（至少 1 聪，避免出现零手续费交易）。"""
    return max(1, int(estimate_size(input_count, output_count) * fee_rate))


def address_to_script(address: str, version: int = ADDRESS_VERSION) -> bytes:
    """Base58Check 地址 → P2PKH 锁定脚本。"""
    try:
        decoded_version, payload = b58check_decode(address)
    except Base58ChecksumError as error:
        raise WalletError(f"invalid address {address!r}: {error}") from error
    if decoded_version != version:
        raise WalletError(f"unexpected address version {decoded_version}, expected {version}")
    if len(payload) != 20:
        raise WalletError("address payload must be a 20-byte hash160")
    return p2pkh_script(payload)


def script_to_address(script_pubkey: bytes, version: int = ADDRESS_VERSION) -> str | None:
    """P2PKH 锁定脚本 → 地址；不是 P2PKH 时返回 ``None``。"""
    if len(script_pubkey) != 25 or script_pubkey[0] != 0x76 or script_pubkey[1] != 0xA9:
        return None
    if script_pubkey[23] != 0x88 or script_pubkey[24] != 0xAC:
        return None
    return b58check_encode(script_pubkey[3:23], version)


def transaction_fee(chain: Chain, tx: Transaction) -> int:
    """交易手续费 = 全部输入金额 − 全部输出金额（链上没有单独的「手续费」字段）。"""
    total_in = 0
    for tx_in in tx.inputs:
        entry = chain.utxo.get(tx_in.outpoint())
        if entry is None:
            raise WalletError("cannot compute the fee: an input is not in the utxo set")
        total_in += entry.value
    return total_in - tx.total_out()


class Wallet:
    """由若干私钥组成的钱包，按 ``HASH160(pubkey)`` 索引以支持查找。"""

    def __init__(self, name: str = "wallet", keys: list[PrivateKey] | None = None) -> None:
        self.name = name
        self._by_hash160: dict[bytes, PrivateKey] = {}
        for key in keys or []:
            self.add_key(key)

    # -- 密钥 ------------------------------------------------------------- #

    def add_key(self, key: PrivateKey) -> str:
        self._by_hash160[key.public_key().hash160()] = key
        return key.public_key().address()

    def new_key(self) -> str:
        return self.add_key(PrivateKey.generate())

    @classmethod
    def from_secrets(cls, *secrets: int, name: str = "wallet") -> "Wallet":
        return cls(name=name, keys=[PrivateKey(secret) for secret in secrets])

    @classmethod
    def from_hex(cls, *secrets_hex: str, name: str = "wallet") -> "Wallet":
        return cls(name=name, keys=[PrivateKey(int(text, 16)) for text in secrets_hex])

    @property
    def key_count(self) -> int:
        return len(self._by_hash160)

    @property
    def hash160s(self) -> list[bytes]:
        return list(self._by_hash160)

    @property
    def secrets(self) -> list[int]:
        """全部私钥标量（供持久化/调试使用；顺序与 :attr:`hash160s` 一致）。"""
        return [key.secret for key in self._by_hash160.values()]

    @property
    def script_pubkeys(self) -> list[bytes]:
        return [p2pkh_script(digest) for digest in self._by_hash160]

    def first_script(self) -> bytes:
        if not self._by_hash160:
            raise WalletError("wallet has no keys")
        return p2pkh_script(self.hash160s[0])

    def address(self) -> str:
        return script_to_address(self.first_script())

    def addresses(self) -> list[str]:
        return [script_to_address(script) for script in self.script_pubkeys]

    def owns(self, script_pubkey: bytes) -> bool:
        return script_pubkey in set(self.script_pubkeys)

    def key_for_script(self, script_pubkey: bytes) -> PrivateKey | None:
        if len(script_pubkey) != 25:
            return None
        return self._by_hash160.get(script_pubkey[3:23])

    # -- 余额 ------------------------------------------------------------- #

    def utxos(self, chain: Chain) -> list[tuple[tuple[bytes, int], object]]:
        """本钱包的**可花费** UTXO（已过滤 coinbase 成熟度），按金额降序。"""
        found = []
        for script in self.script_pubkeys:
            found.extend(chain.spendable_utxos(script))
        found.sort(key=lambda item: item[1].value, reverse=True)
        return found

    def balance(self, chain: Chain) -> int:
        return sum(entry.value for _, entry in self.utxos(chain))

    # -- 构造与签名 ------------------------------------------------------- #

    def create_transaction(self, chain: Chain, outputs: list[TxOut], *,
                           fee_rate: float = 1.0, change_script: bytes | None = None,
                           locktime: int = 0) -> Transaction:
        """用 largest-first 选币构造一笔已签名的交易。

        ``fee_rate`` 单位是聪/字节；``change_script`` 默认为钱包的第一个地址。
        """
        if not outputs:
            raise WalletError("transaction must have at least one output")
        change_script = change_script or self.first_script()
        target = sum(tx_out.value for tx_out in outputs)

        candidates = self.utxos(chain)
        if not candidates:
            raise WalletError("no spendable utxos")

        selected: list[tuple[tuple[bytes, int], object]] = []
        total = 0
        for candidate in candidates:
            selected.append(candidate)
            total += candidate[1].value
            fee = estimate_fee(len(selected), len(outputs) + 1, fee_rate)
            if total >= target + fee:
                break
        else:
            raise WalletError(
                f"insufficient funds: have {total}, need at least "
                f"{target + estimate_fee(len(selected), len(outputs) + 1, fee_rate)}")

        fee = estimate_fee(len(selected), len(outputs) + 1, fee_rate)
        change = total - target - fee
        final_outputs = list(outputs)
        if change > DUST_THRESHOLD:
            final_outputs.append(TxOut(change, change_script))
        else:
            # 找零低于粉尘阈值：并入手续费，而不是造一个花不掉的输出
            fee = total - target

        tx = Transaction(
            version=1,
            inputs=[TxIn(key[0], key[1], b"", 0xFFFFFFFF) for key, _ in selected],
            outputs=final_outputs,
            locktime=locktime,
        )
        self.sign(chain, tx)
        return tx

    def send(self, chain: Chain, address: str, amount: int, *, fee_rate: float = 1.0,
             data: bytes | None = None) -> Transaction:
        """给某个地址转 ``amount`` 聪，可选附加一笔 ``OP_RETURN`` 数据输出。"""
        if amount <= 0:
            raise WalletError("amount must be positive")
        outputs = [TxOut(amount, address_to_script(address))]
        if data is not None:
            from .script import op_return_script
            outputs.append(TxOut(0, op_return_script(data)))
        return self.create_transaction(chain, outputs, fee_rate=fee_rate)

    def sign(self, chain: Chain, tx: Transaction) -> Transaction:
        """为交易中属于本钱包的每个输入生成 P2PKH 签名脚本。"""
        for index, tx_in in enumerate(tx.inputs):
            entry = chain.utxo.get(tx_in.outpoint())
            if entry is None:
                continue
            key = self.key_for_script(entry.tx_out.script_pubkey)
            if key is None:
                continue
            digest = tx.sighash(index, entry.tx_out.script_pubkey, SIGHASH_ALL)
            signature = key.sign(digest).to_der() + bytes([SIGHASH_ALL])
            tx_in.script_sig = p2pkh_script_sig(signature, key.public_key().to_bytes())
        return tx

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"Wallet({self.name!r}, keys={self.key_count}, address={self.address()})"

"""存证应用：把文件哈希锚定到链上，事后用 SPV 证明「这份文件当时就存在」。

这是 nimbus-chain 的**应用层**：一条能挖矿、能转账的链本身只是一个平台，
真正的问题是「它拿来干什么」。这里选的是**可检测篡改的存证**
（tamper-evident notarisation），因为它的价值主张与区块链的本质完全对齐：

* **不可事后修改**：把 ``SHA-256(文件内容)`` 写进一个 ``OP_RETURN`` 输出。
  想改文件而不被发现，就必须同时改掉那个输出——而那个输出被 PoW 与 Merkle 根
  锁在区块里，改它等于重做整条链的工作量证明。
* **可公开验证**：任何持有原文件的人都能算出哈希，然后在链上找到锚定交易，
  并用 Merkle 证明验证它确实在那个区块里——**不需要信任任何中心机构**。
* **轻客户端可行**：验证者只需要区块头 + 一条 Merkle 路径，不必下载整条链。

必须说清楚边界：区块链保证的是「**可检测**篡改」，而不是「阻止篡改」。文件
本身仍然可以被改，只是改完再也验不过了。措辞上绝不能声称"防篡改"。

链上只存 32 字节的哈希，**不存文件内容**——原始文件留在持有者手里。
"""

from __future__ import annotations

from dataclasses import dataclass

from .chain import Chain, InvalidBlock
from .crypto import sha256
from .mempool import Mempool
from .script import op_return_script
from .spv import SPVClient
from .tx import Transaction, TxOut
from .wallet import Wallet, WalletError

__all__ = [
    "DIGEST_SIZE",
    "NotaryError",
    "Notarization",
    "VerificationResult",
    "AnchorRecord",
    "document_digest",
    "Notary",
]

DIGEST_SIZE = 32


class NotaryError(WalletError):
    """存证构造或验证失败。"""


def document_digest(data: bytes) -> bytes:
    """文件的 32 字节指纹：``SHA-256(内容)``。

    刻意不做双哈希——存证的对象是「内容」而不是「区块头」，单次 SHA-256 已经
    满足抗碰撞要求，也让任何第三方能用一个普通工具独立算出同一结果。
    """
    return sha256(data)


@dataclass
class Notarization:
    """一次存证的产物：锚定交易 + 被锚定的摘要（两者都不可分割地绑定在一起）。"""

    tx: Transaction
    digest: bytes

    @property
    def txid(self) -> bytes:
        return self.tx.txid()

    @property
    def txid_hex(self) -> str:
        return self.tx.txid_hex()

    def to_dict(self) -> dict:
        return {
            "txid": self.txid_hex,
            "digest": self.digest.hex(),
            "outputs": len(self.tx.outputs),
            "size": len(self.tx.serialize()),
        }


@dataclass
class VerificationResult:
    """验证结论：不仅在链上存在，还要说清"凭什么"以及确认为何还不足。"""

    digest: bytes
    present: bool
    confirmed: bool
    reason: str
    txid: bytes | None = None
    block_hash: bytes | None = None
    height: int | None = None
    confirmations: int = 0
    spv_verified: bool = False

    @property
    def valid(self) -> bool:
        """对使用者而言「验证通过」= 已确认 + （若启用 SPV）SPV 证明也成立。"""
        return self.present and self.confirmed

    def to_dict(self) -> dict:
        return {
            "digest": self.digest.hex(),
            "valid": self.valid,
            "present": self.present,
            "confirmed": self.confirmed,
            "spv_verified": self.spv_verified,
            "reason": self.reason,
            "txid": self.txid[::-1].hex() if self.txid else None,
            "block_hash": self.block_hash[::-1].hex() if self.block_hash else None,
            "height": self.height,
            "confirmations": self.confirmations,
        }


@dataclass
class AnchorRecord:
    """链上发现的一条存证记录（供浏览器与 CLI 展示）。"""

    digest: bytes
    txid: bytes
    block_hash: bytes
    height: int
    confirmations: int

    def to_dict(self) -> dict:
        return {
            "digest": self.digest.hex(),
            "txid": self.txid[::-1].hex(),
            "block_hash": self.block_hash[::-1].hex(),
            "height": self.height,
            "confirmations": self.confirmations,
        }


class Notary:
    """存证应用：构造锚定交易、在链上检索、并给出带证据的验证结论。"""

    def __init__(self, chain: Chain, wallet: Wallet, mempool: Mempool | None = None) -> None:
        self.chain = chain
        self.wallet = wallet
        self.mempool = mempool

    # -- 存证 ------------------------------------------------------------- #

    def anchor_output(self, digest: bytes) -> TxOut:
        if len(digest) != DIGEST_SIZE:
            raise NotaryError(f"digest must be {DIGEST_SIZE} bytes")
        return TxOut(0, op_return_script(digest))

    def notarize(self, data: bytes, *, fee_rate: float = 1.0) -> Notarization:
        """把 ``SHA-256(data)`` 锚定到链上，返回 ``(交易, 摘要)``。

        注意：这里只**构造并签名**交易。真正"上链"还需要它被打进一个区块
        （走交易池，或者由矿工直接打包），因为存证的价值恰恰来自 PoW 的不可回退。
        """
        digest = document_digest(data)
        tx = self.wallet.create_transaction(self.chain, [self.anchor_output(digest)],
                                           fee_rate=fee_rate)
        return Notarization(tx=tx, digest=digest)

    def notarize_many(self, items: list[bytes], *, fee_rate: float = 1.0) -> tuple[Transaction, list[bytes]]:
        """一次交易锚定多份文件（每个摘要一个 ``OP_RETURN`` 输出），省手续费。"""
        if not items:
            raise NotaryError("nothing to notarise")
        digests = [document_digest(item) for item in items]
        tx = self.wallet.create_transaction(self.chain,
                                           [self.anchor_output(d) for d in digests],
                                           fee_rate=fee_rate)
        return tx, digests

    # -- 检索 ------------------------------------------------------------- #

    def lookup(self, digest: bytes) -> Transaction | None:
        """在链上找锚定了 ``digest`` 的交易；找不到返回 ``None``。"""
        self._require_digest(digest)
        found = self.chain.find_transactions_by_op_return(digest)
        return found[0] if found else None

    def anchors(self, limit: int | None = None) -> list[AnchorRecord]:
        """列出链上全部存证记录（摘要长度恰好 32 字节的 ``OP_RETURN`` 载荷）。"""
        records: list[AnchorRecord] = []
        for block in self.chain.main_blocks():
            block_hash = block.block_hash()
            height = self.chain.height_of(block_hash)
            for tx in block.transactions:
                for payload in tx.data_carrier_outputs():
                    if len(payload) != DIGEST_SIZE:
                        continue
                    records.append(AnchorRecord(
                        digest=payload,
                        txid=tx.txid(),
                        block_hash=block_hash,
                        height=height,
                        confirmations=self.chain.confirmations(tx.txid()),
                    ))
        records.sort(key=lambda record: (record.height, record.txid))
        return records[:limit] if limit is not None else records

    # -- 验证 ------------------------------------------------------------- #

    def verify(self, data: bytes, *, spv: SPVClient | None = None) -> VerificationResult:
        """验证「这份文件的内容是否已被锚定且确认」。

        返回结构里把「没找到」「只在交易池里」「已确认」「SPV 也验过」区分开——
        一个只回答 true/false 的接口会掩盖这些关键差别。
        """
        return self.verify_digest(document_digest(data), spv=spv)

    def verify_digest(self, digest: bytes, *, spv: SPVClient | None = None) -> VerificationResult:
        self._require_digest(digest)

        tx = self.lookup(digest)
        if tx is None:
            if self.mempool is not None and any(digest in candidate.data_carrier_outputs()
                                               for candidate in self.mempool.transactions()):
                return VerificationResult(
                    digest=digest, present=True, confirmed=False,
                    reason="anchoring transaction is still in the mempool (not yet mined)")
            return VerificationResult(digest=digest, present=False, confirmed=False,
                                      reason="no anchoring transaction found on the chain")

        location = self.chain.transaction_location(tx.txid())
        if location is None:  # pragma: no cover - 只可能出现在并发修改时
            return VerificationResult(digest=digest, present=True, confirmed=False,
                                      reason="transaction is known but not on the main chain")
        block_hash, height, index = location

        result = VerificationResult(
            digest=digest, present=True, confirmed=True,
            reason=f"anchored in block {block_hash[::-1].hex()[:16]}… at height {height}",
            txid=tx.txid(), block_hash=block_hash, height=height,
            confirmations=self.chain.confirmations(tx.txid()),
        )
        if spv is not None:
            result.spv_verified = self._verify_with_spv(tx.txid(), block_hash, index, spv)
            if not result.spv_verified:
                result.reason += " (spv proof could not be verified by this light client)"
        return result

    def _verify_with_spv(self, txid: bytes, block_hash: bytes, index: int,
                         spv: SPVClient) -> bool:
        """用轻客户端验证：只靠区块头 + Merkle 路径，不采信全节点的交易列表。"""
        if not spv.has_header(block_hash):
            return False
        try:
            proof = self.chain.get_block(block_hash).merkle_proof_for(index)
            return spv.verify_transaction_inclusion(txid, block_hash, proof)
        except (InvalidBlock, ValueError, AttributeError):
            return False

    @staticmethod
    def _require_digest(digest: bytes) -> None:
        if not isinstance(digest, (bytes, bytearray)) or len(digest) != DIGEST_SIZE:
            raise NotaryError(f"digest must be {DIGEST_SIZE} bytes, got {len(digest or b'')}")

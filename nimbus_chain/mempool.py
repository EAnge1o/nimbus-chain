"""交易池（mempool）：依赖、冲突、费用排序与出块打包。

交易池是「已签名但还没进块」的交易待命区。它必须先于区块做一遍**预校验**，
否则矿工会把注定失败的交易打包进块，白白浪费一个 PoW。

这里实现的四件事：

* **依赖**：一笔交易可以花另一笔「还在池子里」的交易产生的输出（子交易先等父
  交易）。因此打包顺序必须是拓扑序，且父交易被剔除时子交易也要一起走。
* **冲突**：同一个 outpoint 只能被池子里的一笔交易花掉；后来者直接拒绝。
* **费用排序**：按 ``fee / size``（聪/字节）排序，而不是绝对手续费——矿工的
  产出是「手续费 / 区块字节」。
* **区块同步**：新区块接入后 ``refresh()`` 会按依赖顺序重新校验每个条目，
  把已确认的、冲突的、悬空的条目清掉。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .chain import Chain
from .script import verify_input
from .tx import SIGHASH_ALL, Transaction, TxValidationError, checker_for

__all__ = ["MempoolError", "MempoolEntry", "Mempool"]


class MempoolError(ValueError):
    """交易被交易池拒绝。"""


@dataclass
class MempoolEntry:
    tx: Transaction
    fee: int
    size: int
    depends: set[bytes] = field(default_factory=set)
    spent: set[tuple[bytes, int]] = field(default_factory=set)

    @property
    def fee_rate(self) -> float:
        """聪/字节；池子排序与打包决策都看它。"""
        return self.fee / self.size if self.size else float(self.fee)

    def to_dict(self) -> dict:
        return {
            "txid": self.tx.txid_hex(),
            "fee": self.fee,
            "size": self.size,
            "fee_rate": round(self.fee_rate, 3),
            "depends": [txid[::-1].hex() for txid in sorted(self.depends)],
            "inputs": len(self.tx.inputs),
            "outputs": len(self.tx.outputs),
            "value": self.tx.total_out(),
        }


class Mempool:
    """内存交易池。与 :class:`~nimbus_chain.chain.Chain` 配合使用。"""

    def __init__(self, chain: Chain, *, max_bytes: int = 4 * 1024 * 1024,
                 min_fee_rate: float = 0.0, max_transactions: int = 5_000) -> None:
        self.chain = chain
        self.max_bytes = max_bytes
        self.min_fee_rate = min_fee_rate
        self.max_transactions = max_transactions
        self._entries: dict[bytes, MempoolEntry] = {}
        self._spent: dict[tuple[bytes, int], bytes] = {}     # outpoint -> 花它的 txid
        self._created: dict[tuple[bytes, int], bytes] = {}   # outpoint -> 创造它的 txid

    # -- 视图 ------------------------------------------------------------- #

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self._entries

    def get(self, txid: bytes) -> MempoolEntry | None:
        return self._entries.get(txid)

    def transactions(self) -> list[Transaction]:
        return [entry.tx for entry in self._entries.values()]

    def size_bytes(self) -> int:
        return sum(entry.size for entry in self._entries.values())

    def total_fees(self) -> int:
        return sum(entry.fee for entry in self._entries.values())

    def spenders_of(self, outpoint: tuple[bytes, int]) -> bytes | None:
        return self._spent.get(outpoint)

    def creator_of(self, outpoint: tuple[bytes, int]) -> bytes | None:
        return self._created.get(outpoint)

    # -- 校验 ------------------------------------------------------------- #

    def _script_pubkey_for(self, outpoint: tuple[bytes, int]) -> tuple[bytes | None, int, str]:
        """返回 ``(锁定脚本, 金额, 来源)``；来源是 ``'chain'`` 或 ``'mempool'``。"""
        entry = self.chain.utxo.get(outpoint)
        if entry is not None:
            return entry.tx_out.script_pubkey, entry.value, "chain"
        creator = self._created.get(outpoint)
        if creator is not None:
            parent = self._entries[creator].tx
            return parent.outputs[outpoint[1]].script_pubkey, parent.outputs[outpoint[1]].value, "mempool"
        return None, 0, "missing"

    def _validate(self, tx: Transaction) -> MempoolEntry:
        try:
            tx.validate_structure()
        except TxValidationError as error:
            raise MempoolError(str(error)) from error

        if tx.is_coinbase():
            raise MempoolError("coinbase transactions cannot enter the mempool")

        txid = tx.txid()
        if txid in self._entries:
            raise MempoolError(f"transaction {tx.txid_hex()} is already in the mempool")
        if self.chain.get_transaction(txid) is not None:
            raise MempoolError(f"transaction {tx.txid_hex()} is already confirmed")

        spent = set(tx.outpoints())
        if len(spent) != len(tx.inputs):
            raise MempoolError("transaction spends the same outpoint twice")
        for outpoint in spent:
            conflict = self._spent.get(outpoint)
            if conflict is not None:
                raise MempoolError(
                    f"conflict: {outpoint[0][::-1].hex()}:{outpoint[1]} is already spent by "
                    f"{conflict[::-1].hex()} in the mempool")

        total_in = 0
        depends: set[bytes] = set()
        for input_index, tx_in in enumerate(tx.inputs):
            outpoint = tx_in.outpoint()
            script_pubkey, value, origin = self._script_pubkey_for(outpoint)
            if script_pubkey is None:
                raise MempoolError(
                    f"missing inputs: {outpoint[0][::-1].hex()}:{outpoint[1]} is not in the "
                    f"utxo set nor created by a mempool transaction")
            if origin == "chain":
                chain_entry = self.chain.utxo[outpoint]
                if chain_entry.is_coinbase and \
                        self.chain.height - chain_entry.height < self.chain.params.coinbase_maturity:
                    raise MempoolError("spends an immature coinbase output")
            if not verify_input(tx_in.script_sig, script_pubkey, checker_for(tx, input_index)):
                raise MempoolError(f"script verification failed for {tx.txid_hex()}")
            total_in += value
            creator = self._created.get(outpoint)
            if creator is not None:
                depends.add(creator)

        fee = total_in - tx.total_out()
        if fee < 0:
            raise MempoolError(f"transaction {tx.txid_hex()} spends more than its inputs")

        size = len(tx.serialize())
        entry = MempoolEntry(tx=tx, fee=fee, size=size, depends=depends, spent=spent)
        if entry.fee_rate < self.min_fee_rate:
            raise MempoolError(
                f"fee rate {entry.fee_rate:.3f} sat/byte is below the minimum {self.min_fee_rate}")
        return entry

    # -- 增删 ------------------------------------------------------------- #

    def add_transaction(self, tx: Transaction) -> MempoolEntry:
        """把一笔交易加入池子；被拒绝时抛 :class:`MempoolError`。"""
        entry = self._validate(tx)
        if len(self._entries) >= self.max_transactions:
            raise MempoolError("mempool transaction limit reached")
        if self.size_bytes() + entry.size > self.max_bytes:
            raise MempoolError("mempool byte limit reached")

        txid = tx.txid()
        self._entries[txid] = entry
        for outpoint in entry.spent:
            self._spent[outpoint] = txid
        for index, _ in enumerate(tx.outputs):
            self._created[(txid, index)] = txid
        return entry

    def descendants_of(self, txid: bytes) -> list[bytes]:
        """所有（直接或间接）依赖 ``txid`` 的交易，按拓扑序返回。"""
        found: list[bytes] = []
        frontier = [txid]
        seen = {txid}
        while frontier:
            current = frontier.pop(0)
            for candidate, entry in self._entries.items():
                if candidate in seen or current not in entry.depends:
                    continue
                seen.add(candidate)
                found.append(candidate)
                frontier.append(candidate)
        return found

    def remove(self, txid: bytes, *, with_descendants: bool = True) -> list[bytes]:
        """移除交易（默认连带移除依赖它的子交易），返回被移除的 txid 列表。"""
        removed: list[bytes] = []
        targets = [txid, *self.descendants_of(txid)] if with_descendants else [txid]
        for target in targets:
            entry = self._entries.pop(target, None)
            if entry is None:
                continue
            for outpoint in entry.spent:
                self._spent.pop(outpoint, None)
            for index, _ in enumerate(entry.tx.outputs):
                self._created.pop((target, index), None)
            removed.append(target)
        return removed

    def remove_for_block(self, block) -> list[bytes]:
        """区块接入后清掉池中已被确认的交易（连带其子交易）。"""
        removed: list[bytes] = []
        for tx in block.transactions:
            txid = tx.txid()
            if txid in self._entries:
                removed.extend(self.remove(txid))
        return removed

    def re_add(self, transactions: list[Transaction]) -> list[Transaction]:
        """重组后被挤出主链的交易尝试回池；不合法的静默丢弃。"""
        accepted = []
        for tx in transactions:
            try:
                self.add_transaction(tx)
                accepted.append(tx)
            except (MempoolError, ValueError):
                continue
        return accepted

    def refresh(self) -> list[bytes]:
        """按依赖顺序重新校验全部条目，剔除已确认/冲突/悬空的交易。

        新区块接入后调用。返回被剔除的 txid 列表。
        """
        ordered = [self._entries[txid] for txid in self._topological_order()]
        self._entries.clear()
        self._spent.clear()
        self._created.clear()
        dropped: list[bytes] = []
        for entry in ordered:
            try:
                self.add_transaction(entry.tx)
            except (MempoolError, ValueError):
                dropped.append(entry.tx.txid())
        return dropped

    def clear(self) -> None:
        self._entries.clear()
        self._spent.clear()
        self._created.clear()

    # -- 排序与打包 ------------------------------------------------------- #

    def _topological_order(self) -> list[bytes]:
        """父交易先于子交易的顺序；同层内按费用率从高到低。"""
        remaining = dict(self._entries)
        ordered: list[bytes] = []
        resolved: set[bytes] = set()
        while remaining:
            ready = [txid for txid, entry in remaining.items() if entry.depends <= resolved]
            if not ready:
                # 理论不可达：入池时已保证依赖存在
                ready = list(remaining)
            ready.sort(key=lambda txid: self._entries[txid].fee_rate, reverse=True)
            for txid in ready:
                ordered.append(txid)
                resolved.add(txid)
                remaining.pop(txid, None)
        return ordered

    def ordered_transactions(self) -> list[Transaction]:
        return [self._entries[txid].tx for txid in self._topological_order()]

    def select_for_block(self, *, max_transactions: int | None = None,
                         max_bytes: int | None = None) -> list[Transaction]:
        """按「父交易先打包 + 高费用率优先」挑选要打包的交易。

        父交易没被选中的子交易一律跳过——否则打包出来的区块会因为「输入不存在」
        被整个拒绝。
        """
        selected: list[Transaction] = []
        included: set[bytes] = set()
        used_bytes = 0
        for txid in self._topological_order():
            entry = self._entries[txid]
            if not entry.depends <= included:
                continue
            if max_transactions is not None and len(selected) >= max_transactions:
                break
            if max_bytes is not None and used_bytes + entry.size > max_bytes:
                continue
            selected.append(entry.tx)
            included.add(txid)
            used_bytes += entry.size
        return selected

    # -- 展示 ------------------------------------------------------------- #

    def stats(self) -> dict:
        return {
            "transactions": len(self._entries),
            "bytes": self.size_bytes(),
            "total_fees": self.total_fees(),
            "max_bytes": self.max_bytes,
            "min_fee_rate": self.min_fee_rate,
        }

    def summary(self, limit: int = 10) -> list[dict]:
        entries = sorted(self._entries.values(), key=lambda entry: entry.fee_rate, reverse=True)
        return [entry.to_dict() for entry in entries[:limit]]

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"Mempool({len(self._entries)} txs, {self.size_bytes()} bytes)"

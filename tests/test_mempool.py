"""交易池测试：依赖、冲突、费用排序、打包选择、区块同步与重组回池。"""

from __future__ import annotations

import unittest

from nimbus_chain.chain import Chain, ChainParams
from nimbus_chain.mempool import Mempool, MempoolError
from nimbus_chain.script import p2pkh_script, p2pkh_script_sig
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.tx import Transaction, TxIn, TxOut
from nimbus_chain.wallet import Wallet

PARAMS = ChainParams(retarget_interval=10_000, coinbase_maturity=1)
MINER_KEY = PrivateKey(0xF00D)
ALICE_KEY = PrivateKey(0xA11CE)
BOB_KEY = PrivateKey(0xB0B)
MINER_SCRIPT = p2pkh_script(MINER_KEY.public_key().hash160())
ALICE_SCRIPT = p2pkh_script(ALICE_KEY.public_key().hash160())
BOB_SCRIPT = p2pkh_script(BOB_KEY.public_key().hash160())


def miner_wallet() -> Wallet:
    return Wallet(name="miner", keys=[MINER_KEY])


def alice_wallet() -> Wallet:
    return Wallet(name="alice", keys=[ALICE_KEY])


def fund(chain: Chain, wallet: Wallet, blocks: int = 3) -> None:
    """挖若干块并把 coinbase 付给钱包（coinbase_maturity=1 ⇒ 下一块即可花）。"""
    script = wallet.first_script()
    for _ in range(blocks):
        chain.add_block(chain.build_and_mine([], script))


def signed_spend(prev_txid: bytes, prev_index: int, prev_script: bytes,
                 outputs: list[TxOut], key: PrivateKey) -> Transaction:
    """构造并签名一笔 P2PKH 花费；显式给出被花输出的属性，便于分叉/冲突场景。"""
    tx = Transaction(1, [TxIn(prev_txid, prev_index, b"")], outputs)
    digest = tx.sighash(0, prev_script)
    tx.inputs[0].script_sig = p2pkh_script_sig(
        key.sign(digest).to_der() + b"\x01", key.public_key().to_bytes())
    return tx


class MempoolBasicsTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(PARAMS)
        self.miner = miner_wallet()
        self.alice = alice_wallet()
        # 3 块 => 高度 3 时可花的是高度 1、2 的 coinbase（成熟度 1），共 2 个
        fund(self.chain, self.miner, blocks=3)
        self.pool = Mempool(self.chain)

    def test_add_and_lookup(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        entry = self.pool.add_transaction(tx)
        self.assertEqual(len(self.pool), 1)
        self.assertIn(tx.txid(), self.pool)
        self.assertEqual(self.pool.get(tx.txid()).fee, entry.fee)
        self.assertGreater(entry.fee_rate, 0)

    def test_coinbase_rejected(self):
        block = self.chain.build_and_mine([], MINER_SCRIPT)
        with self.assertRaises(MempoolError) as context:
            self.pool.add_transaction(block.transactions[0])
        self.assertIn("coinbase", str(context.exception))

    def test_duplicate_rejected(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        self.pool.add_transaction(tx)
        with self.assertRaises(MempoolError) as context:
            self.pool.add_transaction(tx)
        self.assertIn("already in the mempool", str(context.exception))

    def test_confirmed_transaction_rejected(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        self.chain.add_block(self.chain.build_and_mine([tx], MINER_SCRIPT))
        with self.assertRaises(MempoolError) as context:
            self.pool.add_transaction(tx)
        self.assertIn("already confirmed", str(context.exception))

    def test_missing_inputs_rejected(self):
        bogus = Transaction(1, [TxIn(b"\x77" * 32, 0, b"")], [TxOut(1, MINER_SCRIPT)])
        with self.assertRaises(MempoolError) as context:
            self.pool.add_transaction(bogus)
        self.assertIn("missing inputs", str(context.exception))

    def test_bad_signature_rejected(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        tx.inputs[0].script_sig = b"\x01\x02\x03"
        with self.assertRaises(MempoolError) as context:
            self.pool.add_transaction(tx)
        self.assertIn("script verification failed", str(context.exception))

    def test_conflict_rejected(self):
        """同一个 outpoint 被两笔交易花：先到者留下，后来者被拒。"""
        (txid, index), entry = self.miner.utxos(self.chain)[0]
        first = signed_spend(txid, index, entry.tx_out.script_pubkey,
                             [TxOut(entry.value - 1000, ALICE_SCRIPT)], MINER_KEY)
        self.pool.add_transaction(first)
        second = signed_spend(txid, index, entry.tx_out.script_pubkey,
                              [TxOut(entry.value - 2000, ALICE_SCRIPT)], MINER_KEY)
        with self.assertRaises(MempoolError) as context:
            self.pool.add_transaction(second)
        self.assertIn("conflict", str(context.exception))

    def test_immature_coinbase_rejected(self):
        """默认成熟度 100：刚挖出来的 coinbase 不能进池。"""
        strict = Chain(ChainParams(retarget_interval=10_000))
        key = PrivateKey(0xC0FFEE)
        script = p2pkh_script(key.public_key().hash160())
        strict.add_block(strict.build_and_mine([], script))
        (txid, index), entry = strict.utxos_for_script(script)[0]
        tx = signed_spend(txid, index, entry.tx_out.script_pubkey,
                          [TxOut(entry.value - 1000, ALICE_SCRIPT)], key)
        with self.assertRaises(MempoolError) as context:
            Mempool(strict).add_transaction(tx)
        self.assertIn("immature coinbase", str(context.exception))

    def test_negative_fee_rejected(self):
        (txid, index), entry = self.miner.utxos(self.chain)[0]
        greedy = signed_spend(txid, index, entry.tx_out.script_pubkey,
                              [TxOut(entry.value + 1, MINER_SCRIPT)], MINER_KEY)
        with self.assertRaises(MempoolError) as context:
            self.pool.add_transaction(greedy)
        self.assertIn("spends more than its inputs", str(context.exception))

    def test_coinbase_in_mempool_structure_checks(self):
        """一笔假 coinbase（prev 全零）也必须被拒。"""
        fake = Transaction(1, [TxIn(b"\x00" * 32, 0xFFFFFFFF, b"\x03abc")],
                           [TxOut(1, MINER_SCRIPT)])
        with self.assertRaises(MempoolError):
            self.pool.add_transaction(fake)

    def test_min_fee_rate_enforced(self):
        pool = Mempool(self.chain, min_fee_rate=1000.0)
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        with self.assertRaises(MempoolError) as context:
            pool.add_transaction(tx)
        self.assertIn("below the minimum", str(context.exception))

    def test_transaction_limit_enforced(self):
        pool = Mempool(self.chain, max_transactions=1)
        pool.add_transaction(self.miner.send(self.chain, self.alice.address(), 100_000))
        (txid, index), entry = self.miner.utxos(self.chain)[1]
        second = signed_spend(txid, index, entry.tx_out.script_pubkey,
                              [TxOut(entry.value - 5000, ALICE_SCRIPT)], MINER_KEY)
        with self.assertRaises(MempoolError) as context:
            pool.add_transaction(second)
        self.assertIn("transaction limit", str(context.exception))


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(PARAMS)
        self.miner = miner_wallet()
        self.alice = alice_wallet()
        self.bob = Wallet(name="bob", keys=[BOB_KEY])
        fund(self.chain, self.miner, blocks=3)
        self.pool = Mempool(self.chain)

    def _parent_and_child(self):
        parent = self.miner.send(self.chain, self.alice.address(), 500_000)
        self.pool.add_transaction(parent)
        # alice 的钱还没进块，但她可以立刻花掉它（链式交易）
        child = signed_spend(parent.txid(), 0, ALICE_SCRIPT,
                             [TxOut(400_000, BOB_SCRIPT), TxOut(99_500, ALICE_SCRIPT)], ALICE_KEY)
        return parent, child

    def test_child_transaction_has_dependency(self):
        parent, child = self._parent_and_child()
        entry = self.pool.add_transaction(child)
        self.assertEqual(entry.depends, {parent.txid()})
        self.assertEqual(self.pool.creator_of((parent.txid(), 0)), parent.txid())

    def test_topological_order_lists_parent_first(self):
        parent, child = self._parent_and_child()
        self.pool.add_transaction(child)
        ordered = [tx.txid() for tx in self.pool.ordered_transactions()]
        self.assertLess(ordered.index(parent.txid()), ordered.index(child.txid()))

    def test_select_for_block_skips_child_when_parent_excluded(self):
        parent, child = self._parent_and_child()
        self.pool.add_transaction(child)
        # 只允许打 1 笔：必须选到父交易，子交易因依赖未满足被跳过
        selected = self.pool.select_for_block(max_transactions=1)
        self.assertEqual([tx.txid() for tx in selected], [parent.txid()])

    def test_removing_parent_removes_children(self):
        parent, child = self._parent_and_child()
        self.pool.add_transaction(child)
        removed = self.pool.remove(parent.txid())
        self.assertEqual(set(removed), {parent.txid(), child.txid()})
        self.assertEqual(len(self.pool), 0)

    def test_spenders_and_creators_indexes(self):
        parent, child = self._parent_and_child()
        self.pool.add_transaction(child)
        # (parent, 0) 这个 outpoint 是 parent 创造的、被 child 花掉的
        self.assertEqual(self.pool.creator_of((parent.txid(), 0)), parent.txid())
        self.assertEqual(self.pool.spenders_of((parent.txid(), 0)), child.txid())


class FeeOrderingTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(PARAMS)
        self.miner = miner_wallet()
        fund(self.chain, self.miner, blocks=4)
        self.pool = Mempool(self.chain)

    def test_higher_fee_rate_selected_first(self):
        utxos = self.miner.utxos(self.chain)
        self.assertGreaterEqual(len(utxos), 2)
        cheap = signed_spend(utxos[1][0][0], utxos[1][0][1], utxos[1][1].tx_out.script_pubkey,
                             [TxOut(utxos[1][1].value - 100, ALICE_SCRIPT)], MINER_KEY)
        rich = signed_spend(utxos[0][0][0], utxos[0][0][1], utxos[0][1].tx_out.script_pubkey,
                            [TxOut(utxos[0][1].value - 5_000, ALICE_SCRIPT)], MINER_KEY)
        self.pool.add_transaction(cheap)
        self.pool.add_transaction(rich)
        self.assertGreater(self.pool.get(rich.txid()).fee_rate,
                           self.pool.get(cheap.txid()).fee_rate)
        selected = self.pool.select_for_block(max_transactions=1)
        self.assertEqual([tx.txid() for tx in selected], [rich.txid()])

    def test_byte_budget_respected(self):
        tx = self.miner.send(self.chain, alice_wallet().address(), 100_000)
        self.pool.add_transaction(tx)
        size = self.pool.get(tx.txid()).size
        self.assertEqual(self.pool.select_for_block(max_bytes=size), [tx])
        self.assertEqual(self.pool.select_for_block(max_bytes=size - 1), [])

    def test_total_fees_and_stats(self):
        tx = self.miner.send(self.chain, alice_wallet().address(), 100_000)
        entry = self.pool.add_transaction(tx)
        stats = self.pool.stats()
        self.assertEqual(stats["transactions"], 1)
        self.assertEqual(stats["bytes"], entry.size)
        self.assertEqual(stats["total_fees"], entry.fee)
        self.assertEqual(len(self.pool.summary()), 1)
        self.assertIn("Mempool(", repr(self.pool))

    def test_summary_ordering(self):
        utxos = self.miner.utxos(self.chain)
        cheap = signed_spend(utxos[1][0][0], utxos[1][0][1], utxos[1][1].tx_out.script_pubkey,
                             [TxOut(utxos[1][1].value - 50, ALICE_SCRIPT)], MINER_KEY)
        rich = signed_spend(utxos[0][0][0], utxos[0][0][1], utxos[0][1].tx_out.script_pubkey,
                            [TxOut(utxos[0][1].value - 5_000, ALICE_SCRIPT)], MINER_KEY)
        self.pool.add_transaction(cheap)
        self.pool.add_transaction(rich)
        self.assertEqual(self.pool.summary()[0]["txid"], rich.txid_hex())


class MempoolSyncTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(PARAMS)
        self.miner = miner_wallet()
        fund(self.chain, self.miner, blocks=3)
        self.alice = alice_wallet()
        self.pool = Mempool(self.chain)

    def test_remove_for_block_clears_confirmed_transactions(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        self.pool.add_transaction(tx)
        block = self.chain.build_and_mine([tx], MINER_SCRIPT)
        self.chain.add_block(block)
        self.assertEqual(self.pool.remove_for_block(block), [tx.txid()])
        self.assertEqual(len(self.pool), 0)

    def test_refresh_drops_transactions_that_became_invalid(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        self.pool.add_transaction(tx)
        # 该交易被打进区块 => 池中这笔已确认，refresh 必须剔除
        self.chain.add_block(self.chain.build_and_mine([tx], MINER_SCRIPT))
        self.assertEqual(self.pool.refresh(), [tx.txid()])
        self.assertEqual(len(self.pool), 0)

    def test_refresh_keeps_still_valid_transactions(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        self.pool.add_transaction(tx)
        # 挖一个不含该交易的块：交易依然有效
        self.chain.add_block(self.chain.build_and_mine([], MINER_SCRIPT))
        self.assertEqual(self.pool.refresh(), [])
        self.assertEqual(len(self.pool), 1)

    def test_re_add_ignores_invalid_transactions(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        self.chain.add_block(self.chain.build_and_mine([tx], MINER_SCRIPT))
        self.assertEqual(self.pool.re_add([tx]), [])
        self.assertEqual(len(self.pool), 0)

    def test_re_add_accepts_still_valid_transactions(self):
        tx = self.miner.send(self.chain, self.alice.address(), 100_000)
        accepted = self.pool.re_add([tx])
        self.assertEqual([item.txid() for item in accepted], [tx.txid()])
        self.assertEqual(len(self.pool), 1)

    def test_clear(self):
        self.pool.add_transaction(self.miner.send(self.chain, self.alice.address(), 100_000))
        self.pool.clear()
        self.assertEqual(len(self.pool), 0)
        self.assertIsNone(self.pool.spenders_of((b"\x00" * 32, 0)))


if __name__ == "__main__":
    unittest.main()

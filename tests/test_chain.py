"""链测试：校验流水线、难度重定目标与钳制、累计工作量重组、UTXO 一致性、持久化。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nimbus_chain.block import (
    Block,
    BlockHeader,
    bits_to_target,
    block_work,
    mine,
    target_to_bits,
)
from nimbus_chain.chain import (
    GENESIS_TIMESTAMP,
    Chain,
    ChainParams,
    InvalidBlock,
    create_genesis_block,
)
from nimbus_chain.crypto import hash160
from nimbus_chain.merkle import merkle_root
from nimbus_chain.script import op_return_script, p2pkh_script, p2pkh_script_sig, serialize_script
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.tx import Transaction, TxIn, TxOut, coinbase_transaction

MINER = PrivateKey(0xD0C0FFEE_1234_5678_9ABC_DEF0_1234_5678_9ABC_DEF0_1234_5678)
MINER_SCRIPT = p2pkh_script(MINER.public_key().hash160())
OTHER_SCRIPT = p2pkh_script(hash160(b"other-address"))
NO_RETARGET = ChainParams(retarget_interval=10_000)
SPEND_PARAMS = ChainParams(retarget_interval=10_000, coinbase_maturity=1)
REORG_PARAMS = ChainParams(retarget_interval=2, target_block_time=100, coinbase_maturity=1)


def mine_onto(chain: Chain, txs: list[Transaction] | None = None,
              script: bytes = MINER_SCRIPT, timestamp: int | None = None):
    """在当前链尖上挖一个块并交给链处理。"""
    block = chain.build_and_mine(list(txs or []), script, timestamp)
    return block, chain.add_block(block)


def build_on(chain: Chain, parent: Block, txs: list[Transaction], script: bytes,
             timestamp: int) -> Block:
    """在**指定父块**上组装并挖出一个块（用来手工制造分叉）。"""
    return mine(chain.assemble_block(parent.block_hash(), timestamp, txs, script))


def build_fork(chain: Chain, genesis: Block, count: int) -> list:
    """从创世块分叉出 ``count`` 个空块，返回每次 ``add_block`` 的结果。"""
    results = []
    parent = genesis
    timestamp = genesis.header.timestamp + 1000
    for _ in range(count):
        parent = build_on(chain, parent, [], MINER_SCRIPT, timestamp)
        results.append(chain.add_block(parent))
        timestamp += 600
    return results


def make_spend(prev_txid: bytes, prev_index: int, script_pubkey: bytes, value: int,
               to_script: bytes, amount: int, fee: int,
               key: PrivateKey = MINER) -> Transaction:
    """构造并签名一笔 P2PKH 花费（显式传入被花输出的属性，便于制造双花场景）。"""
    tx = Transaction(1, [TxIn(prev_txid, prev_index, b"")],
                     [TxOut(amount, to_script), TxOut(value - amount - fee, MINER_SCRIPT)])
    digest = tx.sighash(0, script_pubkey)
    signature = key.sign(digest).to_der() + b"\x01"
    tx.inputs[0].script_sig = p2pkh_script_sig(signature, key.public_key().to_bytes())
    return tx


def spend_coinbase(chain: Chain, txid: bytes, to_script: bytes, amount: int, fee: int,
                   key: PrivateKey = MINER) -> Transaction:
    """花掉 ``txid`` 的第 0 号输出（必须是本链上的 P2PKH coinbase）。"""
    tx_out = chain.get_transaction(txid).outputs[0]
    return make_spend(txid, 0, tx_out.script_pubkey, tx_out.value, to_script, amount, fee, key)


class GenesisTests(unittest.TestCase):
    def test_genesis_is_valid_and_at_height_zero(self):
        chain = Chain()
        self.assertEqual(chain.height, 0)
        self.assertTrue(chain.genesis.has_valid_pow())
        self.assertTrue(chain.genesis.merkle_root_matches())
        self.assertTrue(chain.genesis.transactions[0].is_coinbase())
        self.assertEqual(set(chain.utxo), {(chain.genesis.transactions[0].txid(), 0)})

    def test_genesis_bits_equal_pow_limit(self):
        chain = Chain()
        self.assertEqual(chain.genesis.header.bits, chain.params.pow_limit_bits)

    def test_genesis_is_memoized(self):
        self.assertIs(create_genesis_block(), create_genesis_block())

    def test_genesis_coinbase_respects_subsidy(self):
        chain = Chain()
        coinbase = chain.genesis.transactions[0]
        self.assertLessEqual(coinbase.total_out(), chain.subsidy(0))


class BlockAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(NO_RETARGET)

    def test_extends_tip(self):
        block, result = mine_onto(self.chain)
        self.assertEqual(result.status, "connected")
        self.assertEqual(self.chain.height, 1)
        self.assertEqual(self.chain.tip.block_hash(), block.block_hash())
        self.assertEqual(self.chain.total_work, 2 * block_work(self.chain.genesis.header.bits))

    def test_duplicate_is_idempotent(self):
        block, _ = mine_onto(self.chain)
        again = self.chain.add_block(block)
        self.assertEqual(again.status, "duplicate")
        self.assertEqual(self.chain.height, 1)

    def test_orphan_rejected(self):
        orphan = BlockHeader(1, b"\xAB" * 32, b"\xCD" * 32, GENESIS_TIMESTAMP + 10,
                             NO_RETARGET.pow_limit_bits)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(Block(orphan, []))
        self.assertIn("orphan", str(context.exception))

    def test_pow_failure_rejected(self):
        block = self.chain.build_candidate([], MINER_SCRIPT)
        target = block.header.target()
        while int.from_bytes(block.header.hash(), "big") <= target:
            block.header.nonce += 1
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(block)
        self.assertIn("proof of work", str(context.exception))

    def test_wrong_bits_rejected_even_with_valid_pow(self):
        block = self.chain.build_candidate([], MINER_SCRIPT)
        block.header.bits = target_to_bits(bits_to_target(block.header.bits) // 2)
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(block)
        self.assertIn("difficulty bits", str(context.exception))

    def test_tampered_merkle_root_rejected(self):
        block = self.chain.build_and_mine([], MINER_SCRIPT)
        block.header.merkle_root = b"\x00" * 32
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(block)
        self.assertIn("merkle root", str(context.exception))

    def test_timestamp_not_after_median_time_past_rejected(self):
        block = self.chain.build_candidate(
            [], MINER_SCRIPT, timestamp=self.chain.tip.header.timestamp - 1)
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(block)
        self.assertIn("median time past", str(context.exception))

    def test_empty_block_rejected(self):
        header = BlockHeader(1, self.chain.tip_hash, b"\x00" * 32,
                             self.chain.tip.header.timestamp + 600,
                             self.chain.params.pow_limit_bits)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(Block(header, []))
        self.assertIn("no transactions", str(context.exception))

    def test_two_coinbases_rejected(self):
        block = self.chain.build_candidate([], MINER_SCRIPT)
        block.transactions.append(coinbase_transaction(1, 1, MINER_SCRIPT))
        block.header.merkle_root = block.compute_merkle_root()
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(block)
        self.assertIn("more than one coinbase", str(context.exception))

    def test_duplicate_transaction_in_block_rejected(self):
        funding, _ = mine_onto(self.chain)
        txid = funding.transactions[0].txid()
        spend = spend_coinbase(self.chain, txid, OTHER_SCRIPT, 1000, 100)
        block = self.chain.build_candidate([spend, spend], MINER_SCRIPT)
        block.header.merkle_root = block.compute_merkle_root()
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(block)
        self.assertIn("duplicate transactions", str(context.exception))

    def test_coinbase_overpayment_rejected(self):
        block = self.chain.assemble_block(
            self.chain.tip_hash, self.chain.tip.header.timestamp + 600, [], MINER_SCRIPT,
            coinbase_value=self.chain.subsidy(1) + 1)
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            self.chain.add_block(block)
        self.assertIn("coinbase pays", str(context.exception))


class SpendingTests(unittest.TestCase):
    def test_spend_coinbase_after_maturity(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        txid = funding.transactions[0].txid()
        tx = spend_coinbase(chain, txid, OTHER_SCRIPT, 1000, 100)
        _, result = mine_onto(chain, [tx])
        self.assertEqual(result.status, "connected")
        self.assertIn((tx.txid(), 0), chain.utxo)
        self.assertNotIn((txid, 0), chain.utxo)
        self.assertEqual(chain.balance(OTHER_SCRIPT), 1000)
        # 手续费也归矿工：change 少 100，但下一个 coinbase 多 100
        self.assertEqual(chain.balance(MINER_SCRIPT),
                         chain.subsidy(1) - 1000 + chain.subsidy(2))

    def test_immature_coinbase_rejected(self):
        chain = Chain()  # 默认成熟度 100
        funding, _ = mine_onto(chain)
        tx = spend_coinbase(chain, funding.transactions[0].txid(), OTHER_SCRIPT, 1000, 100)
        block = chain.assemble_block(chain.tip_hash, chain.tip.header.timestamp + 600,
                                    [tx], MINER_SCRIPT)
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            chain.add_block(block)
        self.assertIn("immature coinbase", str(context.exception))

    def test_bad_signature_rejected(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        tx = spend_coinbase(chain, funding.transactions[0].txid(), OTHER_SCRIPT, 1000, 100)
        tx.inputs[0].script_sig = serialize_script([b"\x30" * 70 + b"\x01", b"\x02" * 33])
        block = chain.assemble_block(chain.tip_hash, chain.tip.header.timestamp + 600,
                                    [tx], MINER_SCRIPT)
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            chain.add_block(block)
        self.assertIn("script verification failed", str(context.exception))

    def test_double_spend_in_later_block_rejected(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        txid = funding.transactions[0].txid()
        first = spend_coinbase(chain, txid, OTHER_SCRIPT, 1000, 100)
        mine_onto(chain, [first])

        second = spend_coinbase(chain, txid, OTHER_SCRIPT, 2000, 100)
        # 显式给 coinbase 金额，跳过组装阶段的 UTXO 预检，让区块真的被提交给链
        block = chain.assemble_block(chain.tip_hash, chain.tip.header.timestamp + 600,
                                     [second], MINER_SCRIPT,
                                     coinbase_value=chain.subsidy(2) + 100)
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            chain.add_block(block)
        self.assertIn("already-spent", str(context.exception))

    def test_double_spend_within_one_block_rejected(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        txid = funding.transactions[0].txid()
        first = spend_coinbase(chain, txid, OTHER_SCRIPT, 1000, 100)
        second = spend_coinbase(chain, txid, MINER_SCRIPT, 2000, 100)
        block = chain.assemble_block(chain.tip_hash, chain.tip.header.timestamp + 600,
                                     [first, second], MINER_SCRIPT,
                                     coinbase_value=chain.subsidy(2) + 200)
        mine(block)
        with self.assertRaises(InvalidBlock) as context:
            chain.add_block(block)
        self.assertIn("already-spent", str(context.exception))

    def test_fee_flows_into_coinbase(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        tx = spend_coinbase(chain, funding.transactions[0].txid(), OTHER_SCRIPT, 1000, 250)
        collection, _ = mine_onto(chain, [tx])
        self.assertEqual(collection.transactions[0].total_out(), chain.subsidy(2) + 250)

    def test_spend_more_than_inputs_rejected(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        txid = funding.transactions[0].txid()
        greedy = Transaction(1, [TxIn(txid, 0, b"")],
                             [TxOut(chain.subsidy(1), OTHER_SCRIPT), TxOut(1, MINER_SCRIPT)])
        with self.assertRaises(InvalidBlock) as context:
            chain.assemble_block(chain.tip_hash, chain.tip.header.timestamp + 600,
                                 [greedy], MINER_SCRIPT)
        self.assertIn("more than its inputs", str(context.exception))


class DifficultyTests(unittest.TestCase):
    """难度重定目标只在 retarget_interval 的整数倍高度发生，并做 4 倍钳制。"""

    CLAMP = ChainParams(retarget_interval=4, target_block_time=100, max_adjustment_factor=4)

    def _chain_with_timestamps(self, offsets: list[int]) -> Chain:
        chain = Chain(self.CLAMP)
        base = chain.genesis.header.timestamp
        for offset in offsets:
            mine_onto(chain, timestamp=base + offset)
        return chain

    def test_no_retarget_before_interval(self):
        chain = self._chain_with_timestamps([1, 2])
        self.assertEqual(chain.next_block_bits(), chain.params.pow_limit_bits)

    def test_fast_blocks_make_target_harder_by_at_most_four_x(self):
        chain = self._chain_with_timestamps([1, 2, 3])
        harder = chain.next_block_bits()
        limit_target = bits_to_target(chain.params.pow_limit_bits)
        self.assertNotEqual(harder, chain.params.pow_limit_bits)
        self.assertEqual(harder, target_to_bits(limit_target // 4))
        self.assertLess(bits_to_target(harder), limit_target)

    def test_slow_blocks_cannot_exceed_pow_limit(self):
        chain = self._chain_with_timestamps([1000, 2000, 3000])
        self.assertEqual(chain.next_block_bits(), chain.params.pow_limit_bits)

    def test_lower_clamp_engages(self):
        """实测时间跨度被抬到 target_timespan/4 才算——更短也不会更难。"""
        extreme = self._chain_with_timestamps([1, 2, 3])                # 实际 3 秒
        boundary = self._chain_with_timestamps([33, 66, 100])           # 实际恰为 100 秒
        self.assertEqual(extreme.next_block_bits(), boundary.next_block_bits())

    def test_upper_clamp_engages(self):
        """实测时间跨度被压到 target_timespan*4 才算——更长也不会更松。"""
        extreme = self._chain_with_timestamps([10_000, 20_000, 30_000])  # 实际 3 万秒
        boundary = self._chain_with_timestamps([533, 1066, 1600])        # 实际恰为 1600 秒
        self.assertEqual(extreme.next_block_bits(), boundary.next_block_bits())

    def test_retargeted_block_is_accepted(self):
        """验证器算出的 bits 与挖矿者用的 bits 必须一致，否则谁也接不上。"""
        chain = self._chain_with_timestamps([1, 2, 3])
        expected = chain.next_block_bits()
        block = chain.build_and_mine([], MINER_SCRIPT, timestamp=chain.tip.header.timestamp + 1)
        self.assertEqual(block.header.bits, expected)
        self.assertEqual(chain.add_block(block).status, "connected")
        self.assertEqual(chain.height, 4)


class ReorgTests(unittest.TestCase):
    """累计工作量决定主链：短而高难度的分支可以击败长而低难度的分支。"""

    def _build_competing_branches(self):
        chain = Chain(REORG_PARAMS)
        base = chain.genesis.header.timestamp
        genesis = chain.genesis

        # 分支 A：长而「松」（时间戳拉得很开，难度停在 pow limit）
        a_blocks = [mine_onto(chain, timestamp=base + index * 1000)[0] for index in range(1, 5)]

        # 分支 B：短而「紧」（时间戳只隔 1 秒，触发 4 倍变难），从创世块分叉
        b1 = build_on(chain, genesis, [], MINER_SCRIPT, base + 1)
        first_result = chain.add_block(b1)
        b2 = build_on(chain, b1, [], MINER_SCRIPT, base + 2)
        return chain, genesis, a_blocks, [b1, b2], first_result

    def test_shorter_but_heavier_branch_wins(self):
        chain, _, a_blocks, b_blocks, first_result = self._build_competing_branches()

        # B1 单独加进来时工作量不够，只能当侧链
        self.assertEqual(first_result.status, "side_chain")
        self.assertFalse(chain.is_on_main_chain(b_blocks[0].block_hash()))
        self.assertIsNotNone(chain.get_block(b_blocks[0].block_hash()))

        self.assertEqual(chain.height, 4)
        self.assertEqual(chain.tip.block_hash(), a_blocks[-1].block_hash())
        work_before = chain.total_work
        # B2 的难度是 A 各块的 4 倍，所以「2 个块的累计工作量」反而更高
        expected_b_work = (chain.work_of(b_blocks[0].block_hash())
                          + block_work(b_blocks[1].header.bits))
        self.assertGreater(expected_b_work, work_before)

        result = chain.add_block(b_blocks[1])
        self.assertTrue(result.is_reorg)
        self.assertEqual(chain.height, 2)
        self.assertLess(chain.height, len(a_blocks))
        self.assertGreater(chain.total_work, work_before)
        self.assertEqual([chain.height_of(h) for h in result.disconnected], [4, 3, 2, 1])
        self.assertEqual(result.connected, [b_blocks[0].block_hash(), b_blocks[1].block_hash()])
        self.assertEqual(chain.tip_hash, b_blocks[1].block_hash())

    def test_reorg_updates_utxo_and_index(self):
        chain, _, a_blocks, b_blocks, _ = self._build_competing_branches()
        chain.add_block(b_blocks[1])

        for block in a_blocks:
            self.assertFalse(chain.is_on_main_chain(block.block_hash()))
            self.assertIsNotNone(chain.get_block(block.block_hash()))    # 侧链块仍被保留
            self.assertEqual(chain.confirmations(block.transactions[0].txid()), 0)
        for block in b_blocks:
            height = chain.height_of(block.block_hash())
            self.assertTrue(chain.is_on_main_chain(block.block_hash()))
            self.assertEqual(chain.confirmations(block.transactions[0].txid()),
                             chain.height - height + 1)
        self.assertEqual(chain.reorg_count, 1)

    def test_utxo_matches_full_replay_after_reorg(self):
        chain, _, _, b_blocks, _ = self._build_competing_branches()
        chain.add_block(b_blocks[1])
        self.assertEqual(chain.utxo, chain.replay_utxo_set())
        self.assertEqual(set(chain.utxo), set(chain.replay_utxo_set()))

    def test_washed_out_coinbases_leave_the_utxo_set(self):
        chain, _, a_blocks, b_blocks, _ = self._build_competing_branches()
        chain.add_block(b_blocks[1])
        for block in a_blocks:
            txid = block.transactions[0].txid()
            self.assertNotIn((txid, 0), chain.utxo)
            self.assertIsNone(chain.get_transaction(txid))

    def test_extension_never_triggers_reorg(self):
        chain = Chain(REORG_PARAMS)
        _, result = mine_onto(chain)
        self.assertEqual(result.status, "connected")
        self.assertEqual(result.disconnected, [])
        self.assertEqual(chain.reorg_count, 0)


class DisplacedTransactionTests(unittest.TestCase):
    """被挤出主链的非 coinbase 交易必须交还给调用方（交给交易池）。"""

    def test_reorg_returns_displaced_transaction(self):
        chain = Chain(SPEND_PARAMS)
        genesis = chain.genesis
        funding, _ = mine_onto(chain)
        payment = spend_coinbase(chain, funding.transactions[0].txid(), OTHER_SCRIPT, 1000, 100)
        mine_onto(chain, [payment])                      # A2 携带 payment
        self.assertIn((payment.txid(), 0), chain.utxo)

        results = build_fork(chain, genesis, 3)
        reorg = next(result for result in results if result.is_reorg)
        self.assertEqual([tx.txid() for tx in reorg.reaccepted], [payment.txid()])
        self.assertEqual(chain.confirmations(payment.txid()), 0)
        self.assertNotIn((payment.txid(), 0), chain.utxo)

    def test_reaccepted_excludes_coinbases(self):
        chain = Chain(SPEND_PARAMS)
        genesis = chain.genesis
        mine_onto(chain)
        results = build_fork(chain, genesis, 3)
        reorg = next(result for result in results if result.is_reorg)
        self.assertTrue(all(not tx.is_coinbase() for tx in reorg.reaccepted))
        self.assertEqual(reorg.reaccepted, [])
        self.assertEqual(len(reorg.disconnected), 1)


class UtxoConsistencyTests(unittest.TestCase):
    def test_replay_matches_incremental_after_many_blocks(self):
        chain = Chain(SPEND_PARAMS)
        for _ in range(6):
            mine_onto(chain, [], OTHER_SCRIPT)
        self.assertEqual(chain.utxo, chain.replay_utxo_set())

    def test_replay_matches_incremental_with_spends(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        key = (funding.transactions[0].txid(), 0)
        tx = spend_coinbase(chain, key[0], OTHER_SCRIPT, 700, 25)
        mine_onto(chain, [tx])
        self.assertEqual(chain.utxo, chain.replay_utxo_set())
        self.assertNotIn(key, chain.replay_utxo_set())
        self.assertEqual(set(chain.utxo), set(chain.replay_utxo_set()))

    def test_op_return_outputs_never_enter_utxo(self):
        chain = Chain(SPEND_PARAMS)
        coinbase = coinbase_transaction(1, chain.subsidy(1), MINER_SCRIPT)
        coinbase.outputs.append(TxOut(0, op_return_script(b"notarised")))
        header = BlockHeader(1, chain.tip_hash, merkle_root([coinbase.txid()]),
                             chain.tip.header.timestamp + 600, chain.params.pow_limit_bits)
        chain.add_block(mine(Block(header, [coinbase])))
        self.assertTrue(chain.get_transaction(coinbase.txid()).data_carrier_outputs())
        for _, entry in chain.utxo.items():
            self.assertNotEqual(entry.tx_out.script_pubkey[:1], b"\x6a")


class PersistenceTests(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        chain = Chain(SPEND_PARAMS)
        funding, _ = mine_onto(chain)
        tx = spend_coinbase(chain, funding.transactions[0].txid(), OTHER_SCRIPT, 500, 50)
        mine_onto(chain, [tx])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            chain.save(path)
            restored = Chain.load(path)
        self.assertEqual(restored.height, chain.height)
        self.assertEqual(restored.tip_hash, chain.tip_hash)
        self.assertEqual(restored.total_work, chain.total_work)
        self.assertEqual(restored.utxo, chain.utxo)
        self.assertEqual(restored.params, chain.params)

    def test_saved_file_is_readable_json(self):
        chain = Chain(SPEND_PARAMS)
        mine_onto(chain)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            chain.save(path)
            text = path.read_text(encoding="utf-8")
        self.assertIn("nimbus-chain/1", text)
        self.assertIn("retarget_interval", text)


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(SPEND_PARAMS)
        self.block, _ = mine_onto(self.chain)

    def test_get_block_and_height(self):
        self.assertEqual(self.chain.block_at_height(0), self.chain.genesis)
        self.assertEqual(self.chain.block_at_height(1), self.block)
        self.assertIsNone(self.chain.block_at_height(99))
        self.assertEqual(self.chain.height_of(self.block.block_hash()), 1)

    def test_get_transaction_and_confirmations(self):
        coinbase = self.block.transactions[0]
        self.assertEqual(self.chain.get_transaction(coinbase.txid()), coinbase)
        self.assertEqual(self.chain.confirmations(coinbase.txid()), 1)
        self.assertEqual(self.chain.confirmations(b"\x00" * 32), 0)
        self.assertIsNone(self.chain.get_transaction(b"\x00" * 32))

    def test_spendable_utxos_respect_maturity(self):
        immature = Chain()
        block, _ = mine_onto(immature)
        script = block.transactions[0].outputs[0].script_pubkey
        self.assertEqual(len(immature.utxos_for_script(script)), 1)
        self.assertEqual(immature.spendable_utxos(script), [])
        mature_at = 1 + immature.params.coinbase_maturity
        self.assertEqual(len(immature.spendable_utxos(script, at_height=mature_at)), 1)

    def test_find_transactions_by_op_return(self):
        chain = Chain(SPEND_PARAMS)
        coinbase = coinbase_transaction(1, chain.subsidy(1), MINER_SCRIPT)
        coinbase.outputs.append(TxOut(0, op_return_script(b"proof-of-existence")))
        header = BlockHeader(1, chain.tip_hash, merkle_root([coinbase.txid()]),
                             chain.tip.header.timestamp + 600, chain.params.pow_limit_bits)
        chain.add_block(mine(Block(header, [coinbase])))
        found = chain.find_transactions_by_op_return(b"proof-of-existence")
        self.assertEqual([tx.txid() for tx in found], [coinbase.txid()])

    def test_stats_and_repr(self):
        stats = self.chain.stats()
        self.assertEqual(stats["height"], 1)
        self.assertEqual(stats["reorgs"], 0)
        self.assertIn("Chain(height=1", repr(self.chain))


if __name__ == "__main__":
    unittest.main()

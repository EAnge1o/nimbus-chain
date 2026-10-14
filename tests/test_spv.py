"""SPV 轻客户端测试：头链校验、难度独立重算、Merkle 存在性证明。"""

from __future__ import annotations

import unittest
from dataclasses import replace

from nimbus_chain.block import Block, bits_to_target, mine, target_to_bits
from nimbus_chain.chain import Chain, ChainParams
from nimbus_chain.crypto import hash256
from nimbus_chain.script import p2pkh_script
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.spv import SPVClient, SPVError
from nimbus_chain.wallet import Wallet

# retarget_interval 故意设得很小，好让测试真的走到难度重定目标那条分支
PARAMS = ChainParams(retarget_interval=4, target_block_time=100, coinbase_maturity=1)
MINER = PrivateKey(0xF00D)
MINER_SCRIPT = p2pkh_script(MINER.public_key().hash160())
NO_RETARGET = ChainParams(retarget_interval=1_000, coinbase_maturity=1)


def build_chain(spacing: int = 1, blocks: int = 5) -> Chain:
    """按固定时间间隔挖一条链（间隔 1 秒会触发 4 倍变难）。"""
    chain = Chain(PARAMS)
    base = chain.genesis.header.timestamp
    for index in range(1, blocks + 1):
        chain.add_block(chain.build_and_mine([], MINER_SCRIPT, timestamp=base + index * spacing))
    return chain


class HeaderChainTests(unittest.TestCase):
    def setUp(self):
        self.chain = build_chain()
        self.client = SPVClient(PARAMS)

    def test_starts_from_the_genesis_header(self):
        self.assertEqual(self.client.height, 0)
        self.assertEqual(self.client.tip_hash, self.chain.genesis_hash)
        self.assertEqual(len(self.client), 1)
        self.assertEqual(self.client.local_bytes(), 80)

    def test_sync_from_chain(self):
        added = self.client.sync_from_chain(self.chain)
        self.assertEqual(added, self.chain.height)
        self.assertEqual(self.client.height, self.chain.height)
        self.assertEqual(self.client.tip_hash, self.chain.tip_hash)

    def test_client_computes_difficulty_independently(self):
        """轻客户端不采信对端：每个高度的 bits 都自己算，且必须与全节点一致。"""
        self.client.sync_from_chain(self.chain)
        self.assertGreater(self.chain.height, PARAMS.retarget_interval)
        for height in range(1, self.chain.height + 2):
            block = self.chain.block_at_height(height - 1)
            if block is None:
                break
            expected = self.chain.expected_bits(block.block_hash(), height - 1)
            self.assertEqual(self.client.expected_bits_at(height), expected,
                             f"difficulty disagreement at height {height}")

    def test_retarget_actually_happened(self):
        """确认测试路径真的覆盖了难度变化，而不是一路 pow limit。"""
        bits = {block.header.bits for block in self.chain.main_blocks()}
        self.assertGreater(len(bits), 1)

    def test_add_header_returns_height(self):
        block = self.chain.block_at_height(1)
        self.assertEqual(self.client.add_header(block.header), 1)
        self.assertTrue(self.client.has_header(block.block_hash()))
        self.assertEqual(self.client.height_of(block.block_hash()), 1)

    def test_known_header_rejected(self):
        block = self.chain.block_at_height(1)
        self.client.add_header(block.header)
        valid, reason = self.client.check_header(block.header)
        self.assertFalse(valid)
        self.assertIn("already known", reason)
        with self.assertRaises(SPVError):
            self.client.add_header(block.header)

    def test_non_contiguous_header_rejected(self):
        block = self.chain.block_at_height(3)      # 跳过中间的头
        valid, reason = self.client.check_header(block.header)
        self.assertFalse(valid)
        self.assertIn("does not extend", reason)

    def test_wrong_prev_block_rejected(self):
        header = replace(self.chain.block_at_height(1).header, prev_block=b"\xCC" * 32)
        valid, reason = self.client.check_header(header)
        self.assertFalse(valid)
        self.assertIn("does not extend", reason)

    def test_bad_pow_rejected(self):
        header = replace(self.chain.block_at_height(1).header)
        target = header.target()
        while int.from_bytes(header.hash(), "big") <= target:
            header.nonce += 1
        valid, reason = self.client.check_header(header)
        self.assertFalse(valid)
        self.assertIn("proof of work", reason)

    def test_wrong_difficulty_rejected(self):
        header = replace(self.chain.block_at_height(1).header)
        header.bits = target_to_bits(bits_to_target(header.bits) // 2)
        mine(Block(header, []))
        valid, reason = self.client.check_header(header)
        self.assertFalse(valid)
        self.assertIn("unexpected difficulty", reason)

    def test_stale_timestamp_rejected(self):
        # 先让客户端追到链尖，才能构造一个「接得上但时间戳倒退」的头
        self.client.sync_from_chain(self.chain)
        block = self.chain.assemble_block(self.chain.tip_hash, self.chain.genesis.header.timestamp,
                                         [], MINER_SCRIPT)
        mine(block)
        valid, reason = self.client.check_header(block.header)
        self.assertFalse(valid)
        self.assertIn("median time past", reason)

    def test_sync_reports_added_count(self):
        headers = [block.header for block in self.chain.main_blocks()[1:]]
        self.assertEqual(self.client.sync(headers), len(headers))

    def test_expected_bits_out_of_range(self):
        for height in (0, -1, 5):
            with self.subTest(height=height):
                with self.assertRaises(SPVError):
                    self.client.expected_bits_at(height)

    def test_stats_and_repr(self):
        self.client.sync_from_chain(self.chain)
        stats = self.client.stats()
        self.assertEqual(stats["headers"], self.chain.height + 1)
        self.assertEqual(stats["local_bytes"], 80 * (self.chain.height + 1))
        self.assertIn("SPVClient(", repr(self.client))


class InclusionProofTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(NO_RETARGET)
        self.miner = Wallet(name="miner", keys=[MINER])
        self.alice = Wallet(name="alice", keys=[PrivateKey(0xA11CE)])
        self.bob = Wallet(name="bob", keys=[PrivateKey(0xB0B)])
        self.chain.add_block(self.chain.build_and_mine([], self.miner.first_script()))
        self.chain.add_block(self.chain.build_and_mine([], self.alice.first_script()))
        self.chain.add_block(self.chain.build_and_mine([], self.miner.first_script()))
        # 第 4 块里放两笔来自不同钱包的交易，制造非平凡的 Merkle 路径
        payments = [self.miner.send(self.chain, self.alice.address(), 100_000),
                    self.alice.send(self.chain, self.bob.address(), 200_000)]
        self.rich_block = self.chain.build_and_mine(payments, MINER_SCRIPT)
        self.assertEqual(self.chain.add_block(self.rich_block).status, "connected")
        self.client = SPVClient(self.chain.params)
        self.client.sync_from_chain(self.chain)

    def test_inclusion_verified_with_a_single_transaction_block(self):
        block = self.chain.block_at_height(1)
        tx = block.transactions[0]
        self.assertEqual(block.merkle_proof_for(0), [])       # 单叶区块路径为空
        self.assertTrue(self.client.verify_transaction_inclusion(tx.txid(), block.block_hash(), []))

    def test_inclusion_verified_for_every_transaction(self):
        for height in range(1, self.chain.height + 1):
            block = self.chain.block_at_height(height)
            for position, tx in enumerate(block.transactions):
                with self.subTest(height=height, position=position):
                    proof = block.merkle_proof_for(position)
                    self.assertTrue(
                        self.client.verify_transaction_inclusion(tx.txid(), block.block_hash(), proof))

    def test_multi_transaction_block_has_a_real_path(self):
        self.assertEqual(len(self.rich_block.transactions), 3)
        self.assertGreaterEqual(len(self.rich_block.merkle_proof_for(0)), 2)

    def test_tampered_proof_rejected(self):
        tx = self.rich_block.transactions[0]
        broken = [(hash256(sibling), direction)
                  for sibling, direction in self.rich_block.merkle_proof_for(0)]
        self.assertFalse(self.client.verify_transaction_inclusion(
            tx.txid(), self.rich_block.block_hash(), broken))

    def test_reordered_proof_direction_rejected(self):
        tx = self.rich_block.transactions[0]
        flipped = [(sibling, "left" if direction == "right" else "right")
                   for sibling, direction in self.rich_block.merkle_proof_for(0)]
        self.assertFalse(self.client.verify_transaction_inclusion(
            tx.txid(), self.rich_block.block_hash(), flipped))

    def test_txid_from_another_block_rejected(self):
        """拿着 A 区块的路径去证明 B 区块里的交易，必须失败。"""
        other = self.chain.block_at_height(1).transactions[0].txid()
        self.assertFalse(self.client.verify_transaction_inclusion(
            other, self.rich_block.block_hash(), self.rich_block.merkle_proof_for(0)))

    def test_forged_txid_rejected(self):
        forged = hash256(b"a transaction that was never mined")
        self.assertFalse(self.client.verify_transaction_inclusion(
            forged, self.rich_block.block_hash(), self.rich_block.merkle_proof_for(0)))

    def test_unknown_block_hash_raises(self):
        """证明必须挂到本地已校验过的区块头上，否则毫无意义。"""
        tx = self.rich_block.transactions[0]
        with self.assertRaises(SPVError) as context:
            self.client.verify_transaction_inclusion(
                tx.txid(), b"\xAB" * 32, self.rich_block.merkle_proof_for(0))
        self.assertIn("unknown block header", str(context.exception))

    def test_confirmations_counted_from_the_tip(self):
        self.assertEqual(self.client.confirmations(self.rich_block.block_hash()), 1)
        oldest = self.chain.block_at_height(1)
        self.assertEqual(self.client.confirmations(oldest.block_hash()), self.chain.height)
        self.assertEqual(self.client.confirmations(b"\x00" * 32), 0)

    def test_header_at_height_lookup(self):
        self.assertEqual(self.client.header_at_height(0), self.chain.genesis.header)
        self.assertEqual(self.client.header_at_height(1), self.chain.block_at_height(1).header)
        self.assertIsNone(self.client.header_at_height(99))

    def test_light_client_storage_is_tiny(self):
        """轻客户端只存区块头：整条链的本地开销是 80 字节 × 区块数。"""
        self.assertEqual(self.client.local_bytes(), 80 * (self.chain.height + 1))
        self.assertEqual(self.client.height, self.chain.height)


if __name__ == "__main__":
    unittest.main()

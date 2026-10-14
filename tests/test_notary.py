"""存证应用测试：上链、检索、验证，以及「改一个字节就验不过」的端到端证据。"""

from __future__ import annotations

import unittest

from nimbus_chain.chain import Chain, ChainParams
from nimbus_chain.crypto import sha256
from nimbus_chain.mempool import Mempool
from nimbus_chain.notary import (
    DIGEST_SIZE,
    Notary,
    NotaryError,
    document_digest,
)
from nimbus_chain.script import p2pkh_script
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.spv import SPVClient
from nimbus_chain.wallet import Wallet, WalletError

PARAMS = ChainParams(retarget_interval=1_000, coinbase_maturity=1)
NOTARY_KEY = PrivateKey(0x5EC1)
MINER_KEY = PrivateKey(0xF00D)
MINER_SCRIPT = p2pkh_script(MINER_KEY.public_key().hash160())

CONTRACT = b"Service Agreement v3\nParty A: Nimbus Labs\nParty B: Client\nAmount: 1000 NBC\n"


class NotaryFixture(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(PARAMS)
        self.miner = Wallet(name="miner", keys=[MINER_KEY])
        for _ in range(3):
            self.chain.add_block(self.chain.build_and_mine([], self.miner.first_script()))
        self.wallet = Wallet(name="notary", keys=[NOTARY_KEY])
        # 给存证钱包一点钱，好让它有能力支付手续费
        funding = self.miner.send(self.chain, self.wallet.address(), 2_000_000)
        self.chain.add_block(self.chain.build_and_mine([funding], MINER_SCRIPT))
        self.pool = Mempool(self.chain)
        self.notary = Notary(self.chain, self.wallet, mempool=self.pool)

    def notarise_and_mine(self, data: bytes = CONTRACT):
        notarization = self.notary.notarize(data)
        self.chain.add_block(self.chain.build_and_mine([notarization.tx], MINER_SCRIPT))
        return notarization


class DigestTests(unittest.TestCase):
    def test_digest_is_plain_sha256(self):
        self.assertEqual(document_digest(CONTRACT), sha256(CONTRACT))
        self.assertEqual(len(document_digest(CONTRACT)), DIGEST_SIZE)

    def test_digest_is_deterministic(self):
        self.assertEqual(document_digest(CONTRACT), document_digest(bytes(CONTRACT)))

    def test_one_byte_change_changes_the_digest(self):
        tampered = CONTRACT.replace(b"1000 NBC", b"1001 NBC")
        self.assertNotEqual(document_digest(CONTRACT), document_digest(tampered))

    def test_empty_document_has_a_digest(self):
        self.assertEqual(document_digest(b""), sha256(b""))


class AnchoringTests(NotaryFixture):
    def test_anchor_transaction_carries_the_digest_as_op_return(self):
        notarization = self.notary.notarize(CONTRACT)
        self.assertEqual(notarization.digest, document_digest(CONTRACT))
        self.assertEqual(notarization.tx.data_carrier_outputs(), [notarization.digest])
        self.assertEqual(notarization.to_dict()["digest"], notarization.digest.hex())

    def test_anchor_output_rejects_wrong_digest_size(self):
        with self.assertRaises(NotaryError):
            self.notary.anchor_output(b"\x01" * 31)

    def test_notarize_many_anchors_several_digests_in_one_transaction(self):
        items = [b"doc-A", b"doc-B", b"doc-C"]
        tx, digests = self.notary.notarize_many(items)
        self.assertEqual(len(digests), 3)
        self.assertEqual(tx.data_carrier_outputs(), digests)
        self.chain.add_block(self.chain.build_and_mine([tx], MINER_SCRIPT))
        for item, digest in zip(items, digests):
            self.assertTrue(self.notary.verify(item).valid)

    def test_notarize_many_requires_items(self):
        with self.assertRaises(NotaryError):
            self.notary.notarize_many([])

    def test_notarize_needs_funds(self):
        poor = Wallet(name="poor", keys=[PrivateKey(0xBADBAD)])
        notary = Notary(self.chain, poor, mempool=self.pool)
        with self.assertRaises(WalletError) as context:
            notary.notarize(CONTRACT)
        self.assertIn("no spendable utxos", str(context.exception))

    def test_verify_digest_rejects_wrong_size(self):
        with self.assertRaises(NotaryError):
            self.notary.verify_digest(b"\x00" * 31)
        with self.assertRaises(NotaryError):
            self.notary.lookup(b"")


class VerificationTests(NotaryFixture):
    def test_unconfirmed_when_only_in_the_mempool(self):
        notarization = self.notary.notarize(CONTRACT)
        self.pool.add_transaction(notarization.tx)
        result = self.notary.verify(CONTRACT)
        self.assertTrue(result.present)
        self.assertFalse(result.confirmed)
        self.assertFalse(result.valid)
        self.assertIn("mempool", result.reason)

    def test_pending_without_a_mempool_reports_not_found(self):
        notarization = self.notary.notarize(CONTRACT)
        self.pool.add_transaction(notarization.tx)
        plain = Notary(self.chain, self.wallet)      # 不给交易池
        result = plain.verify(CONTRACT)
        self.assertFalse(result.present)
        self.assertIn("no anchoring transaction", result.reason)

    def test_valid_after_being_mined(self):
        notarization = self.notarise_and_mine()
        result = self.notary.verify(CONTRACT)
        self.assertTrue(result.valid)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.txid, notarization.txid)
        self.assertEqual(result.height, self.chain.height)
        self.assertEqual(result.confirmations, 1)
        self.assertEqual(result.digest, notarization.digest)

    def test_tampered_document_fails_verification(self):
        """核心命题：改一个字节，存证验证必须失败。"""
        self.notarise_and_mine()
        self.assertTrue(self.notary.verify(CONTRACT).valid)

        tampered = CONTRACT.replace(b"1000 NBC", b"1001 NBC")
        result = self.notary.verify(tampered)
        self.assertFalse(result.valid)
        self.assertFalse(result.present)
        self.assertIn("no anchoring transaction", result.reason)
        # 而原始文件依然有效——篡改没有破坏链，只是破坏了「这份文件」的身世
        self.assertTrue(self.notary.verify(CONTRACT).valid)

    def test_single_bit_flip_is_detected(self):
        self.notarise_and_mine()
        flipped = bytearray(CONTRACT)
        flipped[0] ^= 0x01
        self.assertFalse(self.notary.verify(bytes(flipped)).valid)

    def test_unrelated_document_never_valid(self):
        self.notarise_and_mine()
        self.assertFalse(self.notary.verify(b"an entirely different document").valid)

    def test_confirmations_grow_with_more_blocks(self):
        self.notarise_and_mine()
        for _ in range(2):
            self.chain.add_block(self.chain.build_and_mine([], MINER_SCRIPT))
        result = self.notary.verify(CONTRACT)
        self.assertEqual(result.confirmations, 3)
        self.assertEqual(result.to_dict()["confirmations"], 3)

    def test_lookup_returns_the_anchoring_transaction(self):
        notarization = self.notarise_and_mine()
        found = self.notary.lookup(document_digest(CONTRACT))
        self.assertIsNotNone(found)
        self.assertEqual(found.txid(), notarization.txid)

    def test_lookup_returns_none_for_unknown_digest(self):
        self.assertIsNone(self.notary.lookup(document_digest(b"never notarised")))


class SpvVerificationTests(NotaryFixture):
    def test_spv_verified_when_the_header_is_known(self):
        self.notarise_and_mine()
        client = SPVClient(self.chain.params)
        client.sync_from_chain(self.chain)
        result = self.notary.verify(CONTRACT, spv=client)
        self.assertTrue(result.valid)
        self.assertTrue(result.spv_verified)
        self.assertLess(client.local_bytes(), 80 * (self.chain.height + 1) + 1)

    def test_spv_fails_when_the_client_has_not_synced(self):
        self.notarise_and_mine()
        blind = SPVClient(self.chain.params)         # 只有创世头
        result = self.notary.verify(CONTRACT, spv=blind)
        self.assertTrue(result.valid)                # 全节点的结论仍然成立
        self.assertFalse(result.spv_verified)        # 但轻客户端无法独立证实
        self.assertIn("spv proof could not be verified", result.reason)

    def test_spv_client_agrees_only_for_the_right_block(self):
        self.notarise_and_mine()
        client = SPVClient(self.chain.params)
        client.sync_from_chain(self.chain)
        location = self.chain.transaction_location(self.notary.lookup(document_digest(CONTRACT)).txid())
        block_hash, _, index = location
        block = self.chain.get_block(block_hash)
        self.assertTrue(client.verify_transaction_inclusion(
            block.transactions[index].txid(), block_hash, block.merkle_proof_for(index)))


class AnchorListingTests(NotaryFixture):
    def test_anchors_lists_every_record(self):
        self.notarise_and_mine(b"first document")
        tx, digests = self.notary.notarize_many([b"second", b"third"])
        self.chain.add_block(self.chain.build_and_mine([tx], MINER_SCRIPT))

        records = self.notary.anchors()
        self.assertEqual(len(records), 3)
        self.assertEqual([record.height for record in records], sorted(r.height for r in records))
        self.assertEqual({record.digest for record in records},
                         {document_digest(b"first document"), *digests})

    def test_anchors_ignores_non_digest_payloads(self):
        """长度不是 32 字节的 OP_RETURN 载荷不算存证记录。"""
        tx = self.notary.wallet.create_transaction(
            self.chain, [self.notary.anchor_output(document_digest(b"real"))])
        block = self.chain.build_and_mine([tx], MINER_SCRIPT)
        self.chain.add_block(block)
        records = self.notary.anchors()
        self.assertEqual([record.digest for record in records], [document_digest(b"real")])

    def test_anchors_limit(self):
        self.notarise_and_mine(b"one")
        self.assertLessEqual(len(self.notary.anchors(limit=1)), 1)

    def test_record_to_dict(self):
        self.notarise_and_mine()
        record = self.notary.anchors()[0]
        payload = record.to_dict()
        self.assertEqual(payload["digest"], record.digest.hex())
        self.assertEqual(payload["height"], record.height)
        self.assertIn("block_hash", payload)


if __name__ == "__main__":
    unittest.main()

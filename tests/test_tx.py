"""交易测试：序列化、txid、sighash、coinbase、减半、结构性校验。"""

from __future__ import annotations

import unittest

from nimbus_chain.crypto import hash256
from nimbus_chain.script import op_return_script, p2pkh_script
from nimbus_chain.tx import (
    COIN,
    INITIAL_SUBSIDY,
    MAX_MONEY,
    SIGHASH_ALL,
    Transaction,
    TxIn,
    TxValidationError,
    TxOut,
    block_subsidy,
    coinbase_transaction,
    read_varint,
    write_varint,
)

PUBKEY_HASH = b"\x42" * 20
SCRIPT = p2pkh_script(PUBKEY_HASH)


def _sample_transaction() -> Transaction:
    return Transaction(
        1,
        [TxIn(b"\xab" * 32, 3, b"\x01\x02\x03", 0xFFFFFFFE), TxIn(b"\xcd" * 32, 0, b"", 0xFFFFFFFF)],
        [TxOut(5000, SCRIPT), TxOut(2500, op_return_script(b"nimbus-chain"))],
        500,
    )


class VarintTests(unittest.TestCase):
    def test_roundtrip(self):
        for value in (0, 1, 0xFC, 0xFD, 0xFF, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000):
            with self.subTest(value=value):
                encoded = write_varint(value)
                decoded, offset = read_varint(encoded, 0)
                self.assertEqual(decoded, value)
                self.assertEqual(offset, len(encoded))

    def test_prefixes(self):
        self.assertEqual(write_varint(0xFC), b"\xfc")
        self.assertEqual(write_varint(0xFD), b"\xfd\xfd\x00")
        self.assertEqual(write_varint(0x10000)[0], 0xFE)

    def test_truncated_rejected(self):
        with self.assertRaises(TxValidationError):
            read_varint(b"\xfd\x01", 0)
        with self.assertRaises(TxValidationError):
            read_varint(b"", 0)

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            write_varint(-1)


class SerializationTests(unittest.TestCase):
    def test_roundtrip(self):
        original = _sample_transaction()
        restored = Transaction.deserialize(original.serialize())
        self.assertEqual(restored, original)
        self.assertEqual(restored.to_hex(), original.to_hex())

    def test_hex_roundtrip(self):
        original = _sample_transaction()
        self.assertEqual(Transaction.from_hex(original.to_hex()), original)

    def test_trailing_bytes_rejected(self):
        with self.assertRaises(TxValidationError):
            Transaction.deserialize(_sample_transaction().serialize() + b"\x00")

    def test_txid_is_double_sha256_of_serialization(self):
        tx = _sample_transaction()
        self.assertEqual(tx.txid(), hash256(tx.serialize()))
        self.assertEqual(tx.txid_hex(), tx.txid()[::-1].hex())

    def test_txid_changes_with_output_value(self):
        tx = _sample_transaction()
        before = tx.txid()
        tx.outputs[0] = TxOut(5001, SCRIPT)
        self.assertNotEqual(tx.txid(), before)

    def test_input_and_output_serialization_roundtrip(self):
        tx_in = TxIn(b"\x99" * 32, 7, b"\x51\x52", 12)
        self.assertEqual(TxIn.deserialize(tx_in.serialize(), 0), (tx_in, len(tx_in.serialize())))
        tx_out = TxOut(1234, SCRIPT)
        self.assertEqual(TxOut.deserialize(tx_out.serialize(), 0), (tx_out, len(tx_out.serialize())))

    def test_bad_prev_txid_length(self):
        with self.assertRaises(TxValidationError):
            TxIn(b"\x00" * 31, 0)

    def test_output_value_out_of_range(self):
        with self.assertRaises(TxValidationError):
            TxOut(MAX_MONEY + 1, SCRIPT)
        with self.assertRaises(TxValidationError):
            TxOut(-1, SCRIPT)


class SighashTests(unittest.TestCase):
    def test_deterministic(self):
        tx = _sample_transaction()
        self.assertEqual(tx.sighash(0, SCRIPT), tx.sighash(0, SCRIPT))
        self.assertEqual(len(tx.sighash(0, SCRIPT)), 32)

    def test_other_inputs_scripts_are_blanked(self):
        """改一个**别的**输入的 scriptSig 不能影响当前输入的 sighash。"""
        tx = _sample_transaction()
        original = tx.sighash(0, SCRIPT)
        tx.inputs[1].script_sig = b"\xde\xad\xbe\xef"
        self.assertEqual(tx.sighash(0, SCRIPT), original)

    def test_hash_type_changes_digest(self):
        tx = _sample_transaction()
        self.assertNotEqual(tx.sighash(0, SCRIPT, SIGHASH_ALL),
                            hash256(tx.serialize()))

    def test_unsupported_hash_type(self):
        tx = _sample_transaction()
        for hash_type in (0, 2, 3, 0x81):
            with self.subTest(hash_type=hash_type):
                with self.assertRaises(TxValidationError):
                    tx.sighash(0, SCRIPT, hash_type)

    def test_index_out_of_range(self):
        tx = _sample_transaction()
        with self.assertRaises(TxValidationError):
            tx.sighash(5, SCRIPT)


class CoinbaseAndSubsidyTests(unittest.TestCase):
    def test_subsidy_halving(self):
        self.assertEqual(block_subsidy(0), INITIAL_SUBSIDY)
        self.assertEqual(block_subsidy(209_999), INITIAL_SUBSIDY)
        self.assertEqual(block_subsidy(210_000), INITIAL_SUBSIDY // 2)
        self.assertEqual(block_subsidy(420_000), INITIAL_SUBSIDY // 4)
        self.assertEqual(block_subsidy(210_000 * 63), INITIAL_SUBSIDY >> 63)
        self.assertEqual(block_subsidy(210_000 * 64), 0)

    def test_subsidy_negative_height(self):
        with self.assertRaises(ValueError):
            block_subsidy(-1)

    def test_coinbase_shape(self):
        tx = coinbase_transaction(42, block_subsidy(42), SCRIPT, extra_nonce=b"\x00" * 8)
        self.assertTrue(tx.is_coinbase())
        self.assertEqual(tx.inputs[0].prev_txid, b"\x00" * 32)
        self.assertEqual(tx.inputs[0].prev_index, 0xFFFFFFFF)
        self.assertEqual(len(tx.inputs), 1)

    def test_coinbase_height_is_bip34_encoded(self):
        tx = coinbase_transaction(300, 100, SCRIPT)
        # 300 需要两个字节：0x2c 0x01（小端最小化）
        self.assertTrue(tx.inputs[0].script_sig.startswith(b"\x02\x2c\x01"))

    def test_coinbase_script_sig_length_validated(self):
        tx = coinbase_transaction(1, 100, SCRIPT, extra_nonce=b"x" * 200)
        with self.assertRaises(TxValidationError):
            tx.validate_structure()

    def test_subsidy_as_output_value(self):
        tx = coinbase_transaction(1, block_subsidy(1), SCRIPT)
        tx.validate_structure()


class StructureValidationTests(unittest.TestCase):
    def test_valid_sample_passes(self):
        _sample_transaction().validate_structure()

    def test_no_inputs(self):
        with self.assertRaises(TxValidationError):
            Transaction(1, [], [TxOut(1, SCRIPT)]).validate_structure()

    def test_no_outputs(self):
        with self.assertRaises(TxValidationError):
            Transaction(1, [TxIn(b"\x01" * 32, 0)], []).validate_structure()

    def test_duplicate_input_spends_same_outpoint(self):
        tx = Transaction(1, [TxIn(b"\x01" * 32, 0), TxIn(b"\x01" * 32, 0)], [TxOut(1, SCRIPT)])
        with self.assertRaises(TxValidationError):
            tx.validate_structure()

    def test_total_output_over_max_money(self):
        tx = Transaction(1, [TxIn(b"\x01" * 32, 0)],
                         [TxOut(MAX_MONEY, SCRIPT), TxOut(MAX_MONEY, SCRIPT)])
        with self.assertRaises(TxValidationError):
            tx.validate_structure()

    def test_coinbase_input_in_normal_transaction(self):
        tx = Transaction(1, [TxIn(b"\x00" * 32, 0xFFFFFFFF, b"\x03abc"), TxIn(b"\x01" * 32, 0)],
                         [TxOut(1, SCRIPT)])
        with self.assertRaises(TxValidationError):
            tx.validate_structure()


class DataCarrierTests(unittest.TestCase):
    def test_collects_op_return_payloads(self):
        tx = Transaction(1, [TxIn(b"\x01" * 32, 0)], [
            TxOut(1000, SCRIPT),
            TxOut(0, op_return_script(b"hash:deadbeef")),
            TxOut(0, op_return_script(b"second")),
        ])
        self.assertEqual(tx.data_carrier_outputs(), [b"hash:deadbeef", b"second"])

    def test_op_return_output_is_not_spendable(self):
        tx = Transaction(1, [TxIn(b"\x01" * 32, 0)], [TxOut(0, op_return_script(b"x"))])
        self.assertFalse(tx.outputs[0].is_spendable())
        self.assertTrue(TxOut(1000, SCRIPT).is_spendable())

    def test_describe(self):
        text = coinbase_transaction(1, 50 * COIN, SCRIPT).describe()
        self.assertIn("coinbase", text)


if __name__ == "__main__":
    unittest.main()

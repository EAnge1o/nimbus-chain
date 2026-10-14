"""脚本解释器测试：数值编码、条件分支、标准脚本、验签、时间锁。"""

from __future__ import annotations

import hashlib
import unittest

from nimbus_chain.crypto import hash160
from nimbus_chain.script import (
    OP_0,
    OP_1,
    OP_1ADD,
    OP_2,
    OP_3,
    OP_5,
    OP_7,
    OP_8,
    OP_9,
    OP_ADD,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_HASH256,
    OP_IF,
    OP_RETURN,
    OP_SHA256,
    OP_SIZE,
    MAX_SCRIPT_SIZE,
    Checker,
    ScriptError,
    cast_to_bool,
    decode_num,
    encode_num,
    extract_op_return,
    is_multisig,
    is_op_return,
    is_p2pkh,
    is_p2sh,
    is_provably_unspendable,
    multisig_script,
    op_return_script,
    p2pkh_script,
    p2pkh_script_sig,
    p2sh_script,
    parse_script,
    run_script,
    serialize_script,
    verify_input,
)
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.tx import SIGHASH_ALL, Transaction, TxIn, TxOut, checker_for

PUBKEY_HASH = bytes(range(20))


def _nop_checker() -> Checker:
    """不含签名验证的执行上下文：sighash 返回全零摘要。"""
    return Checker(lambda script_code, hash_type: b"\x00" * 32)


class ScriptNumberTests(unittest.TestCase):
    def test_roundtrip(self):
        for value in (0, 1, -1, 127, -127, 128, -128, 255, -255, 300, -1000, 2 ** 31 - 1, -(2 ** 31) + 1):
            with self.subTest(value=value):
                self.assertEqual(decode_num(encode_num(value)), value)

    def test_minimal_encoding_lengths(self):
        self.assertEqual(encode_num(0), b"")
        self.assertEqual(encode_num(1), b"\x01")
        self.assertEqual(encode_num(-1), b"\x81")
        self.assertEqual(encode_num(127), b"\x7f")
        self.assertEqual(encode_num(128), b"\x80\x00")   # 0x80 单字节会被读成 -128
        self.assertEqual(encode_num(-128), b"\x80\x80")

    def test_non_minimal_rejected(self):
        with self.assertRaises(ScriptError):
            decode_num(b"\x01\x00")
        self.assertEqual(decode_num(b"\x01\x00", require_minimal=False), 1)

    def test_overflow_rejected(self):
        with self.assertRaises(ScriptError):
            decode_num(b"\x01" * 5)

    def test_cast_to_bool(self):
        self.assertFalse(cast_to_bool(b""))
        self.assertFalse(cast_to_bool(b"\x00"))
        self.assertFalse(cast_to_bool(b"\x80"))  # 负零也必须算假
        self.assertTrue(cast_to_bool(b"\x01"))
        self.assertTrue(cast_to_bool(b"\x00\x01"))


class ParseSerializeTests(unittest.TestCase):
    def test_roundtrip(self):
        for script in (
            b"",
            bytes([OP_0, OP_1, OP_2, OP_9, OP_EQUAL]),
            p2pkh_script(PUBKEY_HASH),
            p2sh_script(hash160(b"redeem")),
            op_return_script(b"nimbus" * 10),
            serialize_script([b"\xff" * 80]),        # 触发 OP_PUSHDATA1
            serialize_script([b"\xaa" * 300]),       # 触发 OP_PUSHDATA2
        ):
            with self.subTest(script=script[:8]):
                self.assertEqual(serialize_script(parse_script(script)), script)

    def test_empty_push_parses_to_empty_bytes(self):
        self.assertEqual(parse_script(bytes([OP_0])), [b""])

    def test_truncated_push_rejected(self):
        with self.assertRaises(ScriptError):
            parse_script(b"\x05ab")

    def test_oversized_script_rejected(self):
        with self.assertRaises(ScriptError):
            parse_script(b"\x00" * (MAX_SCRIPT_SIZE + 1))


class ClassificationTests(unittest.TestCase):
    def test_p2pkh(self):
        self.assertTrue(is_p2pkh(p2pkh_script(PUBKEY_HASH)))
        self.assertFalse(is_p2pkh(p2pkh_script(bytes(20))[:-1]))

    def test_p2sh(self):
        self.assertTrue(is_p2sh(p2sh_script(PUBKEY_HASH)))
        self.assertFalse(is_p2sh(p2pkh_script(PUBKEY_HASH)))

    def test_op_return(self):
        script = op_return_script(b"hello notary")
        self.assertTrue(is_op_return(script))
        self.assertTrue(is_provably_unspendable(script))
        self.assertEqual(extract_op_return(script), b"hello notary")
        self.assertIsNone(extract_op_return(p2pkh_script(PUBKEY_HASH)))

    def test_multisig(self):
        keys = [PrivateKey(index).public_key().to_bytes() for index in (1, 2, 3)]
        self.assertTrue(is_multisig(multisig_script(2, keys)))
        self.assertFalse(is_multisig(multisig_script(2, keys)[:-1]))
        self.assertFalse(is_multisig(p2pkh_script(PUBKEY_HASH)))


class OpcodeTests(unittest.TestCase):
    def _eval(self, script: bytes) -> list[bytes]:
        stack: list[bytes] = []
        run_script(script, stack, _nop_checker())
        return stack

    def test_arithmetic(self):
        self.assertEqual(self._eval(bytes([OP_2, OP_3, OP_ADD, OP_5, OP_EQUAL]))[-1], b"\x01")

    def test_comparison_and_hash(self):
        self.assertEqual(self._eval(b"\x02\xab\xcd" + bytes([OP_SIZE]))[-1], b"\x02")
        self.assertEqual(
            self._eval(b"\x03abc" + bytes([OP_SHA256]) + b"\x20" + hashlib.sha256(b"abc").digest()
                       + bytes([OP_EQUAL]))[-1],
            b"\x01",
        )

    def test_verifiable_hash256(self):
        expected = hashlib.sha256(hashlib.sha256(b"nimbus").digest()).digest()
        self.assertEqual(self._eval(b"\x06nimbus" + bytes([OP_HASH256]) + b"\x20" + expected + bytes([OP_EQUAL]))[-1], b"\x01")

    def test_conditional_takes_then_branch(self):
        script = bytes([OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_2, OP_EQUAL])
        self.assertEqual(self._eval(script)[-1], b"\x01")

    def test_conditional_takes_else_branch(self):
        script = bytes([OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_2, OP_EQUAL])
        self.assertEqual(self._eval(script)[-1], b"")

    def test_nested_if_inside_unexecuted_branch_does_not_pop(self):
        """未生效分支里的 IF 不能弹栈——否则栈会直接下溢。"""
        script = bytes([
            OP_0, OP_IF,
            OP_1, OP_IF, OP_9, OP_ELSE, OP_8, OP_ENDIF,
            OP_ELSE,
            OP_7,
            OP_ENDIF,
            OP_7, OP_EQUAL,
        ])
        self.assertEqual(self._eval(script)[-1], b"\x01")

    def test_unbalanced_endif_rejected(self):
        with self.assertRaises(ScriptError):
            self._eval(bytes([OP_IF, OP_1]))

    def test_stack_underflow_rejected(self):
        with self.assertRaises(ScriptError):
            self._eval(bytes([OP_1ADD]))

    def test_op_return_aborts_execution(self):
        with self.assertRaises(ScriptError):
            self._eval(bytes([OP_1, OP_RETURN]))

    def test_verify_consumes_top(self):
        stack: list[bytes] = []
        run_script(bytes([OP_1, OP_1, OP_EQUAL + 1]), stack, _nop_checker())  # OP_EQUALVERIFY
        self.assertEqual(stack, [])

    def test_unsupported_opcode(self):
        with self.assertRaises(ScriptError):
            self._eval(bytes([0xC0]))


class TimelockTests(unittest.TestCase):
    def test_cltv_satisfied(self):
        script = serialize_script([encode_num(500), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1])
        stack: list[bytes] = []
        run_script(script, stack, Checker(lambda s, h: b"\x00" * 32, locktime=600))
        self.assertEqual(stack[-1], b"\x01")

    def test_cltv_unsatisfied(self):
        script = serialize_script([encode_num(500), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1])
        with self.assertRaises(ScriptError):
            run_script(script, [], Checker(lambda s, h: b"\x00" * 32, locktime=400))

    def test_cltv_type_mismatch(self):
        """高度锁（< 5e8）与时间戳锁（>= 5e8）不能混用。"""
        script = serialize_script([encode_num(500), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1])
        with self.assertRaises(ScriptError):
            run_script(script, [], Checker(lambda s, h: b"\x00" * 32, locktime=1_700_000_000))

    def test_cltv_negative_rejected(self):
        script = serialize_script([encode_num(-5), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1])
        with self.assertRaises(ScriptError):
            run_script(script, [], Checker(lambda s, h: b"\x00" * 32, locktime=600))

    def test_csv_satisfied(self):
        script = serialize_script([encode_num(10), OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1])
        stack: list[bytes] = []
        run_script(script, stack, Checker(lambda s, h: b"\x00" * 32, sequence=12))
        self.assertEqual(stack[-1], b"\x01")

    def test_csv_unsatisfied(self):
        script = serialize_script([encode_num(10), OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1])
        with self.assertRaises(ScriptError):
            run_script(script, [], Checker(lambda s, h: b"\x00" * 32, sequence=5))

    def test_csv_disable_flag_short_circuits(self):
        script = serialize_script([encode_num(1 << 31), OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1])
        stack: list[bytes] = []
        run_script(script, stack, Checker(lambda s, h: b"\x00" * 32, sequence=0))
        self.assertEqual(stack[-1], b"\x01")


class P2PKHTests(unittest.TestCase):
    def _spend(self, secret: int = 0xA11CE, *, sign_secret: int | None = None,
               tamper: bool = False):
        key = PrivateKey(secret)
        pubkey = key.public_key().to_bytes()
        prev_script = p2pkh_script(hash160(pubkey))

        funding = Transaction(1, [TxIn(b"\x11" * 32, 0, b"\x00")], [TxOut(1000, prev_script)])
        spend = Transaction(1, [TxIn(funding.txid(), 0, b"")], [TxOut(900, p2pkh_script(hash160(b"dest")))])
        digest = spend.sighash(0, prev_script, SIGHASH_ALL)
        signer = PrivateKey(sign_secret) if sign_secret is not None else key
        signature = signer.sign(digest).to_der() + bytes([SIGHASH_ALL])
        if tamper:
            signature = signature[:-2] + bytes([signature[-2] ^ 0x01, SIGHASH_ALL])
        spend.inputs[0].script_sig = p2pkh_script_sig(signature, pubkey)
        return spend, prev_script

    def test_valid_p2pkh_spend(self):
        spend, prev_script = self._spend()
        self.assertTrue(verify_input(spend.inputs[0].script_sig, prev_script, checker_for(spend, 0)))

    def test_wrong_key_signature_rejected(self):
        spend, prev_script = self._spend(sign_secret=0xD1FF)
        self.assertFalse(verify_input(spend.inputs[0].script_sig, prev_script, checker_for(spend, 0)))

    def test_tampered_signature_rejected(self):
        spend, prev_script = self._spend(tamper=True)
        self.assertFalse(verify_input(spend.inputs[0].script_sig, prev_script, checker_for(spend, 0)))

    def test_wrong_pubkey_hash_rejected(self):
        """把 prev_script 换成别人的公钥哈希 => HASH160 不匹配。"""
        spend, _ = self._spend()
        other_key = PrivateKey(0xB0B).public_key().to_bytes()
        self.assertFalse(verify_input(
            spend.inputs[0].script_sig, p2pkh_script(hash160(other_key)), checker_for(spend, 0)))

    def test_signing_different_amount_fails(self):
        """签名承诺了整笔交易：改金额后旧签名必须失效。"""
        spend, prev_script = self._spend()
        self.assertTrue(verify_input(spend.inputs[0].script_sig, prev_script, checker_for(spend, 0)))
        spend.outputs[0] = TxOut(999, p2pkh_script(hash160(b"dest")))
        self.assertFalse(verify_input(spend.inputs[0].script_sig, prev_script, checker_for(spend, 0)))

    def test_op_return_output_unspendable(self):
        self.assertFalse(verify_input(b"", op_return_script(b"data"), _nop_checker()))


class MultisigAndP2SHTests(unittest.TestCase):
    def _setup(self, threshold: int = 2):
        keys = [PrivateKey(seed) for seed in (11, 22, 33)]
        pubkeys = [key.public_key().to_bytes() for key in keys]
        redeem = multisig_script(threshold, pubkeys)
        return keys, pubkeys, redeem

    def test_multisig_script_pubkey_spend(self):
        keys, pubkeys, redeem = self._setup(2)
        spend = Transaction(1, [TxIn(b"\x22" * 32, 0, b"")], [TxOut(900, p2pkh_script(PUBKEY_HASH))])
        digest = spend.sighash(0, redeem, SIGHASH_ALL)
        signatures = [key.sign(digest).to_der() + bytes([SIGHASH_ALL]) for key in (keys[0], keys[2])]
        spend.inputs[0].script_sig = serialize_script([b"", *signatures])
        self.assertTrue(verify_input(spend.inputs[0].script_sig, redeem, checker_for(spend, 0)))

    def test_multisig_below_threshold_rejected(self):
        keys, pubkeys, redeem = self._setup(2)
        spend = Transaction(1, [TxIn(b"\x22" * 32, 0, b"")], [TxOut(900, p2pkh_script(PUBKEY_HASH))])
        digest = spend.sighash(0, redeem, SIGHASH_ALL)
        signature = keys[0].sign(digest).to_der() + bytes([SIGHASH_ALL])
        spend.inputs[0].script_sig = serialize_script([b"", signature])
        self.assertFalse(verify_input(spend.inputs[0].script_sig, redeem, checker_for(spend, 0)))

    def test_multisig_out_of_order_signatures_rejected(self):
        keys, pubkeys, redeem = self._setup(2)
        spend = Transaction(1, [TxIn(b"\x22" * 32, 0, b"")], [TxOut(900, p2pkh_script(PUBKEY_HASH))])
        digest = spend.sighash(0, redeem, SIGHASH_ALL)
        # 顺序必须与公钥顺序一致：先 3 后 1 会失败
        signatures = [key.sign(digest).to_der() + bytes([SIGHASH_ALL]) for key in (keys[2], keys[0])]
        spend.inputs[0].script_sig = serialize_script([b"", *signatures])
        self.assertFalse(verify_input(spend.inputs[0].script_sig, redeem, checker_for(spend, 0)))

    def test_p2sh_multisig_spend(self):
        keys, pubkeys, redeem = self._setup(2)
        script_pubkey = p2sh_script(hash160(redeem))
        self.assertTrue(is_p2sh(script_pubkey))
        spend = Transaction(1, [TxIn(b"\x33" * 32, 0, b"")], [TxOut(900, p2pkh_script(PUBKEY_HASH))])
        digest = spend.sighash(0, redeem, SIGHASH_ALL)
        signatures = [key.sign(digest).to_der() + bytes([SIGHASH_ALL]) for key in (keys[1], keys[2])]
        spend.inputs[0].script_sig = serialize_script([b"", *signatures, redeem])
        self.assertTrue(verify_input(spend.inputs[0].script_sig, script_pubkey, checker_for(spend, 0)))

    def test_p2sh_wrong_redeem_script_rejected(self):
        keys, pubkeys, redeem = self._setup(2)
        script_pubkey = p2sh_script(hash160(redeem))
        spend = Transaction(1, [TxIn(b"\x33" * 32, 0, b"")], [TxOut(900, p2pkh_script(PUBKEY_HASH))])
        digest = spend.sighash(0, redeem, SIGHASH_ALL)
        signatures = [key.sign(digest).to_der() + bytes([SIGHASH_ALL]) for key in (keys[1], keys[2])]
        attacker_redeem = multisig_script(2, pubkeys[:2])
        spend.inputs[0].script_sig = serialize_script([b"", *signatures, attacker_redeem])
        self.assertFalse(verify_input(spend.inputs[0].script_sig, script_pubkey, checker_for(spend, 0)))

    def test_p2pkh_changing_scriptcode_changes_sighash(self):
        """sighash 必须把 scriptCode 计入——否则签名可以被跨脚本重放。"""
        tx = Transaction(1, [TxIn(b"\x44" * 32, 0, b"")], [TxOut(900, p2pkh_script(PUBKEY_HASH))])
        self.assertNotEqual(tx.sighash(0, b"\x51"), tx.sighash(0, bytes([OP_CHECKSIG])))


if __name__ == "__main__":
    unittest.main()

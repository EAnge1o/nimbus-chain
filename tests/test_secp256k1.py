"""secp256k1 测试：点运算、群律、RFC 6979、ECDSA、DER、low-S、地址。"""

from __future__ import annotations

import hashlib
import unittest

from nimbus_chain.crypto import b58check_decode, hash160
from nimbus_chain.secp256k1 import (
    GX,
    GY,
    N,
    P,
    DERError,
    Point,
    PrivateKey,
    PublicKey,
    Signature,
    add,
    der_decode,
    der_encode,
    double,
    is_low_s,
    normalize_s,
    rfc6979_nonce,
    scalar_mult,
    sign,
    verify,
)

# 广为引用的 secp256k1 小标量倍点
TWO_G = (
    0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
    0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
)
THREE_G = (
    0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
    0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672,
)


class PointArithmeticTests(unittest.TestCase):
    def test_generator_is_on_curve(self):
        self.assertTrue(Point.G.is_on_curve())

    def test_double_g_matches_known_vector(self):
        self.assertEqual(double(Point.G).to_affine(), TWO_G)

    def test_scalar_mult_known_vectors(self):
        self.assertEqual(scalar_mult(2).to_affine(), TWO_G)
        self.assertEqual(scalar_mult(3).to_affine(), THREE_G)

    def test_scalar_mult_starts_at_generator(self):
        self.assertEqual(scalar_mult(1), Point.G)

    def test_group_law_consistency(self):
        """k·G + G 必须等于 (k+1)·G —— 不依赖任何记忆常量的自洽性检查。"""
        for k in range(1, 40):
            with self.subTest(k=k):
                self.assertEqual(add(scalar_mult(k), Point.G), scalar_mult(k + 1))

    def test_double_matches_add_self(self):
        self.assertEqual(double(scalar_mult(17)), add(scalar_mult(17), scalar_mult(17)))

    def test_infinity_is_identity(self):
        infinity = Point.infinity()
        self.assertTrue(infinity.is_infinity())
        self.assertEqual(add(Point.G, infinity), Point.G)
        self.assertEqual(add(infinity, Point.G), Point.G)

    def test_additive_inverse_is_infinity(self):
        neg_g = Point.affine(GX, P - GY)
        self.assertTrue(add(Point.G, neg_g).is_infinity())

    def test_order_times_generator_is_infinity(self):
        # scalar_mult 内部对 N 取模，所以 N 与 0 等价，都应得到无穷远点
        self.assertTrue(scalar_mult(N).is_infinity())
        self.assertTrue(scalar_mult(0).is_infinity())

    def test_n_minus_one_times_g_is_negated_generator(self):
        self.assertEqual(scalar_mult(N - 1).to_affine(), (GX, (P - GY) % P))

    def test_scalar_mult_is_distributive(self):
        a, b = 123456, 654321
        self.assertEqual(scalar_mult(a + b), add(scalar_mult(a), scalar_mult(b)))

    def test_infinity_hash_and_eq(self):
        self.assertEqual(Point.infinity(), Point.infinity())
        self.assertNotEqual(Point.infinity(), Point.G)


class RFC6979Tests(unittest.TestCase):
    def test_deterministic_nonce_repeats(self):
        message_hash = hashlib.sha256(b"nimbus-chain").digest()
        first = sign(message_hash, 0xDEADBEEF)
        second = sign(message_hash, 0xDEADBEEF)
        self.assertEqual(first, second)
        self.assertEqual(first.to_der(), second.to_der())

    def test_different_messages_differ(self):
        a = sign(hashlib.sha256(b"a").digest(), 7)
        b = sign(hashlib.sha256(b"b").digest(), 7)
        self.assertNotEqual(a, b)

    def test_satoshi_nakamoto_vector(self):
        """Bitcoin wiki 上广为引用的 RFC 6979 确定性签名向量（私钥 = 1）。"""
        message_hash = hashlib.sha256(b"Satoshi Nakamoto").digest()
        self.assertEqual(
            rfc6979_nonce(1, message_hash),
            0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15,
        )
        signature = sign(message_hash, 1)
        self.assertEqual(signature.r, 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8)
        self.assertEqual(signature.s, 0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5)

    def test_nonce_in_valid_range(self):
        for secret in (1, 2, 12345, N - 1):
            with self.subTest(secret=secret):
                k = rfc6979_nonce(secret, hashlib.sha256(b"x").digest())
                self.assertTrue(1 <= k < N)


class ECDSATests(unittest.TestCase):
    def setUp(self):
        self.secret = 0x5EC884F0C2E8B7E5B1A0B7A6D5A3C1E9F0A1B2C3D4E5F60718293A4B5C6D7E8F
        self.key = PrivateKey(self.secret)
        self.message_hash = hashlib.sha256(b"transfer 100 to alice").digest()

    def test_sign_verify_roundtrip(self):
        signature = self.key.sign(self.message_hash)
        self.assertTrue(verify(self.message_hash, signature, self.key.public_key()))

    def test_verify_accepts_der_bytes(self):
        signature = self.key.sign(self.message_hash)
        self.assertTrue(verify(self.message_hash, signature.to_der(), self.key.public_key().to_bytes()))

    def test_flipping_one_message_bit_fails(self):
        signature = self.key.sign(self.message_hash)
        tampered = bytearray(self.message_hash)
        tampered[0] ^= 0x01
        self.assertFalse(verify(bytes(tampered), signature, self.key.public_key()))

    def test_flipping_one_signature_bit_fails(self):
        signature = self.key.sign(self.message_hash)
        tampered_r = signature.r ^ 0x01
        self.assertFalse(verify(self.message_hash, type(signature)(tampered_r, signature.s), self.key.public_key()))

    def test_wrong_public_key_fails(self):
        signature = self.key.sign(self.message_hash)
        other = PrivateKey(self.secret + 1).public_key()
        self.assertFalse(verify(self.message_hash, signature, other))

    def test_high_s_variant_is_mathematically_valid(self):
        """(r, N-s) 在数学上同样有效；是否禁止由上层策略决定。"""
        signature = self.key.sign(self.message_hash)
        high = type(signature)(signature.r, N - signature.s)
        self.assertFalse(is_low_s(high.s))
        self.assertTrue(verify(self.message_hash, high, self.key.public_key()))

    def test_signer_always_produces_low_s(self):
        for index in range(12):
            with self.subTest(index=index):
                signature = self.key.sign(hashlib.sha256(f"msg-{index}".encode()).digest())
                self.assertTrue(is_low_s(signature.s), "签名未归一化到低半区")

    def test_normalize_s(self):
        self.assertEqual(normalize_s(1), 1)
        self.assertEqual(normalize_s(N - 1), 1)
        self.assertEqual(normalize_s(N // 2), N // 2)

    def test_out_of_range_values_rejected(self):
        signature = self.key.sign(self.message_hash)
        for bad in (type(signature)(0, signature.s), type(signature)(signature.r, N)):
            with self.subTest(bad=bad):
                self.assertFalse(verify(self.message_hash, bad, self.key.public_key()))

    def test_invalid_message_hash_length(self):
        with self.assertRaises(ValueError):
            sign(b"short", 1)
        with self.assertRaises(ValueError):
            verify(b"short", sign(hashlib.sha256(b"x").digest(), 1), PrivateKey(1).public_key())


class DERTests(unittest.TestCase):
    def test_roundtrip(self):
        for r, s in ((1, 1), (N - 1, N - 1), (0x7F, 0x80), (2 ** 255, 2 ** 200 + 7)):
            with self.subTest(r=r, s=s):
                self.assertEqual(der_decode(der_encode(r, s)), Signature(r, s))

    def test_minimal_encoding_prepends_zero_for_high_bit(self):
        encoded = der_encode(0x80, 0x01)
        self.assertIn(b"\x02\x02\x00\x80", encoded)

    def test_signature_object_to_der_matches_function(self):
        signature = sign(hashlib.sha256(b"der").digest(), 42)
        self.assertEqual(signature.to_der(), der_encode(signature.r, signature.s))

    def test_malformed_rejected(self):
        cases = [
            b"",
            b"\x31\x08" + b"\x00" * 8,                       # 不是 SEQUENCE
            b"\x30\x09\x02\x02\x01\x00\x02\x01\x05",          # 长度不一致
            b"\x30\x07\x02\x02\x00\x01\x02\x01\x05",          # r 非最小编码
            b"\x30\x05\x02\x02\x01\x00\x02\x00",              # 零长度整数
            der_encode(1, 2) + b"\x00",                       # 尾部多余字节
        ]
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(DERError):
                    der_decode(data)

    def test_negative_integer_rejected(self):
        with self.assertRaises(DERError):
            der_decode(b"\x30\x06\x02\x01\x81\x02\x01\x05")


class PublicKeyTests(unittest.TestCase):
    def test_serialization_roundtrip(self):
        for seed in (1, 2, 0x1234567890ABCDEF, N - 2):
            with self.subTest(seed=seed):
                key = PrivateKey(seed).public_key()
                self.assertEqual(PublicKey.from_bytes(key.to_bytes(compressed=True)), key)
                self.assertEqual(PublicKey.from_bytes(key.to_bytes(compressed=False)), key)

    def test_compressed_form_is_33_bytes_and_prefix_matches_parity(self):
        key = PrivateKey(2026).public_key()
        compressed = key.to_bytes(compressed=True)
        self.assertEqual(len(compressed), 33)
        self.assertEqual(compressed[0], 0x02 + (key.point.to_affine()[1] & 1))
        self.assertEqual(len(key.to_bytes(compressed=False)), 65)

    def test_address_is_base58check_of_pubkey_hash(self):
        key = PrivateKey(0xBEEF).public_key()
        version, payload = b58check_decode(key.address())
        self.assertEqual(version, 0)
        self.assertEqual(payload, hash160(key.to_bytes(compressed=True)))
        self.assertEqual(payload, key.hash160())

    def test_bad_encoding_rejected(self):
        for data in (b"", b"\x01" + b"\x00" * 32, b"\x04" + b"\x00" * 64, b"\x02" + b"\x00" * 32):
            with self.subTest(data=data[:2]):
                with self.assertRaises(ValueError):
                    PublicKey.from_bytes(data)

    def test_generate_produces_valid_key(self):
        key = PrivateKey.generate()
        self.assertTrue(1 <= key.secret < N)
        self.assertTrue(key.public_key().point.is_on_curve())

    def test_out_of_range_private_key_rejected(self):
        for bad in (0, N, N + 1, -1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    PrivateKey(bad)


if __name__ == "__main__":
    unittest.main()

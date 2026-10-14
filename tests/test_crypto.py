"""密码学原语测试：NIST 向量、纯实现 vs hashlib 逐字节交叉验证、Base58Check。"""

from __future__ import annotations

import hashlib
import random
import unittest

from nimbus_chain.crypto import (
    Base58ChecksumError,
    b58check_decode,
    b58check_encode,
    b58decode,
    b58encode,
    hash160,
    hash256,
    ripemd160,
    set_hash_backend,
    sha256,
    sha256_pure,
    using_pure_backend,
)

# NIST FIPS 180-4 官方向量
SHA256_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
]

# RIPEMD-160 官方测试向量（Bosselaers 等给出的标准集）
RIPEMD160_VECTORS = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
]

# 填充边界：刚好在 55/56/63/64/119/120 字节处，最容易写错 bit 长度字段
BOUNDARY_LENGTHS = [0, 1, 2, 55, 56, 57, 63, 64, 65, 111, 119, 120, 127, 128, 129, 255, 256]


class SHA256Tests(unittest.TestCase):
    def test_nist_vectors_pure(self):
        for data, expected in SHA256_VECTORS:
            with self.subTest(data=data[:16]):
                self.assertEqual(sha256_pure(data).hex(), expected)

    def test_padding_boundaries_match_hashlib(self):
        rng = random.Random(20261015)
        for length in BOUNDARY_LENGTHS:
            with self.subTest(length=length):
                data = bytes(rng.randrange(256) for _ in range(length))
                self.assertEqual(sha256_pure(data), hashlib.sha256(data).digest())

    def test_random_payloads_match_hashlib(self):
        rng = random.Random(7)
        for _ in range(40):
            data = rng.randbytes(rng.randrange(0, 600))
            self.assertEqual(sha256_pure(data), hashlib.sha256(data).digest())

    def test_backend_switch(self):
        previous = using_pure_backend()
        try:
            self.assertFalse(previous)  # 默认快路径
            set_hash_backend(True)
            self.assertTrue(using_pure_backend())
            self.assertEqual(sha256(b"abc"), sha256_pure(b"abc"))
            set_hash_backend(False)
            self.assertEqual(sha256(b"abc"), hashlib.sha256(b"abc").digest())
        finally:
            set_hash_backend(previous)

    def test_hash256_is_double_sha256(self):
        data = b"nimbus-chain"
        self.assertEqual(hash256(data), hashlib.sha256(hashlib.sha256(data).digest()).digest())


class RIPEMD160Tests(unittest.TestCase):
    def test_official_vectors(self):
        for data, expected in RIPEMD160_VECTORS:
            with self.subTest(data=data[:16]):
                self.assertEqual(ripemd160(data).hex(), expected)

    def test_padding_boundaries_match_hashlib(self):
        try:
            reference = hashlib.new("ripemd160")
        except (ValueError, TypeError):  # pragma: no cover - 取决于 OpenSSL provider
            self.skipTest("hashlib 未提供 ripemd160，退回官方向量校验")
        rng = random.Random(42)
        for length in BOUNDARY_LENGTHS:
            with self.subTest(length=length):
                data = bytes(rng.randrange(256) for _ in range(length))
                reference_copy = reference.copy()
                reference_copy.update(data)
                self.assertEqual(ripemd160(data), reference_copy.digest())

    def test_hash160_composition(self):
        pubkey = bytes.fromhex("02" + "ab" * 32)
        expected = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest() \
            if _has_ripemd160() else ripemd160(sha256(pubkey))
        self.assertEqual(hash160(pubkey), expected)


def _has_ripemd160() -> bool:
    try:
        hashlib.new("ripemd160")
    except (ValueError, TypeError):
        return False
    return True


class Base58Tests(unittest.TestCase):
    def test_roundtrip(self):
        rng = random.Random(99)
        for _ in range(60):
            data = rng.randbytes(rng.randrange(0, 40))
            self.assertEqual(b58decode(b58encode(data)), data)

    def test_leading_zero_bytes_preserved(self):
        data = b"\x00\x00\x01"
        encoded = b58encode(data)
        self.assertEqual(encoded, "112")
        self.assertEqual(b58decode(encoded), data)
        self.assertEqual(b58decode("1"), b"\x00")

    def test_invalid_character_rejected(self):
        for bad in ("0", "O", "I", "l", "!"):
            with self.subTest(char=bad):
                with self.assertRaises(ValueError):
                    b58decode(bad)

    def test_genesis_address_vector(self):
        """Bitcoin 创世区块 coinbase 输出地址：0x00 版本 + 已知 hash160。"""
        pubkey_hash = bytes.fromhex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
        address = b58check_encode(pubkey_hash, version=0x00)
        self.assertEqual(address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        version, payload = b58check_decode(address)
        self.assertEqual(version, 0x00)
        self.assertEqual(payload, pubkey_hash)

    def test_checksum_tamper_detected(self):
        address = b58check_encode(b"\x11" * 20, version=0x00)
        # 翻转最后一个字符，必然破坏校验和
        flipped = address[:-1] + ("2" if address[-1] != "2" else "3")
        with self.assertRaises(Base58ChecksumError):
            b58check_decode(flipped)

    def test_version_byte_must_fit(self):
        with self.assertRaises(ValueError):
            b58check_encode(b"\x00" * 20, version=256)


if __name__ == "__main__":
    unittest.main()

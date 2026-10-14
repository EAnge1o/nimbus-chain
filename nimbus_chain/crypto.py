"""密码学原语：SHA-256 / SHA-256d / RIPEMD-160 / Base58Check。

本项目最核心的一条约束是「零第三方运行时依赖」，因此这里的哈希函数都是
**纯 Python 从零实现**（消息填充、压缩函数、轮常量全部手写），而不是包装
``hashlib``。同时保留一条 ``hashlib`` 快路径：挖矿与批量哈希默认走快路径，
两套实现由 ``tests/test_crypto.py`` 用 NIST 向量与随机数据逐字节交叉验证。

对外接口：

    sha256_pure(data)         纯 Python SHA-256
    sha256(data)              当前后端（快路径 / 纯实现）的 SHA-256
    hash256(data)             SHA-256d，即 sha256(sha256(data))，Bitcoin 的 HASH256
    ripemd160(data)           纯 Python RIPEMD-160
    hash160(data)             RIPEMD-160(SHA-256(data))，公钥哈希
    set_hash_backend(pure)    切换后端，返回切换前的值
    b58encode / b58decode     Base58
    b58check_encode / b58check_decode   Base58Check（版本字节 + 4 字节双 SHA256 校验和）
"""

from __future__ import annotations

import hashlib

__all__ = [
    "sha256_pure",
    "sha256",
    "hash256",
    "ripemd160",
    "hash160",
    "set_hash_backend",
    "using_pure_backend",
    "b58encode",
    "b58decode",
    "b58check_encode",
    "b58check_decode",
    "Base58ChecksumError",
]

# --------------------------------------------------------------------------- #
# SHA-256
# --------------------------------------------------------------------------- #

_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

_SHA256_H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

_MASK32 = 0xFFFFFFFF


def _ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _sha256_compress(state: list[int], block: bytes) -> None:
    """压缩函数：一轮 64 步，就地更新 8 个 32 位工作变量。"""
    w = [0] * 64
    for i in range(16):
        j = i * 4
        w[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]
    for i in range(16, 64):
        s0 = _ror32(w[i - 15], 7) ^ _ror32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _ror32(w[i - 2], 17) ^ _ror32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        sigma1 = _ror32(e, 6) ^ _ror32(e, 11) ^ _ror32(e, 25)
        ch = (e & f) ^ (~e & g & _MASK32)
        t1 = (h + sigma1 + ch + _SHA256_K[i] + w[i]) & _MASK32
        sigma0 = _ror32(a, 2) ^ _ror32(a, 13) ^ _ror32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (sigma0 + maj) & _MASK32
        h = g
        g = f
        f = e
        e = (d + t1) & _MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & _MASK32

    state[0] = (state[0] + a) & _MASK32
    state[1] = (state[1] + b) & _MASK32
    state[2] = (state[2] + c) & _MASK32
    state[3] = (state[3] + d) & _MASK32
    state[4] = (state[4] + e) & _MASK32
    state[5] = (state[5] + f) & _MASK32
    state[6] = (state[6] + g) & _MASK32
    state[7] = (state[7] + h) & _MASK32


def _sha256_pad(data: bytes) -> bytes:
    """Merkle–Damgård 填充：0x80 + 0 字节 + 64 位大端比特长度。"""
    bit_len = len(data) * 8
    pad_len = (56 - (len(data) + 1) % 64) % 64
    return data + b"\x80" + b"\x00" * pad_len + bit_len.to_bytes(8, "big")


def sha256_pure(data: bytes) -> bytes:
    """纯 Python SHA-256，不使用 ``hashlib``。"""
    state = list(_SHA256_H0)
    padded = _sha256_pad(data)
    for offset in range(0, len(padded), 64):
        _sha256_compress(state, padded[offset:offset + 64])
    return b"".join(x.to_bytes(4, "big") for x in state)


_pure_backend = False


def sha256(data: bytes) -> bytes:
    """SHA-256。默认走 ``hashlib`` 快路径，``set_hash_backend(pure=True)`` 可切到纯实现。"""
    if _pure_backend:
        return sha256_pure(data)
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Bitcoin 的 HASH256 = SHA-256(SHA-256(data))。

    注意它不是「SHA-256d 之后再取反」，这里返回的是原始大端字节序摘要；
    面向用户展示时（区块哈希、交易哈希）才需要 ``[::-1].hex()``。
    """
    return sha256(sha256(data))


def set_hash_backend(pure: bool) -> bool:
    """切换哈希后端，返回切换前的值。"""
    global _pure_backend
    previous = _pure_backend
    _pure_backend = bool(pure)
    return previous


def using_pure_backend() -> bool:
    return _pure_backend


# --------------------------------------------------------------------------- #
# RIPEMD-160
# --------------------------------------------------------------------------- #

_RL = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_RR = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
_SL = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_SR = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)
_KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
_RIPEMD_H0 = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _r_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z & _MASK32)
    if j < 48:
        return (x | (~y & _MASK32)) ^ z
    if j < 64:
        return (x & z) | (y & (~z & _MASK32))
    return x ^ (y | (~z & _MASK32))


def _ripemd160_pad(data: bytes) -> bytes:
    """RIPEMD-160 填充与 SHA-256 相同，但长度字段是 **小端** 64 位。"""
    bit_len = len(data) * 8
    pad_len = (56 - (len(data) + 1) % 64) % 64
    return data + b"\x80" + b"\x00" * pad_len + bit_len.to_bytes(8, "little")


def _ripemd160_compress(state: list[int], block: bytes) -> None:
    x = []
    for i in range(16):
        j = i * 4
        x.append(block[j] | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24))

    al, bl, cl, dl, el = state
    ar, br, cr, dr, er = state

    for j in range(80):
        # 左侧线（f1 → f5）
        t = (_rol32((al + _r_f(j, bl, cl, dl) + x[_RL[j]] + _KL[j // 16]) & _MASK32, _SL[j]) + el) & _MASK32
        al, el, dl, cl, bl = el, dl, _rol32(cl, 10), bl, t
        # 右侧线（f5 → f1，即 f(79 - j)）
        t = (_rol32((ar + _r_f(79 - j, br, cr, dr) + x[_RR[j]] + _KR[j // 16]) & _MASK32, _SR[j]) + er) & _MASK32
        ar, er, dr, cr, br = er, dr, _rol32(cr, 10), br, t

    t = (state[1] + cl + dr) & _MASK32
    state[1] = (state[2] + dl + er) & _MASK32
    state[2] = (state[3] + el + ar) & _MASK32
    state[3] = (state[4] + al + br) & _MASK32
    state[4] = (state[0] + bl + cr) & _MASK32
    state[0] = t


def ripemd160(data: bytes) -> bytes:
    """纯 Python RIPEMD-160。

    这里刻意不走 ``hashlib.new('ripemd160')``：该算法在部分 OpenSSL 构建里被
    移出默认 provider，跨平台不可靠；公钥哈希不是热点路径，纯实现足够快。
    """
    state = list(_RIPEMD_H0)
    padded = _ripemd160_pad(data)
    for offset in range(0, len(padded), 64):
        _ripemd160_compress(state, padded[offset:offset + 64])
    return b"".join(w.to_bytes(4, "little") for w in state)


def hash160(data: bytes) -> bytes:
    """HASH160 = RIPEMD-160(SHA-256(data))，即 Bitcoin 的公钥哈希 / 脚本哈希。"""
    return ripemd160(sha256(data))


# --------------------------------------------------------------------------- #
# Base58 / Base58Check
# --------------------------------------------------------------------------- #

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


class Base58ChecksumError(ValueError):
    """Base58Check 解码时校验和不匹配。"""


def b58encode(data: bytes) -> str:
    """Base58 编码。前导 0x00 字节编码为等量的 ``'1'``（Bitcoin 地址语义）。"""
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    number = int.from_bytes(data, "big")
    out = []
    while number > 0:
        number, rem = divmod(number, 58)
        out.append(_B58_ALPHABET[rem])
    return "1" * leading_zeros + "".join(reversed(out))


def b58decode(text: str) -> bytes:
    """Base58 解码；非法字符抛 ``ValueError``。"""
    number = 0
    for char in text:
        if char not in _B58_INDEX:
            raise ValueError(f"invalid base58 character: {char!r}")
        number = number * 58 + _B58_INDEX[char]
    leading_zeros = 0
    for char in text:
        if char == "1":
            leading_zeros += 1
        else:
            break
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * leading_zeros + body


def b58check_encode(payload: bytes, version: int = 0) -> str:
    """Base58Check 编码：``version || payload`` 后接双 SHA-256 的前 4 字节校验和。"""
    if not 0 <= version <= 0xFF:
        raise ValueError("version must be a single byte")
    raw = bytes([version]) + payload
    checksum = hash256(raw)[:4]
    return b58encode(raw + checksum)


def b58check_decode(text: str) -> tuple[int, bytes]:
    """Base58Check 解码，返回 ``(version, payload)``；校验和错误抛异常。"""
    raw = b58decode(text)
    if len(raw) < 5:
        raise Base58ChecksumError("payload too short to contain a checksum")
    payload, checksum = raw[:-4], raw[-4:]
    if hash256(payload)[:4] != checksum:
        raise Base58ChecksumError("base58check checksum mismatch")
    return payload[0], payload[1:]

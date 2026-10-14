"""secp256k1 椭圆曲线与 ECDSA —— 纯 Python 从零实现。

标准库不提供任何椭圆曲线运算，所以这一层没有"快路径"可退：曲线参数、Jacobian
点运算、标量乘、ECDSA 签验、RFC 6979 确定性 nonce、DER 编解码、low-S 归一化、
公钥压缩/解压全部手写。

坐标选择：内部用 **Jacobian 坐标** ``(X : Y : Z)`` 表示仿射点 ``(X/Z², Y/Z³)``。
仿射坐标每做一次点加都要模逆，而 ``pow(a, -1, p)`` 是 C 实现的模幂，仍然比几次
模乘贵得多；Jacobian 只在最后转仿射时做一次模逆。实测标量乘约 5–15 ms、
验签约 15–40 ms，足够支撑上百个单测和低难度 PoW 演示。

对外接口：

    Point                     曲线点（Jacobian 封装，``Point.G`` 为基点）
    scalar_mult(k, P)         k·P
    PublicKey                 公钥：序列化、压缩、地址、hash160
    PrivateKey                私钥包装：签名、公钥导出
    sign(msg_hash, priv)      ECDSA 签名，返回 DER；RFC 6979 确定性、low-S
    verify(msg_hash, sig, pub) 验签；接受 high-S（数学有效），是否禁由上层决定
    is_low_s(s) / normalize_s(s)
    der_encode / der_decode
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .crypto import b58check_encode, hash160

__all__ = [
    "P",
    "N",
    "GX",
    "GY",
    "Point",
    "scalar_mult",
    "Signature",
    "PrivateKey",
    "PublicKey",
    "sign",
    "verify",
    "is_low_s",
    "normalize_s",
    "rfc6979_nonce",
    "der_encode",
    "der_decode",
    "DERError",
]

# --------------------------------------------------------------------------- #
# 曲线参数（SEC 2 / Standards for Efficient Cryptography）
# --------------------------------------------------------------------------- #

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

_HALF_N = N // 2
_QLEN = 256  # N.bit_length()
_ROLEN = 32  # (QLEN + 7) // 8
_P_PLUS_1_OVER_4 = (P + 1) // 4


class DERError(ValueError):
    """DER 签名编码格式非法。"""


# --------------------------------------------------------------------------- #
# 点运算
# --------------------------------------------------------------------------- #


class Point:
    """secp256k1 上的点，内部为 Jacobian 坐标。"""

    __slots__ = ("x", "y", "z")

    def __init__(self, x: int, y: int, z: int) -> None:
        self.x = x
        self.y = y
        self.z = z

    @classmethod
    def infinity(cls) -> "Point":
        """无穷远点（群单位元），按约定用 ``z == 0`` 表示。"""
        return cls(0, 1, 0)

    @classmethod
    def affine(cls, x: int, y: int) -> "Point":
        return cls(x % P, y % P, 1)

    def is_infinity(self) -> bool:
        return self.z == 0

    def is_on_curve(self) -> bool:
        if self.is_infinity():
            return True
        x, y = self.to_affine()
        return (y * y - x * x * x - 7) % P == 0

    def to_affine(self) -> tuple[int, int] | None:
        if self.is_infinity():
            return None
        z_inv = pow(self.z, -1, P)
        z_inv2 = z_inv * z_inv % P
        return self.x * z_inv2 % P, self.y * z_inv2 * z_inv % P

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        if self.is_infinity() or other.is_infinity():
            return self.is_infinity() and other.is_infinity()
        return self.to_affine() == other.to_affine()

    def __hash__(self) -> int:
        return hash(self.to_affine())

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        affine = self.to_affine()
        if affine is None:
            return "Point(infinity)"
        return f"Point(x={affine[0]:064x}, y={affine[1]:064x})"


Point.G = Point.affine(GX, GY)  # type: ignore[attr-defined]


def double(point: Point) -> Point:
    """倍增：``a == 0`` 时的 Jacobian 公式。"""
    if point.is_infinity() or point.y == 0:
        return Point.infinity()
    x, y, z = point.x, point.y, point.z
    y2 = y * y % P
    s = 4 * x * y2 % P                      # S = 4XY²
    m = 3 * x * x % P                       # M = 3X² + aZ⁴，这里 a = 0
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * y2 * y2) % P   # Y' = M(S-X') - 8Y⁴
    z3 = 2 * y * z % P
    return Point(x3, y3, z3)


def add(left: Point, right: Point) -> Point:
    """点加，正确处理「同一个点」与「互为逆元」两种退化情形。"""
    if left.is_infinity():
        return right
    if right.is_infinity():
        return left

    z1z1 = left.z * left.z % P
    z2z2 = right.z * right.z % P
    u1 = left.x * z2z2 % P
    u2 = right.x * z1z1 % P
    s1 = left.y * right.z * z2z2 % P
    s2 = right.y * left.z * z1z1 % P

    h = (u2 - u1) % P
    r = (s2 - s1) % P
    if h == 0:
        # 同一点（或互为逆元：R == 0 时两者互逆，和为无穷远）
        return double(left) if r == 0 else Point.infinity()

    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    x3 = (r * r - h3 - 2 * u1h2) % P
    y3 = (r * (u1h2 - x3) - s1 * h3) % P
    z3 = h * left.z % P * right.z % P
    return Point(x3, y3, z3)


def scalar_mult(k: int, point: Point = Point.G) -> Point:
    """标量乘 ``k·P``（从高位到低位的 double-and-add）。

    只用于基点及基点所在素数阶子群中的点，因此先对 ``k`` 取模 ``N``。
    """
    k %= N
    if k == 0 or point.is_infinity():
        return Point.infinity()
    result = Point.infinity()
    addend = point
    while k:
        if k & 1:
            result = add(result, addend)
        addend = double(addend)
        k >>= 1
    return result


def _lift_x(x: int) -> Point:
    """由 x 还原点（取偶数 y）；x 不在曲线上时抛 ``ValueError``。"""
    if not 0 <= x < P:
        raise ValueError("x out of field range")
    alpha = (x * x * x + 7) % P
    # p ≡ 3 (mod 4)，所以平方根可以直接写成 pow(alpha, (p+1)/4, p)
    beta = pow(alpha, _P_PLUS_1_OVER_4, P)
    if beta * beta % P != alpha:
        raise ValueError("x is not on the curve")
    return Point.affine(x, beta if beta % 2 == 0 else P - beta)


# --------------------------------------------------------------------------- #
# 公钥 / 私钥
# --------------------------------------------------------------------------- #


class PublicKey:
    """公钥：一个曲线点，附带序列化与地址能力。"""

    __slots__ = ("point",)

    def __init__(self, point: Point) -> None:
        if point.is_infinity():
            raise ValueError("public key cannot be the point at infinity")
        self.point = point

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicKey":
        if len(data) == 33 and data[0] in (0x02, 0x03):
            point = _lift_x(int.from_bytes(data[1:], "big"))
            if point.to_affine()[1] % 2 != data[0] - 0x02:
                point = Point.affine(point.to_affine()[0], P - point.to_affine()[1])
            return cls(point)
        if len(data) == 65 and data[0] == 0x04:
            point = Point.affine(int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
            if not point.is_on_curve():
                raise ValueError("public key is not on the curve")
            return cls(point)
        raise ValueError("unsupported public key encoding")

    def to_bytes(self, compressed: bool = True, prefix: int = 0x00) -> bytes:
        x, y = self.point.to_affine()  # type: ignore[misc]
        if compressed:
            return bytes([0x02 + (y & 1), *x.to_bytes(32, "big")])
        return bytes([0x04, *x.to_bytes(32, "big"), *y.to_bytes(32, "big")])

    def hash160(self, compressed: bool = True) -> bytes:
        return hash160(self.to_bytes(compressed))

    def address(self, version: int = 0, compressed: bool = True) -> str:
        return b58check_encode(self.hash160(compressed), version=version)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.point == other.point

    def __hash__(self) -> int:
        return hash(self.point)


class PrivateKey:
    """私钥：一个 ``[1, N-1]`` 的标量。"""

    __slots__ = ("secret",)

    def __init__(self, secret: int) -> None:
        if not 1 <= secret < N:
            raise ValueError("private key must be in [1, N-1]")
        self.secret = secret

    @classmethod
    def generate(cls) -> "PrivateKey":
        return cls(secrets.randbelow(N - 1) + 1)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PrivateKey":
        return cls(int.from_bytes(data, "big"))

    def to_bytes(self) -> bytes:
        return self.secret.to_bytes(32, "big")

    def public_key(self) -> PublicKey:
        return PublicKey(scalar_mult(self.secret))

    def sign(self, msg_hash: bytes) -> Signature:
        return sign(msg_hash, self.secret)

    def __repr__(self) -> str:  # pragma: no cover - 不泄露私钥
        return f"PrivateKey(<hidden>, address={self.public_key().address()})"


# --------------------------------------------------------------------------- #
# RFC 6979 确定性 nonce
# --------------------------------------------------------------------------- #


def _bits2int(data: bytes) -> int:
    """取数据最左侧 ``qlen`` 位作为整数（注意：**不是**直接取模）。"""
    value = int.from_bytes(data, "big")
    blen = len(data) * 8
    if blen > _QLEN:
        value >>= blen - _QLEN
    return value


def _int2octets(value: int) -> bytes:
    return value.to_bytes(_ROLEN, "big")


def _bits2octets(data: bytes) -> bytes:
    z1 = _bits2int(data)
    z2 = z1 % N
    return _int2octets(z2)


def rfc6979_nonce(secret: int, msg_hash: bytes) -> int:
    """RFC 6979 §3.2 的 HMAC-SHA256 DRBG，为 ``(secret, msg_hash)`` 产出确定性 k。

    确定性 nonce 的意义在于：同一个密钥对同一条消息永远给出同一个签名，彻底
    消灭"随机数复用导致私钥泄露"这一类事故，也让测试可以逐字节断言。
    """
    x = _int2octets(secret)
    h1 = _bits2octets(msg_hash)
    v = b"\x01" * 32
    k = b"\x00" * 32

    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = _bits2int(v)
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# --------------------------------------------------------------------------- #
# DER 编解码
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Signature:
    r: int
    s: int

    def to_der(self) -> bytes:
        return der_encode(self.r, self.s)


def _der_int(value: int) -> bytes:
    """DER INTEGER：最小化大端，最高位为 1 时补一个 ``0x00`` 防止被读成负数。"""
    if value == 0:
        return b"\x02\x01\x00"
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes([0x02, len(body)]) + body


def der_encode(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    if len(body) > 127:
        raise DERError("signature too long for short-form DER length")
    return bytes([0x30, len(body)]) + body


def der_decode(data: bytes) -> Signature:
    """严格解析 DER：拒绝长度不一致、非最小化整数、越界值。"""
    if len(data) < 8 or data[0] != 0x30:
        raise DERError("not a DER SEQUENCE")
    if data[1] != len(data) - 2:
        raise DERError("DER length mismatch")
    offset = 2
    values = []
    for _ in range(2):
        if offset + 2 > len(data) or data[offset] != 0x02:
            raise DERError("expected DER INTEGER")
        length = data[offset + 1]
        if length == 0:
            raise DERError("zero-length DER INTEGER")
        body = data[offset + 2:offset + 2 + length]
        if len(body) != length:
            raise DERError("truncated DER INTEGER")
        if body[0] & 0x80:
            raise DERError("DER INTEGER must be non-negative")
        if length > 1 and body[0] == 0x00 and not body[1] & 0x80:
            raise DERError("DER INTEGER is not minimally encoded")
        values.append(int.from_bytes(body, "big"))
        offset += 2 + length
    if offset != len(data):
        raise DERError("trailing bytes after DER signature")
    r, s = values
    if r <= 0 or s <= 0:
        raise DERError("signature values must be positive")
    return Signature(r, s)


# --------------------------------------------------------------------------- #
# ECDSA
# --------------------------------------------------------------------------- #


def is_low_s(s: int) -> bool:
    """BIP 62 low-S 规则：``s <= N/2`` 才是「标准」签名。"""
    return s <= _HALF_N


def normalize_s(s: int) -> int:
    """把 ``s`` 归一化到低半区；``s > N/2`` 时取 ``N - s``。"""
    return s if s <= _HALF_N else N - s


def sign(msg_hash: bytes, secret: int) -> Signature:
    """对 32 字节消息摘要签名，RFC 6979 确定性 nonce + low-S 归一化。"""
    if len(msg_hash) != 32:
        raise ValueError("message hash must be 32 bytes")
    if not 1 <= secret < N:
        raise ValueError("private key must be in [1, N-1]")

    z = _bits2int(msg_hash)
    while True:
        k = rfc6979_nonce(secret, msg_hash)
        point = scalar_mult(k)
        r = point.to_affine()[0] % N  # type: ignore[index]
        if r == 0:
            # 概率 ~2^-256，只可能出现在极其病态的输入上
            raise ValueError("unusable nonce produced r == 0")
        s = pow(k, -1, N) * (z + r * secret) % N
        if s == 0:
            raise ValueError("unusable nonce produced s == 0")
        return Signature(r, normalize_s(s))


def verify(msg_hash: bytes, signature: Signature | bytes, public_key: PublicKey | bytes) -> bool:
    """验签。``signature`` 可以是 :class:`Signature` 或 DER 字节；``public_key`` 可以是对象或字节。

    返回 ``False`` 表示「签名无效」，而不是抛异常——调用方（脚本解释器）需要把
    失败当作 ``OP_CHECKSIG`` 压栈 ``False``，而不是让整个校验崩掉。
    """
    if len(msg_hash) != 32:
        raise ValueError("message hash must be 32 bytes")
    try:
        sig = der_decode(signature) if isinstance(signature, (bytes, bytearray)) else signature
        key = PublicKey.from_bytes(public_key) if isinstance(public_key, (bytes, bytearray)) else public_key
    except (ValueError, DERError):
        return False
    if not isinstance(sig, Signature) or not isinstance(key, PublicKey):
        return False
    if not 1 <= sig.r < N or not 1 <= sig.s < N:
        return False

    z = _bits2int(msg_hash)
    w = pow(sig.s, -1, N)
    u1 = z * w % N
    u2 = sig.r * w % N
    point = add(scalar_mult(u1), scalar_mult(u2, key.point))
    if point.is_infinity():
        return False
    return point.to_affine()[0] % N == sig.r

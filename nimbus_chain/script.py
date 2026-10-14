"""栈式脚本解释器（Bitcoin Script 子集）。

脚本是区块链里「钱能不能被花」的唯一判据。这个模块实现了一个真正的栈式
解释器，而不是"对哈希签个名"：

* 脚本的字节级解析（``OP_PUSHDATA1/2/4``、最小推送编码）与序列化
* CScriptNum 数值编码（小端 + 符号位 + 最小化）
* P2PKH / P2SH / 多签 / OP_RETURN 的构造与识别
* 哈希、算术、比较、条件分支、栈操作类 opcode
* ``OP_CHECKSIG`` / ``OP_CHECKMULTISIG``：从栈上取签名与公钥，用当前交易的
  **sighash** 做真实验签（``sighash`` 由调用方通过 :class:`Checker` 注入，
  避免与 ``tx`` 模块循环导入）
* ``OP_CHECKLOCKTIMEVERIFY`` / ``OP_CHECKSEQUENCEVERIFY`` 时间锁
* P2SH 两阶段执行（先验证 redeem script 的哈希，再用它作为 scriptCode 执行）

有意未实现：``OP_CODESEPARATOR`` 的 FindAndDelete 语义、SegWit 的 BIP143、
时钟类 opcode；遇到即抛 :class:`ScriptError` 而不是静默出错。
"""

from __future__ import annotations

from .crypto import hash160, hash256, ripemd160, sha256
from .secp256k1 import verify

__all__ = [
    "ScriptError",
    "OP_RETURN",
    "MAX_SCRIPT_SIZE",
    "MAX_STACK_ITEMS",
    "encode_num",
    "decode_num",
    "cast_to_bool",
    "parse_script",
    "serialize_script",
    "p2pkh_script",
    "p2pkh_script_sig",
    "p2sh_script",
    "multisig_script",
    "op_return_script",
    "is_p2pkh",
    "is_p2sh",
    "is_op_return",
    "is_multisig",
    "is_provably_unspendable",
    "extract_op_return",
    "Checker",
    "verify_input",
    "run_script",
]

MAX_SCRIPT_SIZE = 10_000
MAX_STACK_ITEMS = 1_000
_MAX_NUM_BYTES = 4  # 参与算术运算的脚本数最长 4 字节


class ScriptError(ValueError):
    """脚本结构非法或执行失败。"""


# --------------------------------------------------------------------------- #
# opcode 表
# --------------------------------------------------------------------------- #

OP_0 = 0x00
OP_FALSE = OP_0
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1NEGATE = 0x4F
OP_RESERVED = 0x50
OP_1 = 0x51
OP_TRUE = OP_1
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_7 = 0x57
OP_8 = 0x58
OP_9 = 0x59
OP_10 = 0x5A
OP_11 = 0x5B
OP_12 = 0x5C
OP_13 = 0x5D
OP_14 = 0x5E
OP_15 = 0x5F
OP_16 = 0x60

OP_NOP = 0x61
OP_VER = 0x62
OP_IF = 0x63
OP_NOTIF = 0x64
OP_VERIF = 0x65
OP_VERNOTIF = 0x66
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6A

OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_2DROP = 0x6D
OP_2DUP = 0x6E
OP_3DUP = 0x6F
OP_2OVER = 0x70
OP_2ROT = 0x71
OP_2SWAP = 0x72
OP_IFDUP = 0x73
OP_DEPTH = 0x74
OP_DROP = 0x75
OP_DUP = 0x76
OP_NIP = 0x77
OP_OVER = 0x78
OP_PICK = 0x79
OP_ROLL = 0x7A
OP_ROT = 0x7B
OP_SWAP = 0x7C
OP_TUCK = 0x7D

OP_SIZE = 0x82

OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88

OP_1ADD = 0x8B
OP_1SUB = 0x8C
OP_NEGATE = 0x8F
OP_ABS = 0x90
OP_NOT = 0x91
OP_0NOTEQUAL = 0x92
OP_ADD = 0x93
OP_SUB = 0x94
OP_BOOLAND = 0x9A
OP_BOOLOR = 0x9B
OP_NUMEQUAL = 0x9C
OP_NUMEQUALVERIFY = 0x9D
OP_NUMNOTEQUAL = 0x9E
OP_LESSTHAN = 0x9F
OP_GREATERTHAN = 0xA0
OP_LESSTHANOREQUAL = 0xA1
OP_GREATERTHANOREQUAL = 0xA2
OP_MIN = 0xA3
OP_MAX = 0xA4
OP_WITHIN = 0xA5

OP_RIPEMD160 = 0xA6
OP_SHA1 = 0xA7
OP_SHA256 = 0xA8
OP_HASH160 = 0xA9
OP_HASH256 = 0xAA
OP_CODESEPARATOR = 0xAB
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF

OP_CHECKLOCKTIMEVERIFY = 0xB1
OP_CHECKSEQUENCEVERIFY = 0xB2

_OPCODE_NAMES = {value: name for name, value in list(globals().items()) if name.startswith("OP_") and isinstance(value, int)}

# 已实现但**禁用**的 opcode（会直接导致脚本失败）
_DISABLED = {OP_VER, OP_VERIF, OP_VERNOTIF, OP_CODESEPARATOR}


# --------------------------------------------------------------------------- #
# CScriptNum
# --------------------------------------------------------------------------- #


def encode_num(value: int) -> bytes:
    """CScriptNum 编码：小端序，最高字节的 0x80 位表示符号，最小化长度。"""
    if value == 0:
        return b""
    negative = value < 0
    magnitude = -value if negative else value
    result = bytearray()
    while magnitude:
        result.append(magnitude & 0xFF)
        magnitude >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(data: bytes, *, require_minimal: bool = True, max_size: int = _MAX_NUM_BYTES) -> int:
    """CScriptNum 解码。``require_minimal`` 打开时拒绝非最小化编码。

    ``max_size`` 默认 4 字节；``OP_CHECKLOCKTIMEVERIFY`` / ``OP_CHECKSEQUENCEVERIFY``
    需要按 5 字节解码，因为 ``1 << 31``（sequence 禁用位）必须用 5 字节才能最小化表示。
    """
    if len(data) > max_size:
        raise ScriptError("script number overflow")
    if not data:
        return 0
    if require_minimal and (data[-1] & 0x7F) == 0:
        # 末字节除符号位外全 0 => 本可以少一个字节
        if len(data) == 1 or not data[-2] & 0x80:
            raise ScriptError("non-minimally encoded script number")
    result = int.from_bytes(data, "little")
    if data[-1] & 0x80:
        result &= ~(0x80 << (8 * (len(data) - 1)))
        result = -result
    return result


def cast_to_bool(data: bytes) -> bool:
    """脚本真值判定：**负零**（如 ``0x80``）也是假，不能只判断"非空"。"""
    for index, byte in enumerate(data):
        if byte != 0:
            if index == len(data) - 1 and byte == 0x80:
                return False
            return True
    return False


# --------------------------------------------------------------------------- #
# 解析 / 序列化
# --------------------------------------------------------------------------- #


def parse_script(raw: bytes) -> list[bytes | int]:
    """把字节脚本解析成元素列表：``int`` 表示 opcode，``bytes`` 表示被推送的数据。"""
    if len(raw) > MAX_SCRIPT_SIZE:
        raise ScriptError("script exceeds maximum size")
    elements: list[bytes | int] = []
    offset = 0
    length = len(raw)
    while offset < length:
        opcode = raw[offset]
        offset += 1
        if opcode == OP_0:
            elements.append(b"")  # OP_0 就是「推送空字节串」，不是普通 opcode
            continue
        if 1 <= opcode <= 75:
            size = opcode
        elif opcode == OP_PUSHDATA1:
            if offset + 1 > length:
                raise ScriptError("OP_PUSHDATA1 truncated")
            size = raw[offset]
            offset += 1
        elif opcode == OP_PUSHDATA2:
            if offset + 2 > length:
                raise ScriptError("OP_PUSHDATA2 truncated")
            size = int.from_bytes(raw[offset:offset + 2], "little")
            offset += 2
        elif opcode == OP_PUSHDATA4:
            if offset + 4 > length:
                raise ScriptError("OP_PUSHDATA4 truncated")
            size = int.from_bytes(raw[offset:offset + 4], "little")
            offset += 4
        else:
            elements.append(opcode)
            continue
        if offset + size > length:
            raise ScriptError("push data truncated")
        elements.append(raw[offset:offset + size])
        offset += size
    return elements


def serialize_script(elements: list[bytes | int]) -> bytes:
    """把元素列表序列化回字节脚本，推送使用最小编码。"""
    out = bytearray()
    for element in elements:
        if isinstance(element, int):
            if not 0 <= element <= 0xFF:
                raise ScriptError(f"invalid opcode: {element}")
            out.append(element)
            continue
        size = len(element)
        if size == 0:
            out.append(OP_0)
        elif size == 1 and 1 <= element[0] <= 16:
            # 单字节 1..16 用 OP_1..OP_16 表达：更短，且推送的数值完全等价
            out.append(OP_1 + element[0] - 1)
        elif size == 1 and element[0] == 0x81:
            out.append(OP_1NEGATE)
        else:
            if size <= 75:
                out.append(size)
            elif size <= 0xFF:
                out.extend((OP_PUSHDATA1, size))
            elif size <= 0xFFFF:
                out.append(OP_PUSHDATA2)
                out.extend(size.to_bytes(2, "little"))
            else:
                out.append(OP_PUSHDATA4)
                out.extend(size.to_bytes(4, "little"))
            out.extend(element)
    return bytes(out)


def _push(data: bytes) -> bytes | int:
    """单个数据的最小推送元素（供构造器复用）。"""
    return serialize_script([data])


# --------------------------------------------------------------------------- #
# 标准脚本构造器
# --------------------------------------------------------------------------- #


def p2pkh_script(pubkey_hash: bytes) -> bytes:
    """``OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG``。"""
    if len(pubkey_hash) != 20:
        raise ScriptError("pubkey hash must be 20 bytes")
    return (bytes([OP_DUP, OP_HASH160]) + _push(pubkey_hash)
            + bytes([OP_EQUALVERIFY, OP_CHECKSIG]))


def p2pkh_script_sig(signature: bytes, public_key: bytes) -> bytes:
    """签名脚本：``<sig+hash_type> <pubkey>``。"""
    return serialize_script([signature, public_key])


def p2sh_script(script_hash: bytes) -> bytes:
    """``OP_HASH160 <20> OP_EQUAL``。"""
    if len(script_hash) != 20:
        raise ScriptError("script hash must be 20 bytes")
    return bytes([OP_HASH160]) + _push(script_hash) + bytes([OP_EQUAL])


def multisig_script(threshold: int, public_keys: list[bytes]) -> bytes:
    """``<m> <pub1> ... <pubn> <n> OP_CHECKMULTISIG``。"""
    if not 1 <= threshold <= len(public_keys) <= 16:
        raise ScriptError("invalid multisig threshold/pubkey count")
    elements: list[bytes | int] = [OP_1 + threshold - 1]
    elements.extend(public_keys)
    elements.append(OP_1 + len(public_keys) - 1)
    elements.append(OP_CHECKMULTISIG)
    return serialize_script(elements)


def op_return_script(data: bytes) -> bytes:
    """数据载体输出：``OP_RETURN <data>``。这类输出被共识判定为不可花费。"""
    if data and data[0] == OP_RETURN:
        raise ScriptError("data must not start with OP_RETURN")
    return bytes([OP_RETURN]) + _push(data)


# --------------------------------------------------------------------------- #
# 模式识别
# --------------------------------------------------------------------------- #


def _elements(raw: bytes) -> list[bytes | int] | None:
    try:
        return parse_script(raw)
    except ScriptError:
        return None


def is_p2pkh(raw: bytes) -> bool:
    if len(raw) != 25:
        return False
    return (raw[0] == OP_DUP and raw[1] == OP_HASH160 and raw[2] == 20
            and raw[23] == OP_EQUALVERIFY and raw[24] == OP_CHECKSIG)


def is_p2sh(raw: bytes) -> bool:
    if len(raw) != 23:
        return False
    return raw[0] == OP_HASH160 and raw[1] == 20 and raw[22] == OP_EQUAL


def is_op_return(raw: bytes) -> bool:
    return bool(raw) and raw[0] == OP_RETURN


def is_provably_unspendable(raw: bytes) -> bool:
    """``OP_RETURN`` 开头，或长度非法（超过脚本上限）—— 永不可花费。"""
    return is_op_return(raw) or len(raw) > MAX_SCRIPT_SIZE


def is_multisig(raw: bytes) -> bool:
    elements = _elements(raw)
    if not elements or elements[-1] != OP_CHECKMULTISIG:
        return False
    if len(elements) < 4:
        return False
    threshold, count = elements[0], elements[-2]
    if not isinstance(threshold, int) or not isinstance(count, int):
        return False
    if not (OP_1 <= threshold <= OP_16) or not (OP_1 <= count <= OP_16):
        return False
    return count - OP_1 + 1 == len(elements) - 3 and (threshold - OP_1 + 1) <= (count - OP_1 + 1)


def extract_op_return(raw: bytes) -> bytes | None:
    """取出 ``OP_RETURN`` 推送的数据；不是 OP_RETURN 输出时返回 ``None``。"""
    if not is_op_return(raw):
        return None
    elements = _elements(raw)
    if not elements or len(elements) < 2:
        return b""
    payload = elements[1]
    return payload if isinstance(payload, bytes) else None


# --------------------------------------------------------------------------- #
# 执行
# --------------------------------------------------------------------------- #


class Checker:
    """执行 ``OP_CHECKSIG`` 所需的交易上下文（由 ``tx`` 模块注入 sighash）。

    ``sighash(script_code, hash_type)`` 必须返回 32 字节摘要。把 sighash 计算
    留在 tx 里、把签名与栈逻辑留在 script 里，两个模块就不必互相导入。
    """

    __slots__ = ("sighash", "locktime", "sequence")

    def __init__(self, sighash, locktime: int = 0, sequence: int = 0xFFFFFFFF) -> None:
        self.sighash = sighash
        self.locktime = locktime
        self.sequence = sequence


_LOCKTIME_THRESHOLD = 500_000_000
_SEQUENCE_LOCKTIME_DISABLE = 1 << 31
_SEQUENCE_LOCKTIME_TYPE = 1 << 22
_SEQUENCE_LOCKTIME_MASK = 0x0000FFFF


def _require_stack(stack: list[bytes], count: int) -> None:
    if len(stack) < count:
        raise ScriptError("stack underflow")


def _check_locktime(required: int, checker: Checker) -> None:
    """CLTV 的完整语义：负数失败、类型必须一致、交易值必须 >= 要求值。"""
    if required < 0:
        raise ScriptError("CLTV: negative locktime")
    if (required < _LOCKTIME_THRESHOLD) != (checker.locktime < _LOCKTIME_THRESHOLD):
        raise ScriptError("CLTV: locktime type mismatch")
    if required > checker.locktime:
        raise ScriptError("CLTV: locktime not satisfied")


def _check_sequence(required: int, checker: Checker) -> None:
    """CSV 的完整语义：禁用位、类型位一致、相对高度必须被满足。"""
    if required < 0:
        raise ScriptError("CSV: negative sequence")
    if required & _SEQUENCE_LOCKTIME_DISABLE:
        return
    if checker.sequence & _SEQUENCE_LOCKTIME_DISABLE:
        raise ScriptError("CSV: input sequence has the disable flag set")
    if (required & _SEQUENCE_LOCKTIME_TYPE) != (checker.sequence & _SEQUENCE_LOCKTIME_TYPE):
        raise ScriptError("CSV: sequence type mismatch")
    masked_required = required & _SEQUENCE_LOCKTIME_MASK
    masked_actual = checker.sequence & _SEQUENCE_LOCKTIME_MASK
    if masked_required > masked_actual:
        raise ScriptError("CSV: relative timelock not satisfied")


def _find_and_delete(script_code: bytes, signature: bytes) -> bytes:
    """``OP_CODESEPARATOR`` 之后的脚本里，要删掉签名自身的推送（legacy 规则）。"""
    if not signature:
        return script_code
    for element in (signature, signature[:-1]):
        if not element:
            continue
        push = _push(element)
        if push in script_code:
            return script_code.replace(push, b"")
    return script_code


def _op_checksig(stack: list[bytes], checker: Checker, script_code: bytes) -> bool:
    """栈序与 Bitcoin 一致：**栈顶是公钥，下面是签名**。"""
    _require_stack(stack, 2)
    public_key = stack.pop()
    signature = stack.pop()
    if not signature or not public_key:
        return False
    if not isinstance(signature, (bytes, bytearray)) or not isinstance(public_key, (bytes, bytearray)):
        raise ScriptError("CHECKSIG expects byte strings")
    hash_type = signature[-1]
    if hash_type != 1:  # 仅支持 SIGHASH_ALL
        raise ScriptError(f"unsupported sighash type: {hash_type}")
    digest = checker.sighash(_find_and_delete(script_code, bytes(signature)), hash_type)
    return verify(digest, bytes(signature[:-1]), bytes(public_key))


def _apply_opcode(opcode: int, stack: list[bytes], altstack: list[bytes], checker: Checker,
                  script_code: bytes) -> None:
    """执行单个 opcode，就地修改 ``stack`` / ``altstack``。

    条件指令（``IF/NOTIF/ELSE/ENDIF``）由 :func:`run_script` 的循环处理，因为
    「是否执行」是脚本级状态，而不是单个 opcode 能决定的事情。
    """

    def pop_num() -> int:
        _require_stack(stack, 1)
        return decode_num(stack.pop())

    def push_num(value: int) -> None:
        stack.append(encode_num(value))

    def push_bool(flag: bool) -> None:
        stack.append(b"\x01" if flag else b"")

    if OP_1 <= opcode <= OP_16:
        stack.append(encode_num(opcode - OP_1 + 1))
        return
    if opcode == OP_1NEGATE:
        stack.append(encode_num(-1))
        return
    if opcode == OP_TOALTSTACK:
        _require_stack(stack, 1)
        altstack.append(stack.pop())
    elif opcode == OP_FROMALTSTACK:
        if not altstack:
            raise ScriptError("alt stack underflow")
        stack.append(altstack.pop())
    elif opcode == OP_DROP:
        _require_stack(stack, 1)
        stack.pop()
    elif opcode == OP_2DROP:
        _require_stack(stack, 2)
        stack.pop()
        stack.pop()
    elif opcode == OP_DUP:
        _require_stack(stack, 1)
        stack.append(stack[-1])
    elif opcode == OP_2DUP:
        _require_stack(stack, 2)
        stack.extend(stack[-2:])
    elif opcode == OP_NIP:
        _require_stack(stack, 2)
        del stack[-2]
    elif opcode == OP_OVER:
        _require_stack(stack, 2)
        stack.append(stack[-2])
    elif opcode == OP_SWAP:
        _require_stack(stack, 2)
        stack[-2], stack[-1] = stack[-1], stack[-2]
    elif opcode == OP_ROT:
        _require_stack(stack, 3)
        stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-3]
    elif opcode == OP_TUCK:
        _require_stack(stack, 2)
        stack.insert(len(stack) - 2, stack[-1])
    elif opcode == OP_SIZE:
        _require_stack(stack, 1)
        stack.append(encode_num(len(stack[-1])))
    elif opcode == OP_DEPTH:
        stack.append(encode_num(len(stack)))
    elif opcode == OP_IFDUP:
        _require_stack(stack, 1)
        if cast_to_bool(stack[-1]):
            stack.append(stack[-1])
    elif opcode == OP_VERIFY:
        _require_stack(stack, 1)
        if not cast_to_bool(stack.pop()):
            raise ScriptError("VERIFY failed")
    elif opcode == OP_RETURN:
        raise ScriptError("OP_RETURN encountered: output is unspendable")
    elif opcode == OP_EQUAL or opcode == OP_EQUALVERIFY:
        _require_stack(stack, 2)
        equal = stack.pop() == stack.pop()
        if opcode == OP_EQUALVERIFY:
            if not equal:
                raise ScriptError("EQUALVERIFY failed")
        else:
            push_bool(equal)
    elif opcode in (OP_ADD, OP_SUB):
        _require_stack(stack, 2)
        right, left = pop_num(), pop_num()
        push_num(left + right if opcode == OP_ADD else left - right)
    elif opcode == OP_1ADD:
        push_num(pop_num() + 1)
    elif opcode == OP_1SUB:
        push_num(pop_num() - 1)
    elif opcode == OP_NEGATE:
        push_num(-pop_num())
    elif opcode == OP_ABS:
        push_num(abs(pop_num()))
    elif opcode == OP_NOT:
        push_bool(pop_num() == 0)
    elif opcode == OP_0NOTEQUAL:
        push_bool(pop_num() != 0)
    elif opcode in (OP_BOOLAND, OP_BOOLOR):
        _require_stack(stack, 2)
        right, left = pop_num(), pop_num()
        push_bool((left != 0 and right != 0) if opcode == OP_BOOLAND else (left != 0 or right != 0))
    elif opcode in (OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL):
        _require_stack(stack, 2)
        right, left = pop_num(), pop_num()
        equal = left == right
        if opcode == OP_NUMEQUALVERIFY:
            if not equal:
                raise ScriptError("NUMEQUALVERIFY failed")
        else:
            push_bool(equal if opcode == OP_NUMEQUAL else not equal)
    elif opcode in (OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL):
        _require_stack(stack, 2)
        right, left = pop_num(), pop_num()
        if opcode == OP_LESSTHAN:
            push_bool(left < right)
        elif opcode == OP_GREATERTHAN:
            push_bool(left > right)
        elif opcode == OP_LESSTHANOREQUAL:
            push_bool(left <= right)
        else:
            push_bool(left >= right)
    elif opcode in (OP_MIN, OP_MAX):
        _require_stack(stack, 2)
        right, left = pop_num(), pop_num()
        push_num(min(left, right) if opcode == OP_MIN else max(left, right))
    elif opcode == OP_WITHIN:
        _require_stack(stack, 3)
        maximum, minimum, value = pop_num(), pop_num(), pop_num()
        push_bool(minimum <= value < maximum)
    elif opcode in (OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256):
        _require_stack(stack, 1)
        target = stack.pop()
        if opcode == OP_RIPEMD160:
            stack.append(ripemd160(target))
        elif opcode == OP_SHA1:
            raise ScriptError("OP_SHA1 is not implemented in this engine")
        elif opcode == OP_SHA256:
            stack.append(sha256(target))
        elif opcode == OP_HASH160:
            stack.append(hash160(target))
        else:
            stack.append(hash256(target))
    elif opcode == OP_CHECKSIG or opcode == OP_CHECKSIGVERIFY:
        ok = _op_checksig(stack, checker, script_code)
        if opcode == OP_CHECKSIGVERIFY:
            if not ok:
                raise ScriptError("CHECKSIGVERIFY failed")
        else:
            push_bool(ok)
    elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
        _require_stack(stack, 1)
        key_count = decode_num(stack.pop())
        if not 0 <= key_count <= 20:
            raise ScriptError("invalid multisig key count")
        _require_stack(stack, key_count + 1)
        public_keys = [stack.pop() for _ in range(key_count)]
        signature_count = decode_num(stack.pop())
        if not 0 <= signature_count <= key_count:
            raise ScriptError("invalid multisig signature count")
        _require_stack(stack, signature_count + 1)
        signatures = [stack.pop() for _ in range(signature_count)]
        # 著名的 off-by-one：CHECKMULTISIG 会多弹一个元素（中本聪留下的 bug，必须兼容）
        _require_stack(stack, 1)
        stack.pop()

        digest_cache: dict[int, bytes] = {}
        signature_index = 0
        key_index = 0
        success = True
        while success and signature_index < signature_count:
            signature = signatures[signature_index]
            hash_type = signature[-1] if signature else 0
            if hash_type != 1:
                raise ScriptError("unsupported sighash type in multisig")
            if hash_type not in digest_cache:
                digest_cache[hash_type] = checker.sighash(_find_and_delete(script_code, signature), hash_type)
            digest = digest_cache[hash_type]
            while key_index < key_count:
                if verify(digest, signature[:-1], public_keys[key_index]):
                    signature_index += 1
                    key_index += 1
                    break
                key_index += 1
                if signature_count - signature_index > key_count - key_index:
                    success = False
                    break
            else:
                success = False
        if opcode == OP_CHECKMULTISIGVERIFY:
            if not success:
                raise ScriptError("CHECKMULTISIGVERIFY failed")
        else:
            push_bool(success)
    elif opcode == OP_CHECKLOCKTIMEVERIFY:
        _require_stack(stack, 1)
        _check_locktime(decode_num(stack[-1], max_size=5), checker)
    elif opcode == OP_CHECKSEQUENCEVERIFY:
        _require_stack(stack, 1)
        _check_sequence(decode_num(stack[-1], max_size=5), checker)
    elif opcode == OP_NOP:
        pass
    else:
        name = _OPCODE_NAMES.get(opcode, f"0x{opcode:02x}")
        raise ScriptError(f"unsupported opcode: {name}")


def run_script(script: bytes, stack: list[bytes], checker: Checker, script_code: bytes | None = None) -> None:
    """执行脚本，就地修改 ``stack``。失败抛 :class:`ScriptError`。

    条件执行遵循 Bitcoin 的语义：``conditions`` 里只要有一个 ``False``，整段脚本
    就处于「不执行」状态——不执行的 opcode 一律跳过，但 **IF/ELSE/ENDIF 的嵌套
    结构仍要跟踪**，否则条件分支会静默跑偏。未生效分支里的 ``IF`` 不弹栈（因为
    栈上根本没有对应的值），直接压入 ``False``。
    """
    if len(script) > MAX_SCRIPT_SIZE:
        raise ScriptError("script exceeds maximum size")
    if script_code is None:
        script_code = script

    elements = parse_script(script)
    altstack: list[bytes] = []
    conditions: list[bool] = []

    def executing() -> bool:
        return all(conditions)

    for element in elements:
        if isinstance(element, bytes):
            if executing():
                if len(stack) + len(altstack) >= MAX_STACK_ITEMS:
                    raise ScriptError("stack size limit exceeded")
                stack.append(element)
            continue

        if element in (OP_IF, OP_NOTIF):
            if executing():
                _require_stack(stack, 1)
                value = cast_to_bool(stack.pop())
                conditions.append(not value if element == OP_NOTIF else value)
            else:
                conditions.append(False)  # 父分支未执行：只记嵌套，不弹栈
            continue
        if element == OP_ELSE:
            if not conditions:
                raise ScriptError("ELSE without IF")
            conditions[-1] = not conditions[-1]
            continue
        if element == OP_ENDIF:
            if not conditions:
                raise ScriptError("ENDIF without IF")
            conditions.pop()
            continue

        if not executing():
            continue
        if len(stack) + len(altstack) >= MAX_STACK_ITEMS:
            raise ScriptError("stack size limit exceeded")
        _apply_opcode(element, stack, altstack, checker, script_code)

    if conditions:
        raise ScriptError("unbalanced IF/ENDIF")


def verify_input(script_sig: bytes, script_pubkey: bytes, checker: Checker) -> bool:
    """验证一个输入能否花费 ``script_pubkey``；P2SH 走两阶段执行。

    返回 ``False`` 表示「不合法」，不抛异常——调用方需要把它当作 consensus
    failure 处理并给出明确原因，而不是让异常穿透整个区块校验。
    """
    if is_provably_unspendable(script_pubkey):
        return False
    try:
        stack: list[bytes] = []
        run_script(script_sig, stack, checker)
        if is_p2sh(script_pubkey):
            # 阶段一：只在副本上验证 redeem script 的哈希与 OP_EQUAL 结果
            script_hash_stack = list(stack)
            run_script(script_pubkey, script_hash_stack, checker)
            if not script_hash_stack or not cast_to_bool(script_hash_stack[-1]):
                return False
            if not stack:
                return False
            redeem_script = stack.pop()
            # 阶段二：用 redeem script 作为 scriptCode 执行剩余栈
            run_script(redeem_script, stack, checker, script_code=redeem_script)
        else:
            run_script(script_pubkey, stack, checker)
        return bool(stack) and cast_to_bool(stack[-1])
    except (ScriptError, ValueError):
        return False

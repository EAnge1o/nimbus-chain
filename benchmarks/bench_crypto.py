"""密码学原语基准：纯 Python 实现 vs ``hashlib``，以及 ECDSA 的真实耗时。

用法（在项目根目录）：``python benchmarks/bench_crypto.py [--time 0.3]``

为什么这个基准值得存在：项目主张"零依赖、全部手写"，最容易被质疑的就是
"纯 Python 会不会慢到不可用"。这里把答案量化出来——哈希确实慢两个数量级，
但**签名与验签完全够用**，而挖矿用快路径后差异可以忽略。
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from nimbus_chain import enable_utf8_console  # noqa: E402
from nimbus_chain.crypto import (  # noqa: E402
    b58check_encode,
    b58decode,
    b58encode,
    hash256,
    ripemd160,
    sha256,
    sha256_pure,
)
from nimbus_chain.merkle import merkle_proof, merkle_root  # noqa: E402
from nimbus_chain.secp256k1 import PrivateKey, scalar_mult, sign, verify  # noqa: E402
from nimbus_chain.script import (  # noqa: E402
    multisig_script,
    p2pkh_script,
    p2pkh_script_sig,
    verify_input,
)
from nimbus_chain.tx import Transaction, TxIn, TxOut, checker_for  # noqa: E402


def measure(func, *, min_time: float, max_loops: int = 1 << 22) -> tuple[int, float]:
    """反复调用 ``func`` 直到累计耗时达到 ``min_time``，返回 ``(次数, 耗时)``。"""
    loops = 1
    while True:
        start = time.perf_counter()
        for _ in range(loops):
            func()
        elapsed = time.perf_counter() - start
        if elapsed >= min_time or loops >= max_loops:
            return loops, elapsed
        loops = max(loops * 2, int(loops * min_time / max(elapsed, 1e-9)) + 1)


def per_second(func, *, min_time: float) -> float:
    loops, elapsed = measure(func, min_time=min_time)
    return loops / elapsed


def main() -> int:
    enable_utf8_console()      # 输出被重定向时 Windows 会退回 cp1252，打印中文会崩
    parser = argparse.ArgumentParser(description="NimbusChain 密码学基准")
    parser.add_argument("--time", type=float, default=0.3, help="每项测量的最短时长（秒）")
    args = parser.parse_args()
    budget = args.time

    message = b"the quick brown fox jumps over the lazy dog" * 2      # 86 字节
    block = message[:60]
    print("NimbusChain 密码学原语基准")
    print(f"每项测量至少 {budget:.2f} 秒；纯 Python 哈希按 64 字节块线性估算吞吐")
    print()

    results: list[tuple[str, str, str, str]] = []

    # --- SHA-256 单次调用 ------------------------------------------------- #
    pure_rate = per_second(lambda: sha256_pure(message), min_time=budget)
    fast_rate = per_second(lambda: sha256(message), min_time=budget)
    results.append(("sha256 单次（86 B）", f"{pure_rate:,.0f} 次/秒", f"{fast_rate:,.0f} 次/秒",
                    f"{fast_rate / pure_rate:.1f}x"))

    # --- SHA-256 吞吐 ----------------------------------------------------- #
    pure_mb = pure_rate * len(message) / (1024 * 1024)
    fast_mb = fast_rate * len(message) / (1024 * 1024)
    results.append(("sha256 吞吐", f"{pure_mb:.2f} MB/s", f"{fast_mb:.1f} MB/s",
                    f"{fast_mb / pure_mb:.1f}x"))

    # --- SHA-256d（挖矿与 txid 用的） ------------------------------------- #
    hash256_rate = per_second(lambda: hash256(block), min_time=budget)
    results.append(("sha256d（80 B 区块头）", "—", f"{hash256_rate:,.0f} 次/秒", "—"))

    # --- RIPEMD-160 ------------------------------------------------------- #
    ripemd_rate = per_second(lambda: ripemd160(message), min_time=budget)
    reference = hashlib.new("ripemd160")
    reference.update(message)
    try:
        openssl_rate = per_second(lambda: hashlib.new("ripemd160", message).digest(),
                                  min_time=budget)
        openssl_text = f"{openssl_rate:,.0f} 次/秒"
    except (ValueError, TypeError):
        openssl_text = "本平台 OpenSSL 未提供"
    results.append(("ripemd160（86 B）", f"{ripemd_rate:,.0f} 次/秒", openssl_text, "—"))

    # --- secp256k1 -------------------------------------------------------- #
    secret = 0x5EC884F0C2E8B7E5B1A0B7A6D5A3C1E9F0A1B2C3D4E5F60718293A4B5C6D7E8F
    key = PrivateKey(secret)
    public_key = key.public_key().to_bytes()
    digest = hash256(b"a message to sign")
    signature = key.sign(digest).to_der()

    scalar_rate = per_second(lambda: scalar_mult(123456789), min_time=budget)
    sign_rate = per_second(lambda: sign(digest, secret), min_time=budget)
    verify_rate = per_second(lambda: verify(digest, signature, public_key), min_time=budget)
    results.append(("secp256k1 标量乘 k·G", f"{scalar_rate:,.0f} 次/秒",
                    f"{1000 / scalar_rate:.2f} ms/次", "—"))
    results.append(("ECDSA 签名（RFC 6979）", f"{sign_rate:,.0f} 次/秒",
                    f"{1000 / sign_rate:.2f} ms/次", "—"))
    results.append(("ECDSA 验签", f"{verify_rate:,.0f} 次/秒",
                    f"{1000 / verify_rate:.2f} ms/次", "—"))

    # --- Base58Check ------------------------------------------------------ #
    payload = bytes(range(20))
    encode_rate = per_second(lambda: b58check_encode(payload), min_time=budget)
    address = b58check_encode(payload)
    decode_rate = per_second(lambda: b58decode(address), min_time=budget)
    results.append(("Base58Check 编码", f"{encode_rate:,.0f} 次/秒", "—", "—"))
    results.append(("Base58 解码", f"{decode_rate:,.0f} 次/秒", "—", "—"))

    # --- Merkle ----------------------------------------------------------- #
    for count in (16, 256, 4096):
        leaves = [hash256(index.to_bytes(4, "big")) for index in range(count)]
        rate = per_second(lambda leaves=leaves: merkle_root(leaves), min_time=budget)
        proof_rate = per_second(lambda leaves=leaves: merkle_proof(leaves, count // 2),
                                min_time=budget)
        results.append((f"Merkle 根（{count} 叶）", f"{rate:,.0f} 次/秒",
                        f"路径 {proof_rate:,.0f} 次/秒", "—"))

    # --- 完整 P2PKH 脚本验证（含一次验签） -------------------------------- #
    script_pubkey = p2pkh_script(key.public_key().hash160())
    spend = Transaction(1, [TxIn(b"\x11" * 32, 0, b"")], [TxOut(900, script_pubkey)])
    sighash = spend.sighash(0, script_pubkey)
    spend.inputs[0].script_sig = p2pkh_script_sig(
        key.sign(sighash).to_der() + b"\x01", public_key)
    checker = checker_for(spend, 0)
    verify_input_rate = per_second(
        lambda: verify_input(spend.inputs[0].script_sig, script_pubkey, checker),
        min_time=budget)
    results.append(("完整 P2PKH 输入验证", f"{verify_input_rate:,.0f} 次/秒",
                    f"{1000 / verify_input_rate:.2f} ms/次", "—"))

    # --- 多签 ------------------------------------------------------------- #
    keys = [PrivateKey(seed).public_key().to_bytes() for seed in (1, 2, 3)]
    redeem = multisig_script(2, keys)
    multisig_spend = Transaction(1, [TxIn(b"\x22" * 32, 0, b"")],
                                 [TxOut(900, p2pkh_script(key.public_key().hash160()))])
    multisig_digest = multisig_spend.sighash(0, redeem)
    signatures = [PrivateKey(seed).sign(multisig_digest).to_der() + b"\x01" for seed in (1, 2)]
    from nimbus_chain.script import serialize_script
    multisig_spend.inputs[0].script_sig = serialize_script([b"", *signatures])
    multisig_checker = checker_for(multisig_spend, 0)
    multisig_rate = per_second(
        lambda: verify_input(multisig_spend.inputs[0].script_sig, redeem, multisig_checker),
        min_time=budget)
    results.append(("多签 2-of-3 输入验证", f"{multisig_rate:,.0f} 次/秒",
                    f"{1000 / multisig_rate:.2f} ms/次", "—"))

    width = max(len(row[0]) for row in results)
    print(f"{'操作':<{width}}  {'纯 Python':>20}  {'hashlib / 参考':>20}  {'倍率':>8}")
    print("-" * (width + 54))
    for label, pure_text, fast_text, ratio in results:
        print(f"{label:<{width}}  {pure_text:>20}  {fast_text:>20}  {ratio:>8}")

    print()
    print("结论：")
    print(f"  * 纯 Python SHA-256 比 hashlib 慢约 {fast_rate / pure_rate:.0f} 倍"
          f"（约 {fast_rate / pure_rate / 100:.1f} 个数量级）——")
    print(f"    所以挖矿与批量哈希默认走快路径，而纯实现保留下来用于交叉验证"
          f"（tests/test_crypto.py 逐字节比对）。")
    print("  * secp256k1 没有标准库替代品，只能手写；毫秒级的签名/验签完全够用。")
    print(f"  * 单笔 P2PKH 验证约 {1000 / verify_input_rate:.2f} ms，"
          f"每秒可校验约 {verify_input_rate:,.0f} 个输入。")
    print(f"  * 挖矿哈希速率约 {hash256_rate:,.0f} 次/秒，"
          f"因此演示难度（期望 4096 次）约 {4096 / hash256_rate * 1000:.1f} ms/块。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

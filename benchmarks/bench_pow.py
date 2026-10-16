"""PoW 与链处理基准：挖矿速率、难度对照表、区块验证吞吐。

用法（在项目根目录）：``python benchmarks/bench_pow.py [--time 0.5]``

这个基准回答两个现场最常被追问的问题：

1. 「你这条链的难度是多少？」—— 给出 bits → target → 期望哈希次数 → 难度倍数的对照表。
2. 「挖一个块要多久、验证一个块要多久？」—— 挖矿必须"贵"（这是它的安全来源），
    验证必须"便宜"（否则节点跟不上）。
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from nimbus_chain import enable_utf8_console  # noqa: E402
from nimbus_chain.block import (  # noqa: E402
    Block,
    BlockHeader,
    bits_to_target,
    block_work,
    mine,
    target_to_bits,
)
from nimbus_chain.chain import Chain, ChainParams, create_genesis_block  # noqa: E402
from nimbus_chain.crypto import hash256  # noqa: E402
from nimbus_chain.merkle import merkle_root  # noqa: E402
from nimbus_chain.script import p2pkh_script  # noqa: E402
from nimbus_chain.secp256k1 import PrivateKey  # noqa: E402
from nimbus_chain.tx import Transaction, TxOut  # noqa: E402
from nimbus_chain.wallet import Wallet  # noqa: E402

PARAMS = ChainParams(retarget_interval=1_000, coinbase_maturity=1)
MINER = PrivateKey(0xF00D)
MINER_SCRIPT = p2pkh_script(MINER.public_key().hash160())


def hash_rate(budget: float) -> float:
    """测量每秒能做多少次 sha256d（80 字节区块头）。"""
    header = BlockHeader(1, b"\x11" * 32, b"\x22" * 32, 1_700_000_000,
                         PARAMS.pow_limit_bits).serialize()
    loops = 0
    start = time.perf_counter()
    while time.perf_counter() - start < budget:
        for _ in range(1000):
            hash256(header)
        loops += 1000
    return loops / (time.perf_counter() - start)


def mine_one(bits: int, budget: float) -> tuple[int, float, bool]:
    """挖一个指定难度的空块，返回 ``(实际尝试次数, 耗时, 是否在预算内成功)``。"""
    coinbase = Transaction(1, [], [])
    from nimbus_chain.tx import coinbase_transaction
    coinbase = coinbase_transaction(1, 1, MINER_SCRIPT, b"bench")
    header = BlockHeader(1, b"\x33" * 32, merkle_root([coinbase.txid()]),
                         1_700_000_000, bits)
    block = Block(header, [coinbase])
    target = bits_to_target(bits)
    start = time.perf_counter()
    attempts = 0
    while attempts < 50_000_000:
        block.header.nonce = attempts
        attempts += 1
        if int.from_bytes(block.header.hash(), "big") <= target:
            return attempts, time.perf_counter() - start, True
        if time.perf_counter() - start > budget * 20:
            return attempts, time.perf_counter() - start, False
    return attempts, time.perf_counter() - start, False


def main() -> int:
    enable_utf8_console()      # 输出被重定向时 Windows 会退回 cp1252，打印中文会崩
    parser = argparse.ArgumentParser(description="NimbusChain PoW 基准")
    parser.add_argument("--time", type=float, default=0.5, help="每项测量时长（秒）")
    parser.add_argument("--rounds", type=int, default=24, help="挖矿采样轮数")
    args = parser.parse_args()

    print("NimbusChain PoW / 链处理基准")
    print()

    # --- 难度对照表 ------------------------------------------------------- #
    print("一、难度对照表（compact bits → 目标值 → 期望哈希次数）")
    print(f"{'bits':>12}  {'目标值（前 16 位十六进制）':>26}  {'期望哈希次数':>14}  {'难度倍数':>10}")
    print("-" * 72)
    limit_target = bits_to_target(PARAMS.pow_limit_bits)
    for bits in (0x1F0FFFFF, 0x1F07FFFF, 0x1F03FFFF, 0x1F00FFFF, 0x1E7FFFFF, 0x1D00FFFF):
        target = bits_to_target(bits)
        expected = (1 << 256) // (target + 1)
        difficulty = limit_target / target
        print(f"     0x{bits:08x}  {'0x' + format(target, '064x')[:16] + '…':>26}  "
              f"{expected:>14,}  {difficulty:>9.1f}x")
    print()
    print("  注：本项目演示用的 pow limit 是 0x1f0fffff（期望约 4096 次），"
          "而 Bitcoin 主网是 0x1d00ffff（期望约 2^32 次）。")
    print()

    # --- 哈希速率 --------------------------------------------------------- #
    rate = hash_rate(args.time)
    print("二、哈希速率")
    print(f"  sha256d 速率（80 B 区块头）  {rate:,.0f} 次/秒")
    print()

    # --- 实际挖矿 --------------------------------------------------------- #
    print("三、实际挖矿（空块，逐难度）")
    print(f"{'bits':>12}  {'期望次数':>12}  {'实测次数':>12}  {'耗时':>10}  {'速率':>14}  {'结果':>6}")
    print("-" * 76)
    for bits in (0x1F0FFFFF, 0x1F07FFFF, 0x1F03FFFF):
        expected = (1 << 256) // (bits_to_target(bits) + 1)
        attempts, elapsed, solved = mine_one(bits, args.time)
        speed = attempts / elapsed if elapsed else 0
        verdict = "成功" if solved else "超时"
        print(f"     0x{bits:08x}  {expected:>12,}  {attempts:>12,}  "
              f"{elapsed * 1000:>8.1f} ms  {speed:>12,.0f} 次/s  {verdict:>6}")
    print()

    # --- 区块验证吞吐 ----------------------------------------------------- #
    print("四、区块验证吞吐（挖矿贵、验证便宜 —— 这才是 PoW 的意义）")
    chain = Chain(PARAMS)
    wallet = Wallet(name="bench", keys=[MINER])
    script = wallet.first_script()
    for _ in range(6):
        chain.add_block(chain.build_and_mine([], script))

    payments = []
    spendable = wallet.utxos(chain)
    for index in range(min(8, len(spendable))):
        key, entry = spendable[index]
        tx = wallet.create_transaction(
            chain, [TxOut(entry.value // 2, script)])
        # 手动把输入指向对应的 UTXO
        from nimbus_chain.script import p2pkh_script_sig
        tx.inputs[0].prev_txid, tx.inputs[0].prev_index = key
        dwell = tx.sighash(0, entry.tx_out.script_pubkey)
        tx.inputs[0].script_sig = p2pkh_script_sig(
            MINER.sign(dwell).to_der() + b"\x01", MINER.public_key().to_bytes())
        payments.append(tx)

    heavy = chain.build_and_mine(payments, script) if payments else chain.build_and_mine([], script)
    size = heavy.size()
    inputs = sum(len(tx.inputs) for tx in heavy.transactions)

    rounds = args.rounds
    start = time.perf_counter()
    for _ in range(rounds):
        chain._apply_block(heavy, chain.height + 1, dict(chain.utxo), validate=True)
    elapsed = time.perf_counter() - start
    per_block = elapsed / rounds

    print(f"  区块大小 / 交易数 / 输入数     {size} B / {len(heavy.transactions)} / {inputs}")
    print(f"  完整校验（含全部签名验证）     {per_block * 1000:,.2f} ms/块"
          f"  =>  {1 / per_block:,.0f} 块/秒")
    if inputs:
        print(f"  折算单个输入                   {per_block / inputs * 1000:,.2f} ms/输入")
    print()

    # --- 链规模对比 ------------------------------------------------------- #
    print("五、存储量对比（同一份信任，两种节点）")
    blockchain_bytes = sum(block.size() for block in chain.main_blocks())
    header_bytes = 80 * (chain.height + 1)
    print(f"  全节点（全部区块）             {blockchain_bytes:,} B（高度 {chain.height}）")
    print(f"  SPV 轻客户端（仅区块头）       {header_bytes:,} B（{chain.height + 1} 个区块头）")
    if blockchain_bytes:
        print(f"  轻客户端占比                   {header_bytes / blockchain_bytes * 100:.2f}%")
    print()
    print("结论：")
    print("  * 挖矿成本随难度线性增长，而验证成本与难度完全无关——这就是 PoW 的意义。")
    print(f"  * 本演示把难度调到最低（期望 {4096} 次哈希），所以挖矿只要十几毫秒；")
    print("    若把 bits 换成 Bitcoin 主网的 0x1d00ffff，挖矿期望次数会放大 100 万倍，")
    print("    而验证依然是同样的毫秒级——贵的是产出区块，不是相信区块。")
    print(f"  * 完整校验约 {per_block * 1000:.2f} ms/块（其中几乎全部是"
          f"{inputs} 次 ECDSA 验签），节点能轻松跟上出块速度。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

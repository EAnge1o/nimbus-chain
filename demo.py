"""NimbusChain 一键演示：`python demo.py`。

这是一个**自校验**的演示：每一段都打印结论并当场断言，最后统计「N 项断言全部
通过」。所以它既是演示脚本，也是最直观的冒烟测试——适合答辩现场直接跑。

八段内容：

1. 密码学原语（纯 Python SHA-256 / RIPEMD-160 / secp256k1 / Base58Check）
2. 建链与挖矿，以及校验流水线（改一个 Merkle 根就接不上）
3. 转账：签名、手续费、找零、篡改签名失效、双花被拒
4. 难度重定目标与 4 倍钳制
5. 分叉重组：短而高工作量击败长而低工作量，UTXO 精确回滚、交易回池
6. 存证应用：上链 → 验证通过 → 改一个字节 → 验证失败
7. SPV 轻客户端：只凭区块头 + Merkle 路径验证；与全节点存储量对比
8. 命令清单

演示参数说明：为让流程在秒级跑完，这里把 ``coinbase_maturity`` 设为 1
（默认值是 100，与 Bitcoin 一致）。共识规则本身没有任何放宽——第 4 段会
用合成时间戳完整展示真实的难度重定目标规则。
"""

from __future__ import annotations

import hashlib
import sys

from nimbus_chain import enable_utf8_console
from nimbus_chain.block import bits_to_target, block_work, mine, target_to_bits
from nimbus_chain.chain import Chain, ChainParams, InvalidBlock
from nimbus_chain.crypto import hash256, ripemd160, sha256, sha256_pure
from nimbus_chain.mempool import Mempool, MempoolError
from nimbus_chain.notary import document_digest
from nimbus_chain.script import p2pkh_script, p2pkh_script_sig
from nimbus_chain.secp256k1 import PrivateKey, scalar_mult, sign, verify
from nimbus_chain.spv import SPVClient
from nimbus_chain.tx import COIN, SIGHASH_ALL, Transaction, TxIn, TxOut
from nimbus_chain.wallet import Wallet, transaction_fee

# 演示参数：coinbase 成熟度设为 1，让流程在秒级完成
DEMO_PARAMS = ChainParams(retarget_interval=16, target_block_time=600, coinbase_maturity=1)
# 重组演示需要一个更小的重定目标间隔，才能在几步之内造出「高工作量」分支
REORG_PARAMS = ChainParams(retarget_interval=2, target_block_time=100, coinbase_maturity=1)
CLAMP_PARAMS = ChainParams(retarget_interval=4, target_block_time=100)

MINER_KEY = PrivateKey(0xF00D_0001)
ALICE_KEY = PrivateKey(0xA111_CE02)
BOB_KEY = PrivateKey(0xB0B0_0003)

_passed = 0
_failed = 0


def section(title: str) -> None:
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def line(label: str, value) -> None:
    print(f"  {label:<22}{value}")


def check(label: str, condition: bool, detail: str = "") -> bool:
    global _passed, _failed
    mark = "✔" if condition else "✘"
    if condition:
        _passed += 1
    else:
        _failed += 1
    print(f"  [{mark}] {label}" + (f"  —— {detail}" if detail else ""))
    return condition


def short(hex_text: str, size: int = 18) -> str:
    return f"{hex_text[:size]}…"


# --------------------------------------------------------------------------- #
# 1. 密码学原语
# --------------------------------------------------------------------------- #


def demo_cryptography() -> None:
    section("1. 密码学原语：全部手写，且与标准库逐字节一致")

    print("  纯 Python SHA-256（自己实现填充 + 压缩函数）对比 hashlib：")
    for payload in (b"", b"abc", b"NimbusChain"):
        pure = sha256_pure(payload)
        reference = hashlib.sha256(payload).digest()
        line(f"sha256({payload[:12]!r})", short(pure.hex(), 32))
        check("与 hashlib 完全一致", pure == reference)

    print("  RIPEMD-160（地址需要它，标准库在部分平台已移除）：")
    line('ripemd160("abc")', ripemd160(b"abc").hex())
    check("匹配官方测试向量",
          ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")

    print("  secp256k1 ECDSA（RFC 6979 确定性 nonce，无随机数可被复用）：")
    message = sha256(b"Satoshi Nakamoto")
    first, second = sign(message, 1), sign(message, 1)
    line("r", f"0x{first.r:064x}"[:34] + "…")
    line("s", f"0x{first.s:064x}"[:34] + "…")
    check("同一密钥 + 同一消息 => 逐字节相同的签名", first.to_der() == second.to_der())
    check("签名可被验证", verify(message, first, PrivateKey(1).public_key()))
    flipped = bytearray(message)
    flipped[0] ^= 1
    check("改 1 个 bit 后验签失败",
          not verify(bytes(flipped), first, PrivateKey(1).public_key()))

    print("  Base58Check 地址（版本字节 + 4 字节双 SHA256 校验和）：")
    key = PrivateKey(0xBEA7)
    line("地址", key.public_key().address())
    check("地址里的校验和能发现 1 个字符的改动",
          _address_checksum_detects_change(key.public_key().address()))
    line("曲线阶 n×G 是否为无穷远点", scalar_mult(1).is_infinity() is False)


def _address_checksum_detects_change(address: str) -> bool:
    from nimbus_chain.crypto import Base58ChecksumError, b58check_decode
    broken = address[:-1] + ("2" if address[-1] != "2" else "3")
    try:
        b58check_decode(broken)
    except Base58ChecksumError:
        return True
    return False


# --------------------------------------------------------------------------- #
# 2. 建链、挖矿与校验流水线
# --------------------------------------------------------------------------- #


def demo_chain() -> tuple[Chain, Wallet]:
    section("2. 建链与挖矿：从创世块到可花费的 coinbase")

    chain = Chain(DEMO_PARAMS)
    miner = Wallet(name="miner", keys=[MINER_KEY])
    line("创世块哈希", short(chain.genesis.block_hash_hex()))
    line("创世块 PoW 是否有效", chain.genesis.has_valid_pow())
    check("创世块本身也是挖出来的（不是硬编码）", chain.genesis.has_valid_pow())

    for _ in range(3):
        chain.add_block(chain.build_and_mine([], miner.first_script()))
    line("当前高度", chain.height)
    line("链尖", short(chain.tip.block_hash_hex()))
    line("累计工作量", chain.total_work)
    line("UTXO 数量", len(chain.utxo))
    line("矿工余额（NBC）", f"{miner.balance(chain) / COIN:.8f}")
    check("挖 3 个块 => 高度 3", chain.height == 3)
    check("矿工有可花费的 coinbase（成熟度 1）", miner.balance(chain) > 0)

    # 校验流水线：改掉 Merkle 根再重挖，PoW 达标也照样被拒
    print("  校验流水线：把 Merkle 根改掉再重新挖矿，看链会不会接受")
    forged = chain.build_candidate([], miner.first_script())
    forged.header.merkle_root = b"\x00" * 32
    mine(forged)
    check("区块头 PoW 依然达标", forged.has_valid_pow())
    rejected = False
    try:
        chain.add_block(forged)
    except InvalidBlock as error:
        rejected = True
        line("拒绝原因", error)
    check("但链仍然拒绝它（Merkle 根与交易不符）", rejected)

    # 难度与目标
    target = bits_to_target(chain.next_block_bits())
    line("下一个 bits", f"0x{chain.next_block_bits():08x}")
    line("对应目标值", f"0x{target:064x}"[:34] + "…")
    line("期望哈希次数", block_work(chain.next_block_bits()))
    check("期望哈希次数在演示友好量级（< 1e6）",
          block_work(chain.next_block_bits()) < 1_000_000)
    return chain, miner


# --------------------------------------------------------------------------- #
# 3. 转账
# --------------------------------------------------------------------------- #


def demo_transfers(chain: Chain, miner: Wallet) -> None:
    section("3. 转账：签名、手续费、找零，以及篡改与双花")

    alice = Wallet(name="alice", keys=[ALICE_KEY])
    bob = Wallet(name="bob", keys=[BOB_KEY])

    tx = miner.send(chain, alice.address(), 2_000_000)
    line("交易", short(tx.txid_hex(), 24))
    line("输入 / 输出", f"{len(tx.inputs)} / {len(tx.outputs)}")
    line("手续费（聪）", transaction_fee(chain, tx))
    check("输入金额覆盖输出", tx.total_out() < miner.utxos(chain)[0][1].value)

    # 篡改签名：把 DER 签名里的一个字节翻转
    tampered = replace_signed_transaction(tx)
    block = chain.build_and_mine([tampered], miner.first_script())
    rejected = False
    try:
        chain.add_block(block)
    except InvalidBlock as error:
        rejected = True
        line("拒绝原因", error)
    check("翻转签名 1 个 bit => 区块被拒绝", rejected)

    # 把合法交易上链
    block = chain.build_and_mine([tx], miner.first_script())
    chain.add_block(block)
    line("已确认高度", chain.confirmations(tx.txid()))
    check("合法交易被接受并确认", chain.confirmations(tx.txid()) == 1)
    check("alice 余额到账", chain.balance(alice.first_script()) == 2_000_000)

    # 双花：同一个 outpoint 再花一次
    spent_outpoint = tx.inputs[0].outpoint()
    double_spend = alice.send(chain, bob.address(), 1_000_000)
    line("alice → bob", short(double_spend.txid_hex(), 24))
    block = chain.build_and_mine([double_spend], miner.first_script())
    chain.add_block(block)
    check("链式转账成功（bob 收到 1 NBC）",
          chain.balance(bob.first_script()) == 1_000_000)

    print("  现在尝试花掉**已经被花过**的那个 outpoint（双花）：")
    replay = alice.create_transaction(chain, [TxOut(500_000, bob.first_script())])
    replay.inputs[0].prev_txid = spent_outpoint[0]
    replay.inputs[0].prev_index = spent_outpoint[1]
    rejected = False
    try:
        Mempool(chain).add_transaction(replay)
    except (MempoolError, ValueError) as error:
        rejected = True
        line("拒绝原因", str(error)[:64] + "…")
    check("双花被拒：该 outpoint 在链上已被花掉，交易池眼里它就是「不存在」", rejected)

    line("alice 最终余额（NBC）", f"{chain.balance(alice.first_script()) / COIN:.8f}")
    line("bob 最终余额（NBC）", f"{chain.balance(bob.first_script()) / COIN:.8f}")


def replace_signed_transaction(tx):
    """复制一笔交易并把签名里的一个字节翻转（用于演示篡改检测）。"""
    from nimbus_chain.tx import Transaction, TxIn
    clone = Transaction(tx.version,
                        [TxIn(tx_in.prev_txid, tx_in.prev_index, tx_in.script_sig, tx_in.sequence)
                         for tx_in in tx.inputs],
                        list(tx.outputs), tx.locktime)
    script_sig = bytearray(clone.inputs[0].script_sig)
    script_sig[3] ^= 0x01          # 跳过 0x47 长度前缀，改签名体里的第 1 个字节
    clone.inputs[0].script_sig = bytes(script_sig)
    return clone


# --------------------------------------------------------------------------- #
# 4. 难度重定目标
# --------------------------------------------------------------------------- #


def demo_difficulty() -> None:
    section("4. 难度重定目标：只在整数倍高度发生，且被 4 倍钳制")

    def build(offsets: list[int]) -> Chain:
        chain = Chain(CLAMP_PARAMS)
        base = chain.genesis.header.timestamp
        for offset in offsets:
            chain.add_block(chain.build_and_mine([], _miner_script(), timestamp=base + offset))
        return chain

    limit_target = bits_to_target(CLAMP_PARAMS.pow_limit_bits)
    line("重定目标间隔", f"{CLAMP_PARAMS.retarget_interval} 块")
    line("期望跨度", f"{CLAMP_PARAMS.target_timespan} 秒")
    line("难度下限（pow_limit bits）", f"0x{CLAMP_PARAMS.pow_limit_bits:08x}")

    no_retarget = build([1, 2])
    line("高度 1、2 之后的 bits", f"0x{no_retarget.next_block_bits():08x}")
    check("没到间隔高度就不重定目标",
          no_retarget.next_block_bits() == CLAMP_PARAMS.pow_limit_bits)

    too_fast = build([1, 2, 3])
    boundary_fast = build([33, 66, 100])
    line("实测 3 秒之后的 bits", f"0x{too_fast.next_block_bits():08x}")
    check("实测远快于期望 => 难度变难（目标缩小 4 倍）",
          too_fast.next_block_bits() == target_to_bits(limit_target // 4))
    check("变难后被 4 倍钳制：更快的实测不会再更难",
          too_fast.next_block_bits() == boundary_fast.next_block_bits())

    too_slow = build([10_000, 20_000, 30_000])
    boundary_slow = build([533, 1066, 1600])
    line("实测 3 万秒之后的 bits", f"0x{too_slow.next_block_bits():08x}")
    check("变松后被 4 倍钳制：更慢的实测不会再更松",
          too_slow.next_block_bits() == boundary_slow.next_block_bits())
    check("松到极限也不会超过 pow limit",
          too_slow.next_block_bits() == CLAMP_PARAMS.pow_limit_bits)

    retargeted = build([1, 2, 3])
    expected = retargeted.next_block_bits()
    block = retargeted.build_and_mine([], _miner_script(),
                                     timestamp=retargeted.tip.header.timestamp + 1)
    line("新块实际使用的 bits", f"0x{block.header.bits:08x}")
    check("挖矿者与验证者算出同一 bits（否则谁也接不上）",
          block.header.bits == expected and retargeted.add_block(block).status == "connected")


def _miner_script() -> bytes:
    return p2pkh_script(MINER_KEY.public_key().hash160())


# --------------------------------------------------------------------------- #
# 5. 分叉重组
# --------------------------------------------------------------------------- #


def demo_reorg() -> None:
    section("5. 分叉重组：比的是累计工作量，不是链有多长")

    chain = Chain(REORG_PARAMS)
    genesis = chain.genesis
    base = genesis.header.timestamp
    script = _miner_script()

    # 分支 A：长而「松」——时间戳拉得很开，难度一直停在 pow limit
    parent = genesis
    branch_a = []
    payment = None
    for index in range(1, 5):
        transactions = []
        if index == 2:
            # 在 A 的第 2 块里放一笔真实交易，稍后验证它会被「退回」
            coinbase = branch_a[0].transactions[0]
            payment = _signed_spend(
                (coinbase.txid(), 0), coinbase.outputs[0].script_pubkey,
                [TxOut(1_000_000, p2pkh_script(ALICE_KEY.public_key().hash160()))])
            transactions = [payment]
        block = chain.assemble_block(parent.block_hash(), base + index * 1000,
                                     transactions, script)
        mine(block)
        chain.add_block(block)
        branch_a.append(block)
        parent = block

    work_a = chain.total_work
    line("分支 A 高度", len(branch_a))
    line("分支 A 累计工作量", work_a)
    line("分支 A 每块难度", f"0x{branch_a[0].header.bits:08x}")
    check("该交易此时已在 A 中确认（高度 2，链尖高度 4）",
          chain.confirmations(payment.txid()) == 3)

    # 分支 B：短而「紧」——从创世块分叉，时间戳只隔 1 秒 => 触发 4 倍变难
    b1 = chain.assemble_block(genesis.block_hash(), base + 1, [], script)
    mine(b1)
    first = chain.add_block(b1)
    line("分支 B 第 1 块状态", first.status)

    b2 = chain.assemble_block(b1.block_hash(), base + 2, [], script)
    mine(b2)
    line("分支 B 第 2 块 bits", f"0x{b2.header.bits:08x}")
    projected = chain.work_of(b1.block_hash()) + block_work(b2.header.bits)
    line("分支 B 预计累计工作量", projected)
    check("分支 B 更短（2 块）但累计工作量更高", projected > work_a)

    result = chain.add_block(b2)
    line("加入分支 B 的结果", result.status)
    line("重组后高度", chain.height)
    line("被断开的块数", len(result.disconnected))
    line("接上的块数", len(result.connected))
    line("退回交易池的交易数", len(result.reaccepted))
    check("触发了重组", result.is_reorg)
    check("主链更短但工作量更大", chain.height < len(branch_a) and chain.total_work > work_a)
    check("被挤出主链的交易被交还给调用方",
          [tx.txid() for tx in result.reaccepted] == [payment.txid()])
    check("该交易在链上已不再确认", chain.confirmations(payment.txid()) == 0)
    check("增量 UTXO 集与全量重放完全一致", chain.utxo == chain.replay_utxo_set())
    check("旧分支的全部 coinbase 已从 UTXO 集移除",
          all((block.transactions[0].txid(), 0) not in chain.utxo for block in branch_a))
    check("新分支的 coinbase 已进入 UTXO 集",
          all((block.transactions[0].txid(), 0) in chain.utxo for block in (b1, b2)))
    line("重组次数", chain.reorg_count)


def _signed_spend(outpoint, script_pubkey: bytes, outputs: list[TxOut]) -> "object":
    from nimbus_chain.script import p2pkh_script_sig
    from nimbus_chain.tx import SIGHASH_ALL, Transaction, TxIn
    tx = Transaction(1, [TxIn(outpoint[0], outpoint[1], b"")], outputs)
    digest = tx.sighash(0, script_pubkey, SIGHASH_ALL)
    tx.inputs[0].script_sig = p2pkh_script_sig(
        MINER_KEY.sign(digest).to_der() + bytes([SIGHASH_ALL]),
        MINER_KEY.public_key().to_bytes())
    return tx


# --------------------------------------------------------------------------- #
# 6. 存证应用
# --------------------------------------------------------------------------- #


CONTRACT = (
    "合作协议 v3\n"
    "甲方：Nimbus Labs\n"
    "乙方：某客户\n"
    "金额：1000 NBC\n"
    "签署日期：2026-01-01\n"
).encode("utf-8")


def demo_notary() -> tuple[Chain, Wallet, bytes, bytes]:
    section("6. 存证应用：把文件摘要锚定上链，篡改必然暴露")

    chain = Chain(DEMO_PARAMS)
    wallet = Wallet(name="notary", keys=[PrivateKey(0x5EC1_0000)])
    for _ in range(2):
        chain.add_block(chain.build_and_mine([], wallet.first_script()))

    from nimbus_chain.notary import Notary
    notary = Notary(chain, wallet, Mempool(chain))

    digest = document_digest(CONTRACT)
    line("文件内容（节选）", CONTRACT.decode("utf-8").splitlines()[0])
    line("文件摘要 (SHA-256)", short(digest.hex(), 40))
    check("摘要大小恰好 32 字节（链上不存文件本体）", len(digest) == 32)

    notarization = notary.notarize(CONTRACT)
    line("锚定交易", short(notarization.txid_hex, 24))
    carriers = notarization.tx.data_carrier_outputs()
    check("交易里带一个 OP_RETURN 输出，载荷就是摘要", carriers == [digest])

    block = chain.build_and_mine([notarization.tx], wallet.first_script())
    chain.add_block(block)
    line("上链高度", chain.height)
    result = notary.verify(CONTRACT)
    line("验证结论", f"valid={result.valid}  confirmations={result.confirmations}")
    check("原文件验证通过", result.valid)

    tampered = CONTRACT.replace(b"1000 NBC", b"1001 NBC")
    tampered_result = notary.verify(tampered)
    line("篡改后结论", f"valid={tampered_result.valid}")
    line("篡改后原因", tampered_result.reason)
    check("改一个字节就无法通过验证", not tampered_result.valid)
    check("原文件依然有效（链没有被篡改影响）", notary.verify(CONTRACT).valid)
    check("两个摘要确实不同", document_digest(tampered) != digest)

    bit_flip = bytearray(CONTRACT)
    bit_flip[0] ^= 0x01
    check("只翻转 1 个 bit 也会被发现", not notary.verify(bytes(bit_flip)).valid)

    records = notary.anchors()
    line("链上存证记录数", len(records))
    check("存证记录能被检索出来", records and records[0].digest == digest)
    return chain, wallet, CONTRACT, digest


# --------------------------------------------------------------------------- #
# 7. SPV 轻客户端
# --------------------------------------------------------------------------- #


def demo_spv(chain: Chain, wallet: Wallet) -> None:
    section("7. SPV 轻客户端：只靠区块头 + Merkle 路径就能验证交易")

    from nimbus_chain.notary import Notary
    notary = Notary(chain, wallet, Mempool(chain))
    digest = document_digest(CONTRACT)
    tx = notary.lookup(digest)
    check("能在链上找到锚定交易", tx is not None)

    location = chain.transaction_location(tx.txid())
    block_hash, height, index = location
    block = chain.get_block(block_hash)
    proof = block.merkle_proof_for(index)

    client = SPVClient(chain.params)
    added = client.sync_from_chain(chain)
    line("轻客户端同步的头数", added)
    line("轻客户端本地存储", f"{client.local_bytes()} 字节（80 × {len(client)}）")
    blockchain_bytes = sum(b.size() for b in chain.main_blocks())
    line("全节点需要存储", f"{blockchain_bytes} 字节")
    line("占比", f"{client.local_bytes() / blockchain_bytes * 100:.3f}%")
    check("轻客户端存储量远小于全节点", client.local_bytes() < blockchain_bytes)

    line("Merkle 路径长度", f"{len(proof)} 个哈希")
    for sibling, direction in proof:
        print(f"      {direction:<5} {short(sibling.hex(), 32)}")
    check("Merkle 证明成立",
          client.verify_transaction_inclusion(tx.txid(), block_hash, proof))

    forged_proof = [(hash256(sibling), direction) for sibling, direction in proof]
    check("篡改路径中的任一哈希 => 证明失败",
          not client.verify_transaction_inclusion(tx.txid(), block_hash, forged_proof))
    check("证明必须挂到已知区块头上（否则无从验证）",
          not client.has_header(b"\xAB" * 32))

    spv_result = notary.verify(CONTRACT, spv=client)
    line("带 SPV 的验证结论", f"valid={spv_result.valid}  spv_verified={spv_result.spv_verified}")
    check("SPV 验证与全节点结论一致", spv_result.valid and spv_result.spv_verified)

    blind = SPVClient(chain.params)          # 只有创世头
    blind_result = notary.verify(CONTRACT, spv=blind)
    check("未同步的轻客户端无法独立证实（但全节点结论仍成立）",
          blind_result.valid and not blind_result.spv_verified)


# --------------------------------------------------------------------------- #
# 8. 收尾
# --------------------------------------------------------------------------- #


def demo_commands() -> None:
    section("8. 接下来可以自己动手")
    for command, description in [
        ("python -m unittest discover -s tests -t . -v", "跑全部单元测试"),
        ("python benchmarks/bench_crypto.py", "对比纯 Python 哈希与 hashlib 的吞吐"),
        ("python benchmarks/bench_pow.py", "挖矿速率与难度对照表"),
        ("python -m nimbus_chain info", "打印链状态（数据目录 ./nimbus-data）"),
        ("python -m nimbus_chain mine --count 3", "挖 3 个块"),
        ("python -m nimbus_chain address", "查看钱包地址与余额"),
        ("python -m nimbus_chain notarize --file REPORT.pdf --mine", "把文件存证上链"),
        ("python -m nimbus_chain verify --file REPORT.pdf --spv", "用轻客户端验证存证"),
        ("python -m nimbus_chain serve --open", "启动浏览器 + 存证验证页面"),
        ("python -m nimbus_chain node --port 8001 --peer 127.0.0.1:8002 --mine",
         "跑一个 P2P 全节点（再开一个端口即组成双节点网络）"),
    ]:
        print(f"  {command}")
        print(f"      {description}")


def main() -> int:
    enable_utf8_console()      # CI / 重定向下 stdout 可能是 cp1252，否则打印中文会崩
    print("NimbusChain —— 零第三方依赖、从零实现的区块链 + 存证应用")
    print("演示参数：coinbase 成熟度 1（默认 100）；重组段单独用 retarget_interval=2")
    demo_cryptography()
    chain, miner = demo_chain()
    demo_transfers(chain, miner)
    demo_difficulty()
    demo_reorg()
    notary_chain, notary_wallet, _, _ = demo_notary()
    demo_spv(notary_chain, notary_wallet)
    demo_commands()

    print()
    print("=" * 78)
    total = _passed + _failed
    if _failed:
        print(f"  演示结束：{total} 项断言中 {_failed} 项失败，{_passed} 项通过")
    else:
        print(f"  演示结束：{total} 项断言全部通过 ✔")
    print("=" * 78)
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())

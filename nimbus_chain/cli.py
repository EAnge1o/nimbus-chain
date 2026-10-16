"""命令行入口：``python -m nimbus_chain <命令>``。

约定：

* 数据默认放在 ``./nimbus-data``：``chain.json``（主链）与 ``wallet.json``（私钥）。
* 金额参数用 NBC（整数或小数），内部一律换算成「聪」。
* 展示给用户看的哈希一律是**字节序反转后的十六进制**（与区块浏览器一致）；
  API 里的 hex 参数也遵循同一约定。
* ``coinbase_maturity`` 默认 100（与 Bitcoin 一致）。想快速演示可以显式指定
  ``--coinbase-maturity 1``，但记得那只是演示参数。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import enable_utf8_console
from .chain import Chain, ChainParams, InvalidBlock
from .mempool import Mempool, MempoolError
from .node import FullNode, NodeConfig, NodeError
from .notary import Notary
from .secp256k1 import PrivateKey
from .server import ExplorerConfig, ExplorerServer
from .spv import SPVClient
from .tx import COIN
from .wallet import Wallet, WalletError, address_to_script

DEFAULT_DATA_DIR = "nimbus-data"


class CliError(RuntimeError):
    """命令行层面的可预期错误（打印友好信息，不打印堆栈）。"""


# --------------------------------------------------------------------------- #
# 工作目录
# --------------------------------------------------------------------------- #


@dataclass
class Workspace:
    """一个「链 + 钱包」的工作目录，让每条命令都能接上上一次的状态。"""

    data_dir: Path
    params: ChainParams

    @property
    def chain_path(self) -> Path:
        return self.data_dir / "chain.json"

    @property
    def wallet_path(self) -> Path:
        return self.data_dir / "wallet.json"

    def ensure_dir(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def load_chain(self) -> Chain:
        if self.chain_path.exists():
            chain = Chain.load(self.chain_path)
            if chain.params != self.params:
                raise CliError(
                    f"链文件是用另一套共识参数创建的（{chain.params}），"
                    f"与当前参数（{self.params}）不一致")
            return chain
        return Chain(self.params)

    def save_chain(self, chain: Chain) -> None:
        self.ensure_dir()
        chain.save(self.chain_path)

    def load_wallet(self, *, name: str = "cli") -> Wallet:
        """从 ``wallet.json`` 读取私钥；文件不存在则新建一把并落盘。"""
        wallet = Wallet(name=name)
        if self.wallet_path.exists():
            payload = json.loads(self.wallet_path.read_text(encoding="utf-8"))
            for secret_hex in payload.get("keys", []):
                wallet.add_key(PrivateKey(int(secret_hex, 16)))
        if wallet.key_count == 0:
            wallet.new_key()
            self.ensure_dir()
            self.wallet_path.write_text(
                json.dumps({"keys": [format(secret, "064x") for secret in wallet.secrets]},
                           indent=2),
                encoding="utf-8")
        return wallet


def _workspace(args) -> Workspace:
    params = ChainParams(
        retarget_interval=args.retarget_interval,
        target_block_time=args.target_block_time,
        coinbase_maturity=args.coinbase_maturity,
    )
    return Workspace(Path(args.data_dir), params)


def _to_satoshis(amount: float) -> int:
    return int(round(amount * COIN))


def _from_satoshis(amount: int) -> str:
    return f"{amount / COIN:.8f}"


# --------------------------------------------------------------------------- #
# 命令实现
# --------------------------------------------------------------------------- #


def cmd_info(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    assert chain is not None
    stats = chain.stats()
    print(f"数据目录      {workspace.data_dir}")
    print(f"链文件        {workspace.chain_path} {'(新建，尚未落盘)' if not workspace.chain_path.exists() else ''}")
    print(f"高度          {stats['height']}")
    print(f"链尖          {stats['tip']}")
    print(f"累计工作量    {stats['total_work']}")
    print(f"UTXO 数量     {stats['utxo_count']}")
    print(f"已见区块      {stats['known_blocks']}（含侧链）")
    print(f"重组次数      {stats['reorgs']}")
    print(f"下一个 bits   {stats['next_bits']}")
    print(f"共识参数      重定目标每 {chain.params.retarget_interval} 块 / "
          f"期望出块 {chain.params.target_block_time}s / coinbase 成熟度 "
          f"{chain.params.coinbase_maturity}")
    if chain.height > 0:
        block = chain.tip
        print(f"链尖区块      {len(block.transactions)} 笔交易，nonce={block.header.nonce}，"
              f"大小 {block.size()} B")
    return 0


def cmd_address(args) -> int:
    workspace = _workspace(args)
    wallet = workspace.load_wallet()
    chain = workspace.load_chain()
    print(f"钱包文件      {workspace.wallet_path}")
    for address in wallet.addresses():
        print(f"地址          {address}")
    print(f"余额          {_from_satoshis(wallet.balance(chain))} NBC")
    print(f"可花费 UTXO   {len(wallet.utxos(chain))}")
    if args.show_secret:
        print("私钥（十六进制，仅调试用）：")
        for secret in wallet.secrets:
            print(f"  {format(secret, '064x')}")
    return 0


def cmd_mine(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    wallet = workspace.load_wallet()
    script = address_to_script(args.address) if args.address else wallet.first_script()
    for index in range(args.count):
        block = chain.build_and_mine([], script)
        chain.add_block(block)
        print(f"[{index + 1}/{args.count}] 高度 {chain.height}  {block.block_hash_hex()}  "
              f"{len(block.transactions)} 笔交易  nonce={block.header.nonce}")
    workspace.save_chain(chain)
    print(f"已保存到 {workspace.chain_path}")
    print(f"收款地址      {args.address or wallet.address()}")
    print(f"到账金额      {_from_satoshis(chain.subsidy(chain.height))} NBC / 块"
          f"（成熟度 {chain.params.coinbase_maturity}，需再挖 "
          f"{chain.params.coinbase_maturity} 块才可花费）")
    return 0


def cmd_balance(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    wallet = workspace.load_wallet()
    if args.address:
        script = address_to_script(args.address)
        print(f"地址          {args.address}")
        print(f"余额          {_from_satoshis(chain.balance(script))} NBC")
        for (txid, index), entry in chain.utxos_for_script(script):
            maturity = ("成熟" if not entry.is_coinbase
                        or chain.height - entry.height >= chain.params.coinbase_maturity
                        else "未成熟")
            print(f"  {txid[::-1].hex()}:{index}  {_from_satoshis(entry.value)} NBC  "
                  f"高度 {entry.height}  {maturity}")
    else:
        print(f"钱包余额      {_from_satoshis(wallet.balance(chain))} NBC")
        for key, entry in wallet.utxos(chain):
            print(f"  {key[0][::-1].hex()}:{key[1]}  {_from_satoshis(entry.value)} NBC")
    return 0


def cmd_send(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    wallet = workspace.load_wallet()
    amount = _to_satoshis(args.amount)
    tx = wallet.send(chain, args.to, amount, fee_rate=args.fee_rate)
    print(f"构造交易      {tx.txid_hex()}")
    print(f"输入 {len(tx.inputs)} / 输出 {len(tx.outputs)}，共 {_from_satoshis(tx.total_out())} NBC")
    if args.mine:
        block = chain.build_and_mine([tx], wallet.first_script())
        chain.add_block(block)
        workspace.save_chain(chain)
        print(f"已打包进高度 {chain.height} 的区块 {block.block_hash_hex()}")
        print(f"确认数        {chain.confirmations(tx.txid())}")
    else:
        # 先做一次完整校验（脚本、双花、手续费），但不落盘：CLI 没有常驻交易池
        Mempool(chain).add_transaction(tx)
        print("交易已通过完整校验（脚本/双花/手续费），但未上链：")
        print("  加 --mine 可以立刻打包；常驻交易池请用 `node` 子命令")
    return 0


def cmd_notarize(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    wallet = workspace.load_wallet()
    data = _read_document(args)
    notary = Notary(chain, wallet, Mempool(chain))
    notarization = notary.notarize(data)
    print(f"文档摘要      {notarization.digest.hex()}")
    print(f"锚定交易      {notarization.txid_hex}")
    if args.mine:
        block = chain.build_and_mine([notarization.tx], wallet.first_script())
        chain.add_block(block)
        workspace.save_chain(chain)
        print(f"已上链        高度 {chain.height}，区块 {block.block_hash_hex()}")
        result = notary.verify(data)
        print(f"验证结论      {'通过' if result.valid else '失败'}（{result.reason}）")
    else:
        print("未打包：加 --mine 让存证真正上链（存证的价值来自 PoW）")
    return 0


def cmd_verify(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    wallet = workspace.load_wallet()
    data = _read_document(args)
    notary = Notary(chain, wallet, Mempool(chain))
    client = None
    if args.spv:
        client = SPVClient(chain.params)
        client.sync_from_chain(chain)
    result = notary.verify(data, spv=client)
    print(f"文档摘要      {result.digest.hex()}")
    print(f"链上已存在    {result.present}")
    print(f"已确认        {result.confirmed}")
    if args.spv:
        print(f"SPV 证明      {result.spv_verified}"
              f"（轻客户端只存 {client.local_bytes()} 字节区块头）")
    print(f"确认数        {result.confirmations}")
    print(f"结论          {'验证通过' if result.valid else '验证失败'}")
    print(f"原因          {result.reason}")
    return 0


def cmd_anchors(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    wallet = workspace.load_wallet()
    notary = Notary(chain, wallet, Mempool(chain))
    records = notary.anchors(limit=args.limit)
    if not records:
        print("链上还没有存证记录")
        return 0
    for record in records:
        print(f"高度 {record.height:>4}  {record.digest.hex()}  "
              f"{record.txid[::-1].hex()}  确认 {record.confirmations}")
    return 0


def cmd_spv(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    if not args.txid:
        client = SPVClient(chain.params)
        client.sync_from_chain(chain)
        print(f"轻客户端高度  {client.height}")
        print(f"本地存储      {client.local_bytes()} 字节（{len(client)} 个区块头）")
        blockchain_bytes = sum(block.size() for block in chain.main_blocks())
        print(f"全节点存储    {blockchain_bytes} 字节")
        if blockchain_bytes:
            print(f"占比          {client.local_bytes() / blockchain_bytes * 100:.3f}%")
        return 0
    raw_txid = bytes.fromhex(args.txid)[::-1]
    location = chain.transaction_location(raw_txid)
    if location is None:
        raise CliError("主链上找不到这笔交易")
    block_hash, height, index = location
    block = chain.get_block(block_hash)
    proof = block.merkle_proof_for(index)
    client = SPVClient(chain.params)
    client.sync_from_chain(chain)
    verified = client.verify_transaction_inclusion(raw_txid, block_hash, proof)
    print(f"交易          {args.txid}")
    print(f"所在区块      {block_hash[::-1].hex()}（高度 {height}）")
    print(f"Merkle 路径   {len(proof)} 个哈希")
    for sibling, direction in proof:
        print(f"  {direction:<5} {sibling.hex()}")
    print(f"SPV 结论      {'证明通过' if verified else '证明失败'}")
    print(f"轻客户端只用了 {client.local_bytes()} 字节区块头，且没有下载任何交易列表")
    return 0


def cmd_serve(args) -> int:
    workspace = _workspace(args)
    chain = workspace.load_chain()
    wallet = workspace.load_wallet()
    if not workspace.chain_path.exists():
        # 空链上什么都看不到，先给几个块让页面有内容
        for _ in range(3):
            chain.add_block(chain.build_and_mine([], wallet.first_script()))
        workspace.save_chain(chain)
    server = ExplorerServer(chain, wallet=wallet, mempool=Mempool(chain),
                           config=ExplorerConfig(host=args.host, port=args.port))
    port = server.start()
    url = server.url()
    # flush：URL 必须立刻可见，否则被重定向到日志时用户看不到地址
    print(f"浏览器服务已启动： {url}", flush=True)
    print(f"按 Ctrl+C 停止。链文件 {workspace.chain_path}，每次挖矿后会写回。", flush=True)
    if args.open:
        import webbrowser
        webbrowser.open(url)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n正在停止……")
        workspace.save_chain(chain)
        server.stop()
        print(f"已保存到 {workspace.chain_path}")
    return 0


def cmd_node(args) -> int:
    workspace = _workspace(args)
    seeds = []
    for seed in args.peer or []:
        host, _, port_text = seed.rpartition(":")
        if not host:
            host, port_text = "127.0.0.1", seed
        seeds.append((host, int(port_text)))

    async def run() -> int:
        node = FullNode(
            chain=workspace.load_chain(),
            wallet=workspace.load_wallet(),
            config=NodeConfig(name=args.name, host=args.host, port=args.port,
                              seeds=seeds, auto_mine=args.mine,
                              mine_interval=args.interval),
        )
        await node.start()
        print(f"[{args.name}] 监听 {args.host}:{node.port()}，种子 {seeds or '（无）'}", flush=True)
        print(f"[{args.name}] 高度 {node.chain.height}，按 Ctrl+C 停止", flush=True)
        try:
            while True:
                await asyncio.sleep(1)
                chain = node.chain
                # flush：输出被重定向到文件/管道时，块缓冲会让状态行"看不到"
                print(f"[{args.name}] 高度 {chain.height}  对等体 {node.p2p.peer_count}  "
                      f"交易池 {len(node.mempool)}  UTXO {len(chain.utxo)}", flush=True)
        finally:
            # 不吞掉 CancelledError / KeyboardInterrupt：让它们继续向上冒泡，
            # 清理与落盘放在 finally 里，保证 Ctrl+C 也能存下图
            await node.stop()
            workspace.save_chain(node.chain)
            print(f"[{args.name}] 已停止，链已保存到 {workspace.chain_path}", flush=True)
        return 0

    return asyncio.run(run())


def _read_document(args) -> bytes:
    if args.file:
        try:
            return Path(args.file).read_bytes()
        except OSError as error:
            raise CliError(f"无法读取文件 {args.file}: {error}") from error
    if args.text is not None:
        return args.text.encode("utf-8")
    raise CliError("请用 --file 或 --text 指定要存证的内容")


# --------------------------------------------------------------------------- #
# 参数解析
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimbus-chain",
        description="NimbusChain —— 零第三方依赖、从零实现的区块链（含存证应用）",
    )
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                        help=f"数据目录（默认 {DEFAULT_DATA_DIR}）")
    parser.add_argument("--retarget-interval", type=int, default=16,
                        help="难度重定目标间隔（块）")
    parser.add_argument("--target-block-time", type=int, default=600,
                        help="期望出块间隔（秒）")
    parser.add_argument("--coinbase-maturity", type=int, default=100,
                        help="coinbase 成熟度（块）；演示可设为 1")
    subparsers = parser.add_subparsers(dest="command", required=True)

    info = subparsers.add_parser("info", help="打印链状态")
    info.set_defaults(func=cmd_info)

    address = subparsers.add_parser("address", help="显示钱包地址与余额")
    address.add_argument("--show-secret", action="store_true", help="同时打印私钥（调试用）")
    address.set_defaults(func=cmd_address)

    mine = subparsers.add_parser("mine", help="挖矿")
    mine.add_argument("--count", type=int, default=1, help="挖几个块")
    mine.add_argument("--address", default=None, help="coinbase 收款地址（默认钱包地址）")
    mine.set_defaults(func=cmd_mine)

    balance = subparsers.add_parser("balance", help="查询余额与 UTXO")
    balance.add_argument("address", nargs="?", default=None, help="地址（默认查钱包）")
    balance.set_defaults(func=cmd_balance)

    send = subparsers.add_parser("send", help="转账")
    send.add_argument("--to", required=True, help="收款地址")
    send.add_argument("--amount", type=float, required=True, help="金额（NBC）")
    send.add_argument("--fee-rate", type=float, default=1.0, help="手续费率（聪/字节）")
    send.add_argument("--mine", action="store_true", help="立刻打包进区块")
    send.set_defaults(func=cmd_send)

    notarize = subparsers.add_parser("notarize", help="把文件摘要锚定到链上")
    notarize.add_argument("--file", help="要存证的文件")
    notarize.add_argument("--text", help="要存证的文本")
    notarize.add_argument("--mine", action="store_true", help="立刻打包进区块")
    notarize.set_defaults(func=cmd_notarize)

    verify = subparsers.add_parser("verify", help="验证某份内容是否已被存证")
    verify.add_argument("--file", help="要验证的文件")
    verify.add_argument("--text", help="要验证的文本")
    verify.add_argument("--spv", action="store_true", help="同时用 SPV 轻客户端验证")
    verify.set_defaults(func=cmd_verify)

    anchors = subparsers.add_parser("anchors", help="列出链上存证记录")
    anchors.add_argument("--limit", type=int, default=None)
    anchors.set_defaults(func=cmd_anchors)

    spv = subparsers.add_parser("spv", help="SPV 统计 / 交易存在性证明")
    spv.add_argument("--txid", default=None, help="要证明的交易哈希（展示用十六进制）")
    spv.set_defaults(func=cmd_spv)

    serve = subparsers.add_parser("serve", help="启动浏览器 / 存证验证页面")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--open", action="store_true", help="启动后打开浏览器")
    serve.set_defaults(func=cmd_serve)

    node = subparsers.add_parser("node", help="运行一个 P2P 全节点")
    node.add_argument("--name", default="node1")
    node.add_argument("--host", default="127.0.0.1")
    node.add_argument("--port", type=int, default=8001)
    node.add_argument("--peer", action="append", help="对等体，可重复：HOST:PORT")
    node.add_argument("--mine", action="store_true", help="自动挖矿")
    node.add_argument("--interval", type=float, default=5.0, help="自动挖矿间隔（秒）")
    node.set_defaults(func=cmd_node)

    return parser


def main(argv: list[str] | None = None) -> int:
    enable_utf8_console()      # 输出被重定向时 Windows 会退回 cp1252，中文会抛异常
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return args.func(args)
    except (CliError, WalletError, InvalidBlock, MempoolError, NodeError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:                                  # pragma: no cover - 手工中断
        print("\n已中断", file=sys.stderr)
        return 130


if __name__ == "__main__":                                     # pragma: no cover
    raise SystemExit(main())

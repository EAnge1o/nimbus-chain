"""全节点：把链、交易池、钱包、P2P 与挖矿组装成一个可运行的节点。

分工刻意清晰：

* :class:`~nimbus_chain.chain.Chain` 只关心「这个块合不合法」；
* :class:`~nimbus_chain.mempool.Mempool` 只关心「这笔交易能不能进池」；
* :class:`~nimbus_chain.p2p.P2PNode` 只关心「说话与转发」；
* :class:`FullNode` 负责把三者黏在一起，并把「谁该转发」这件事留给 P2P。

新区块接入后的顺序很重要：先 ``remove_for_block`` 清掉已确认的交易，再把重组
中被挤出来的交易 ``re_add`` 回池，最后 ``refresh`` 一次把因重组而失效的条目
剔除干净。漏掉任何一步，节点就会拿着已经不可能上链的交易去挖矿。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .chain import AddBlockResult, Chain, ChainParams, InvalidBlock
from .mempool import Mempool, MempoolError
from .notary import Notary
from .p2p import P2PNode
from .spv import SPVClient
from .tx import Transaction
from .wallet import Wallet

__all__ = ["NodeError", "NodeConfig", "FullNode"]


class NodeError(RuntimeError):
    """节点配置或运行状态错误。"""


@dataclass
class NodeConfig:
    """节点运行参数。"""

    host: str = "127.0.0.1"
    port: int = 0                                  # 0 = 让操作系统分配端口
    seeds: list[tuple[str, int]] = field(default_factory=list)
    name: str = "node"
    auto_mine: bool = False
    mine_interval: float = 1.0                     # 自动挖矿的间隔（秒）
    max_transactions_per_block: int = 64
    max_blocks_per_request: int = 16


class FullNode:
    """一个可运行的全节点。"""

    def __init__(self, *, chain: Chain | None = None, params: ChainParams | None = None,
                 wallet: Wallet | None = None, mempool: Mempool | None = None,
                 config: NodeConfig | None = None) -> None:
        self.config = config or NodeConfig()
        self.chain = chain or Chain(params)
        self.mempool = mempool or Mempool(self.chain)
        self.wallet = wallet or Wallet(name=self.config.name)
        self.p2p = P2PNode(
            self,
            host=self.config.host,
            port=self.config.port,
            seeds=self.config.seeds,
            max_blocks_per_request=self.config.max_blocks_per_request,
            name=self.config.name,
        )
        self.events: list[tuple[str, str]] = []
        self._miner_task: asyncio.Task | None = None

    # -- 生命周期 --------------------------------------------------------- #

    async def start(self) -> "FullNode":
        await self.p2p.start()
        if self.config.auto_mine:
            self._miner_task = asyncio.create_task(self._miner_loop())
        self._record("start", f"{self.config.name} 在 {self.port()} 启动")
        return self

    async def stop(self) -> None:
        if self._miner_task is not None:
            self._miner_task.cancel()
            try:
                await self._miner_task
            except asyncio.CancelledError:
                pass
            self._miner_task = None
        await self.p2p.stop()
        self._record("stop", f"{self.config.name} 已停止")

    def port(self) -> int | None:
        return self.p2p.bound_port

    def _record(self, event: str, detail: str = "") -> None:
        self.events.append((event, detail))

    # -- P2P 回调（只改状态；转发由 P2P 负责，避免重复广播） ---------------- #

    def on_block(self, block) -> AddBlockResult | None:
        try:
            result = self.chain.add_block(block)
        except InvalidBlock as error:
            self._record("rejected_block", str(error))
            return None

        if result.status in ("connected", "reorg"):
            accepted = self.chain.get_block(result.block_hash)
            self.mempool.remove_for_block(accepted)
            if result.reaccepted:
                self.mempool.re_add(result.reaccepted)
            self.mempool.refresh()
            self._record("chain", f"高度 {result.height}（{result.status}）")
        elif result.status == "side_chain":
            self._record("side_chain", f"分支工作量 {result.branch_work}")
        return result

    def on_transaction(self, tx: Transaction) -> bool:
        try:
            self.mempool.add_transaction(tx)
        except (MempoolError, ValueError) as error:
            self._record("rejected_tx", str(error))
            return False
        self._record("mempool", f"接受 {tx.txid_hex()[:16]}…")
        return True

    def get_blocks(self, from_height: int, limit: int) -> list:
        blocks = []
        for height in range(max(0, from_height), min(self.chain.height, from_height + limit - 1) + 1):
            block = self.chain.block_at_height(height)
            if block is not None:
                blocks.append(block)
        return blocks

    # -- 本节点发起的动作 ------------------------------------------------- #

    async def submit_transaction(self, tx: Transaction) -> bool:
        """本地构造的交易：进池成功后向全网公告。"""
        accepted = self.on_transaction(tx)
        if accepted:
            await self.p2p.announce_transaction(tx)
        return accepted

    def mining_script(self) -> bytes:
        if self.wallet.key_count:
            return self.wallet.first_script()
        raise NodeError("节点没有收款地址，无法挖矿：请先给节点一个钱包")

    def mine_block(self, script: bytes | None = None,
                   transactions: list[Transaction] | None = None):
        """挖一个区块并接入本链；交易默认从交易池里选。"""
        script = script or self.mining_script()
        if transactions is None:
            transactions = self.mempool.select_for_block(
                max_transactions=self.config.max_transactions_per_block)
        block = self.chain.build_and_mine(list(transactions), script)
        result = self.chain.add_block(block)
        if result.status in ("connected", "reorg"):
            self.mempool.remove_for_block(block)
            self.mempool.refresh()
        self._record("mined", f"高度 {result.height}，{len(block.transactions)} 笔交易")
        return block

    async def mine_and_announce(self, script: bytes | None = None):
        """挖矿 + 广播（自动挖矿循环与演示脚本都用它）。"""
        block = self.mine_block(script)
        await self.p2p.announce_block(block)
        return block

    async def _miner_loop(self) -> None:
        """自动挖矿。挖矿是 CPU 密集的，这里直接在事件循环里跑——
        演示规模下每个块约 0.1 秒尚可接受，代价是这个间隙里 P2P 会短暂停顿。
        生产实现应当把 PoW 放到独立进程/线程里。"""
        try:
            while True:
                await asyncio.sleep(self.config.mine_interval)
                try:
                    await self.mine_and_announce()
                except (InvalidBlock, NodeError):
                    continue
        except asyncio.CancelledError:
            return

    # -- 便利入口 --------------------------------------------------------- #

    def notary(self) -> Notary:
        """基于本节点链与钱包的存证应用。"""
        return Notary(self.chain, self.wallet, self.mempool)

    def spv_client(self) -> SPVClient:
        """构造一个已同步到当前链尖的轻客户端（演示「只靠区块头验证」）。"""
        client = SPVClient(self.chain.params)
        client.sync_from_chain(self.chain)
        return client

    def stats(self) -> dict:
        return {
            "node": self.config.name,
            "chain": self.chain.stats(),
            "mempool": self.mempool.stats(),
            "p2p": self.p2p.stats(),
            "wallet": {
                "keys": self.wallet.key_count,
                "address": self.wallet.address() if self.wallet.key_count else None,
                "balance": self.wallet.balance(self.chain),
            },
        }

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return (f"FullNode({self.config.name!r}, height={self.chain.height}, "
                f"peers={self.p2p.peer_count})")

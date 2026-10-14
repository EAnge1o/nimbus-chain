"""P2P 集成测试：真实启动 asyncio 服务、真实建连、真实同步。

这里刻意不 mock 任何东西：两个节点各自监听一个真实端口，通过 TCP 交换真实的
长度前缀 JSON 消息，跑真实的 PoW 与脚本校验。测试断言的命题是「两个独立进程
级别的节点最终会对同一条链达成一致」——包括交易传播与分叉重组。
"""

from __future__ import annotations

import asyncio
import time
import unittest
from dataclasses import replace

from nimbus_chain.block import Block
from nimbus_chain.chain import Chain, ChainParams
from nimbus_chain.node import FullNode, NodeConfig
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.wallet import Wallet

PARAMS = ChainParams(retarget_interval=10_000, coinbase_maturity=1)
A_KEY = PrivateKey(0xAAAA_0001)
B_KEY = PrivateKey(0xBBBB_0002)
C_KEY = PrivateKey(0xCCCC_0003)

# Windows 上 asyncio + TCP + 真实哈希，超时给得宽一些
DEFAULT_TIMEOUT = 20.0


def make_node(name: str, key: PrivateKey, *, port: int = 0, seeds=(),
              params: ChainParams = PARAMS, auto_mine: bool = False,
              mine_interval: float = 0.05) -> FullNode:
    return FullNode(
        chain=Chain(params),
        wallet=Wallet(name=name, keys=[key]),
        config=NodeConfig(name=name, port=port, seeds=list(seeds),
                          auto_mine=auto_mine, mine_interval=mine_interval),
    )


async def wait_until(predicate, timeout: float = DEFAULT_TIMEOUT, interval: float = 0.02) -> bool:
    """轮询等待条件成立；超时返回 False（而不是抛异常，便于断言给出清晰失败信息）。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return False


class P2PIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.nodes: list[FullNode] = []

    async def asyncTearDown(self):
        # 收尾必须可靠：取消所有任务、关闭服务端与连接，否则会留下 pending task 警告
        for node in self.nodes:
            await node.stop()
        self.nodes.clear()

    async def start_node(self, *args, **kwargs) -> FullNode:
        node = make_node(*args, **kwargs)
        await node.start()
        self.nodes.append(node)
        return node

    async def peer_up(self, *nodes: FullNode) -> bool:
        return await wait_until(lambda: all(node.p2p.peer_count >= 1 for node in nodes))

    # -- 基本握手与出块同步 ---------------------------------------------- #

    async def test_two_nodes_converge_on_a_mined_block(self):
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await self.peer_up(alice, bob), "两个节点未能建立连接")
        self.assertEqual(alice.chain.genesis_hash, bob.chain.genesis_hash)

        block = await alice.mine_and_announce()
        self.assertTrue(await wait_until(lambda: bob.chain.height == 1),
                        f"B 未能同步到高度 1（当前 {bob.chain.height}）")
        self.assertEqual(bob.chain.tip_hash, alice.chain.tip_hash)
        self.assertEqual(bob.chain.tip_hash, block.block_hash())
        self.assertEqual(bob.chain.total_work, alice.chain.total_work)

    async def test_new_node_syncs_an_existing_chain(self):
        alice = await self.start_node("A", A_KEY)
        for _ in range(3):
            await alice.mine_and_announce()
        self.assertEqual(alice.chain.height, 3)

        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await wait_until(lambda: bob.chain.height == 3),
                        f"B 未能追平（当前 {bob.chain.height}）")
        self.assertEqual(bob.chain.tip_hash, alice.chain.tip_hash)
        self.assertEqual(bob.chain.total_work, alice.chain.total_work)
        self.assertTrue(any(event == "sync" for event, _ in bob.p2p.events))

    async def test_header_chain_sync_via_spv_client_from_peer(self):
        """轻客户端的头可以从网络里拿：从对端同步区块头后独立验证。"""
        alice = await self.start_node("A", A_KEY)
        for _ in range(2):
            await alice.mine_and_announce()
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await wait_until(lambda: bob.chain.height == 2))
        client = bob.spv_client()
        self.assertEqual(client.height, 2)
        self.assertEqual(client.tip_hash, alice.chain.tip_hash)

    # -- 交易传播 --------------------------------------------------------- #

    async def test_transaction_propagates_and_then_gets_confirmed(self):
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await self.peer_up(alice, bob))

        await alice.mine_and_announce()
        await alice.mine_and_announce()
        self.assertTrue(await wait_until(lambda: bob.chain.height == 2))

        tx = alice.wallet.send(alice.chain, bob.wallet.address(), 1_000_000)
        self.assertTrue(await alice.submit_transaction(tx))
        self.assertTrue(await wait_until(lambda: tx.txid() in bob.mempool),
                        "B 的交易池没有收到 A 广播的交易")
        self.assertEqual(len(bob.mempool), 1)

        await alice.mine_and_announce()
        self.assertTrue(await wait_until(
            lambda: bob.chain.get_transaction(tx.txid()) is not None),
            "B 没有把 A 挖出的含该交易的区块接上")
        self.assertEqual(bob.chain.confirmations(tx.txid()), 1)
        self.assertEqual(bob.chain.balance(bob.wallet.first_script()), 1_000_000)
        self.assertEqual(len(bob.mempool), 0)          # 已确认 => 交易池清空
        self.assertEqual(bob.chain.utxo, bob.chain.replay_utxo_set())

    async def test_transaction_relayed_to_a_third_node(self):
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await self.peer_up(alice, bob))
        carol = await self.start_node("C", C_KEY, seeds=[("127.0.0.1", bob.port())])
        self.assertTrue(await wait_until(lambda: carol.p2p.peer_count >= 1))

        await alice.mine_and_announce()
        await alice.mine_and_announce()
        self.assertTrue(await wait_until(lambda: carol.chain.height == 2, timeout=30.0))

        tx = alice.wallet.send(alice.chain, carol.wallet.address(), 500_000)
        self.assertTrue(await alice.submit_transaction(tx))
        # A 只连 B，C 只连 B：交易必须经过 B 中转才能到 C
        self.assertTrue(await wait_until(lambda: tx.txid() in carol.mempool, timeout=30.0),
                        "交易没有被中转给第三个节点")

    # -- 分叉与重组（P2P 层面） ------------------------------------------- #

    async def test_fork_is_resolved_by_cumulative_work(self):
        """两个节点各自挖出「同高度但互不相同」的块，再由更长链一方统一全网。"""
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY)

        alice.mine_block()
        bob.mine_block()
        self.assertEqual(alice.chain.height, 1)
        self.assertEqual(bob.chain.height, 1)
        self.assertNotEqual(alice.chain.tip_hash, bob.chain.tip_hash)
        self.assertEqual(alice.chain.total_work, bob.chain.total_work)

        # 现在还互不相识：B 动态连上 A
        bob.p2p.connect_async("127.0.0.1", alice.port())
        self.assertTrue(await self.peer_up(alice, bob))
        # 高度与工作量相同 => 双方都保留自己的链尖（先见者胜），不做重组
        await asyncio.sleep(0.3)
        self.assertNotEqual(alice.chain.tip_hash, bob.chain.tip_hash)
        self.assertEqual(bob.chain.reorg_count, 0)

        # A 再挖一块 => A 的累计工作量更高，B 必须切过去
        await alice.mine_and_announce()
        self.assertTrue(await wait_until(lambda: bob.chain.height == 2), "B 未能追上更长的链")
        self.assertEqual(bob.chain.tip_hash, alice.chain.tip_hash)
        self.assertEqual(bob.chain.total_work, alice.chain.total_work)
        self.assertEqual(bob.chain.reorg_count, 1)
        self.assertEqual(bob.chain.utxo, bob.chain.replay_utxo_set())
        self.assertTrue(bob.chain.is_on_main_chain(bob.chain.tip_hash))

    async def test_same_work_fork_keeps_first_seen_tip(self):
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY)
        alice.mine_block()
        bob.mine_block()
        bob.p2p.connect_async("127.0.0.1", alice.port())
        self.assertTrue(await self.peer_up(alice, bob))
        await asyncio.sleep(0.5)
        self.assertEqual(alice.chain.reorg_count, 0)
        self.assertEqual(bob.chain.reorg_count, 0)
        # 双方都收到了对方的侧链块（被保存但不在主链上）
        self.assertTrue(alice.chain.known(bob.chain.tip_hash))
        self.assertTrue(bob.chain.known(alice.chain.tip_hash))
        self.assertFalse(alice.chain.is_on_main_chain(bob.chain.tip_hash))

    # -- 网络隔离与生命周期 ----------------------------------------------- #

    async def test_nodes_on_different_networks_are_disconnected(self):
        """创世块不同 => 不同网络：连上后必须立刻断开，而不是继续交换数据。"""
        other_params = ChainParams(retarget_interval=1_000, pow_limit_bits=0x1F0FFFFE)
        alice = await self.start_node("A", A_KEY)
        intruder = await self.start_node("X", B_KEY, seeds=[("127.0.0.1", alice.port())],
                                        params=other_params)
        self.assertNotEqual(alice.chain.genesis_hash, intruder.chain.genesis_hash)
        self.assertTrue(await wait_until(
            lambda: any(event == "wrong_network" for event, _ in alice.p2p.events)
            or any(event == "wrong_network" for event, _ in intruder.p2p.events)))
        self.assertTrue(await wait_until(lambda: intruder.p2p.peer_count == 0))
        self.assertEqual(intruder.chain.height, 0)

    async def test_auto_mine_produces_blocks_and_peers_follow(self):
        alice = await self.start_node("A", A_KEY, auto_mine=True, mine_interval=0.05)
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await wait_until(lambda: alice.chain.height >= 2, timeout=30.0))
        self.assertTrue(await wait_until(lambda: bob.chain.height == alice.chain.height,
                                        timeout=30.0),
                        f"B 没跟上自动挖矿（A={alice.chain.height}, B={bob.chain.height}）")
        self.assertEqual(bob.chain.tip_hash, alice.chain.tip_hash)

    async def test_stop_is_clean_and_idempotent(self):
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await self.peer_up(alice, bob))
        await bob.stop()
        await bob.stop()                    # 重复停止不应报错
        self.assertFalse(bob.p2p.is_running)
        self.assertEqual(bob.p2p.peer_count, 0)
        self.assertTrue(await wait_until(lambda: alice.p2p.peer_count == 0))

    async def test_stats_and_events(self):
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await self.peer_up(alice, bob))
        await alice.mine_and_announce()
        self.assertTrue(await wait_until(lambda: bob.chain.height == 1))

        stats = alice.stats()
        self.assertEqual(stats["node"], "A")
        self.assertIn("chain", stats)
        self.assertIn("mempool", stats)
        self.assertEqual(stats["p2p"]["peers"][0]["height"], 0)   # 握手时对端高度为 0
        self.assertEqual(stats["wallet"]["balance"], 0)           # coinbase 尚未成熟
        self.assertTrue(any(event == "mined" for event, _ in alice.events))
        self.assertIn("FullNode(", repr(alice))

    async def test_orphan_pool_does_not_grow_without_bound(self):
        alice = await self.start_node("A", A_KEY)
        bob = await self.start_node("B", B_KEY, seeds=[("127.0.0.1", alice.port())])
        self.assertTrue(await self.peer_up(alice, bob))
        self.assertEqual(bob.p2p.max_orphans, 256)
        self.assertEqual(bob.p2p.orphans, {})


class FakePeer:
    """一个只记录「我收到了什么」的假对等体，用于直接驱动消息处理逻辑。"""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.closed = False
        self.address = "fake:0"

    async def send(self, message: dict) -> None:
        self.sent.append(message)

    def close(self) -> None:
        self.closed = True

    def last(self, kind: str) -> dict | None:
        for message in reversed(self.sent):
            if message.get("type") == kind:
                return message
        return None


class OrphanHandlingTests(unittest.IsolatedAsyncioTestCase):
    """孤儿块：先到的「孩子」必须先挂起，等「父亲」到了再接上。

    这类乱序在真实网络里是常态（对方按 inv 逐个推送、连接中途重置），
    处理不好就会出现「明明广播了区块，对端却永远停在旧高度」。
    """

    def setUp(self):
        self.alice = make_node("A", A_KEY)
        for _ in range(3):
            self.alice.mine_block()
        self.bob = make_node("B", B_KEY)
        self.peer = FakePeer()

    async def deliver(self, block) -> None:
        await self.bob.p2p.handle_message(self.peer, {"type": "block", "block": block.to_hex()})

    async def test_orphan_is_held_and_its_parent_requested(self):
        block2 = self.alice.chain.block_at_height(2)
        await self.deliver(block2)

        self.assertEqual(self.bob.chain.height, 0)                     # 接不上
        self.assertIn(block2.block_hash(), self.bob.p2p.orphans)       # 但被挂起了
        request = self.peer.last("getdata")
        self.assertIsNotNone(request)
        self.assertEqual(request["kind"], "block")
        self.assertEqual(request["ids"], [block2.header.prev_block.hex()])

    async def test_orphan_chain_resolves_when_ancestors_arrive(self):
        block1 = self.alice.chain.block_at_height(1)
        block2 = self.alice.chain.block_at_height(2)
        block3 = self.alice.chain.block_at_height(3)
        await self.deliver(block2)
        await self.deliver(block3)
        self.assertEqual(len(self.bob.p2p.orphans), 2)

        await self.deliver(block1)          # 父块到位 => 两个孤儿必须依次接上
        self.assertEqual(self.bob.p2p.orphans, {})
        self.assertEqual(self.bob.chain.height, 3)
        self.assertEqual(self.bob.chain.tip_hash, block3.block_hash())
        self.assertEqual(self.bob.chain.utxo, self.bob.chain.replay_utxo_set())
        self.assertTrue(any(event == "orphan_resolved" for event, _ in self.bob.p2p.events))

    async def test_orphan_pool_is_bounded(self):
        self.bob.p2p.max_orphans = 1
        for height in (2, 3):
            await self.deliver(self.alice.chain.block_at_height(height))
        self.assertEqual(len(self.bob.p2p.orphans), 1)

    async def test_block_with_invalid_pow_never_enters_the_orphan_pool(self):
        """否则任何对等体都能用垃圾块把内存灌满。"""
        block2 = self.alice.chain.block_at_height(2)
        header = replace(block2.header)
        target = header.target()
        while int.from_bytes(header.hash(), "big") <= target:
            header.nonce += 1                                   # 找一个不满足 PoW 的 nonce
        forged = Block(header, list(block2.transactions))

        await self.bob.p2p.handle_message(
            self.peer, {"type": "block", "block": forged.to_hex()})
        self.assertEqual(self.bob.p2p.orphans, {})
        self.assertTrue(any(event == "bad_pow" for event, _ in self.bob.p2p.events))

    async def test_duplicate_delivery_is_idempotent(self):
        block1 = self.alice.chain.block_at_height(1)
        await self.deliver(block1)
        await self.deliver(block1)
        self.assertEqual(self.bob.chain.height, 1)
        self.assertEqual(len(self.bob.p2p.peers), 0)

    async def test_locator_shrinks_with_depth(self):
        self.assertLessEqual(len(self.alice.p2p._locator()), 17)
        locator = self.alice.p2p._locator()
        self.assertEqual(locator[-1], self.alice.chain.genesis_hash.hex())
        self.assertEqual(locator[0], self.alice.chain.tip_hash.hex())

    async def test_resolve_locator_finds_the_common_ancestor(self):
        genesis = self.alice.chain.genesis_hash.hex()
        self.assertEqual(self.bob.p2p._resolve_locator([genesis, b"\x00" * 32]), 1)
        tip = self.alice.chain.tip_hash.hex()
        self.assertEqual(self.alice.p2p._resolve_locator([tip]), self.alice.chain.height + 1)
        self.assertEqual(self.bob.p2p._resolve_locator([]), 1)


if __name__ == "__main__":
    unittest.main()

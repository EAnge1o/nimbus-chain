"""P2P 网络：基于 asyncio 的长度前缀 JSON gossip 协议。

节点之间只做三件事，但这三件事足以让全网收敛：

1. **握手（``hello``）**：交换创世哈希、高度与累计工作量。创世哈希不一致说明不在
   同一个网络，立刻断开——这比事后因为难度不符而困惑要友好得多。
2. **公告与拉取（``inv`` / ``getdata`` / ``block`` / ``tx``）**：出了新块或新交易，
   只广播「我有这个哈希」（``inv``），对方缺什么再按需索取。这是 Bitcoin 的
   inventory 机制——避免把区块推给已经拥有的节点。
3. **初始同步（``getblocks`` / ``blocks``）**：落后的一方按高度拉取主链区块。

刻意不做的东西：地址簿与节点发现（DNS seeds）、getheaders 增量同步、
bloom filter、限速与反女巫。这些是工程问题，不是共识问题；本项目的目标是
把共识与验证讲清楚，而不是复刻一个可运营的全节点。
"""

from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

from .block import Block
from .tx import Transaction

__all__ = [
    "PROTOCOL_VERSION",
    "P2PError",
    "PeerConnection",
    "P2PNode",
    "read_message",
    "send_message",
]

PROTOCOL_VERSION = 1
_MAX_MESSAGE_BYTES = 8 * 1024 * 1024
_HEADER = struct.Struct(">I")


class P2PError(ValueError):
    """协议层错误。"""


async def send_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    """发送一条消息：4 字节大端长度前缀 + UTF-8 JSON。"""
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_MESSAGE_BYTES:
        raise P2PError(f"message too large: {len(payload)} bytes")
    writer.write(_HEADER.pack(len(payload)) + payload)
    await writer.drain()


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    """读取一条消息；对端正常关闭时返回 ``None``。"""
    try:
        size = _HEADER.unpack(await reader.readexactly(_HEADER.size))[0]
    except (asyncio.IncompleteReadError, ConnectionError):
        return None
    if size > _MAX_MESSAGE_BYTES:
        raise P2PError(f"peer announced an oversized message: {size} bytes")
    try:
        payload = await reader.readexactly(size)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise P2PError(f"malformed message: {error}") from error
    if not isinstance(message, dict) or "type" not in message:
        raise P2PError("message must be an object with a 'type' field")
    return message


class PeerConnection:
    """一条对等体连接：读写管道 + 对端已声明的高度/工作量。"""

    __slots__ = ("reader", "writer", "direction", "host", "port", "height", "work",
                 "genesis", "closed", "_lock")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 *, direction: str) -> None:
        self.reader = reader
        self.writer = writer
        self.direction = direction          # 'in'（别人连我）或 'out'（我连别人）
        peername = writer.get_extra_info("peername") or ("?", 0)
        self.host, self.port = str(peername[0]), int(peername[1])
        self.height: int | None = None
        self.work: int | None = None
        self.genesis: bytes | None = None
        self.closed = False
        self._lock = asyncio.Lock()

    async def send(self, message: dict[str, Any]) -> None:
        if self.closed:
            return
        async with self._lock:              # 并发发送时避免两条消息的字节交错
            await send_message(self.writer, message)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
        except (OSError, RuntimeError):     # pragma: no cover - 关闭已死连接
            pass

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"Peer({self.address}, {self.direction}, height={self.height})"


class P2PNode:
    """一个节点的网络层。

    ``handler`` 提供三个能力（``node.FullNode`` 就是这样的对象）：

    * ``handler.chain``：读主链、查已知区块
    * ``handler.on_block(block)``：把收到的区块交给链（只改状态，不负责转发）
    * ``handler.on_transaction(tx)``：把收到的交易交给交易池
    * ``handler.get_blocks(from_height, limit)``：按高度取主链区块，用于同步
    """

    def __init__(self, handler, *, host: str = "127.0.0.1", port: int = 0,
                 seeds: list[tuple[str, int]] | None = None,
                 max_blocks_per_request: int = 16, name: str = "node") -> None:
        self.handler = handler
        self.host = host
        self.port = port
        self.seeds = list(seeds or [])
        self.max_blocks_per_request = max_blocks_per_request
        self.name = name

        self.peers: list[PeerConnection] = []
        self.bound_port: int | None = None
        self.events: list[tuple[str, str]] = []      # (事件, 说明)，供测试与 Demo 断言
        self.orphans: dict[bytes, Block] = {}        # 父块还没到的区块
        self.max_orphans = 256
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task] = set()
        self._running = False

    # -- 生命周期 --------------------------------------------------------- #

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    async def start(self) -> "P2PNode":
        self._running = True
        self._server = await asyncio.start_server(self._on_incoming, self.host, self.port)
        sockets = self._server.sockets or ()
        self.bound_port = sockets[0].getsockname()[1] if sockets else None
        self._record("listen", f"{self.host}:{self.bound_port}")
        for host, seed_port in self.seeds:
            self._spawn(self._connect_with_retry(host, seed_port))
        return self

    async def stop(self) -> None:
        self._running = False
        for peer in list(self.peers):
            peer.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self.peers.clear()
        self.orphans.clear()
        self._record("stop", f"{self.name} 已停止")

    def connect_async(self, host: str, port: int) -> asyncio.Task:
        """动态加入一个对等体（不阻塞调用方），返回连接任务句柄。"""
        if not self._running:
            raise P2PError("p2p node is not running")
        return self._spawn(self._connect_with_retry(host, port))

    def _spawn(self, coroutine) -> asyncio.Task:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _record(self, event: str, detail: str = "") -> None:
        self.events.append((event, detail))

    # -- 连接 ------------------------------------------------------------- #

    async def _connect_with_retry(self, host: str, port: int, attempts: int = 20,
                                  delay: float = 0.1) -> bool:
        """连种子节点；对端还没起来就退避重试（真实节点会一直重试下去）。"""
        for _ in range(attempts):
            if not self._running:
                return False
            try:
                reader, writer = await asyncio.open_connection(host, port)
            except (OSError, ConnectionError):
                await asyncio.sleep(delay)
                continue
            peer = PeerConnection(reader, writer, direction="out")
            self.peers.append(peer)
            self._record("connect", peer.address)
            await self._run_peer(peer)
            return True
        self._record("connect_failed", f"{host}:{port}")
        return False

    async def _on_incoming(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
        peer = PeerConnection(reader, writer, direction="in")
        self.peers.append(peer)
        self._record("accept", peer.address)
        await self._run_peer(peer)

    async def _run_peer(self, peer: PeerConnection) -> None:
        """握手 → 读循环 → 清理。"""
        try:
            await peer.send(self._hello())
            while self._running and not peer.closed:
                try:
                    message = await read_message(peer.reader)
                except P2PError as error:
                    self._record("protocol_error", str(error))
                    break
                if message is None:
                    break
                await self._handle(peer, message)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        finally:
            peer.close()
            if peer in self.peers:
                self.peers.remove(peer)
            self._record("disconnect", peer.address)

    def _hello(self) -> dict[str, Any]:
        chain = self.handler.chain
        return {
            "type": "hello",
            "version": PROTOCOL_VERSION,
            "genesis": chain.genesis_hash.hex(),
            "height": chain.height,
            "work": chain.total_work,
            "port": self.bound_port or self.port,
            "name": self.name,
            "locator": self._locator(),
        }

    def _locator(self, max_entries: int = 16) -> list[str]:
        """区块定位器：从链尖往回按指数步长取哈希。

        这是 Bitcoin 收敛分叉的关键机制——直接问「你有哪几个高度」无法发现对方
        的分支，而定位器能让双方找出**第一个共同祖先**，再把各自之后的块互换。
        步长在超过 10 个条目后翻倍，所以定位器长度是 O(log 高度)。
        """
        chain = self.handler.chain
        hashes: list[str] = []
        step = 1
        height = chain.height
        while height >= 0 and len(hashes) < max_entries:
            block = chain.block_at_height(height)
            if block is None:
                break
            hashes.append(block.block_hash().hex())
            if len(hashes) > 10:
                step *= 2
            height -= step
        if not hashes or hashes[-1] != chain.genesis_hash.hex():
            hashes.append(chain.genesis_hash.hex())
        return hashes

    async def handle_message(self, peer, message: dict[str, Any]) -> None:
        """处理一条来自 ``peer`` 的消息。

        对 P2P 读循环之外的调用方开放：测试可以直接注入消息，嵌入方也可以把它
        接到别的传输层（例如 WebSocket）上。
        """
        await self._handle(peer, message)

    # -- 消息处理 --------------------------------------------------------- #

    async def _handle(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        kind = message.get("type")
        if kind == "hello":
            await self._on_hello(peer, message)
        elif kind == "getblocks":
            await self._serve_blocks(peer, message)
        elif kind == "blocks":
            await self._receive_blocks(peer, message)
        elif kind == "inv":
            await self._on_inventory(peer, message)
        elif kind == "getdata":
            await self._serve_data(peer, message)
        elif kind == "block":
            await self._receive_block(peer, message)
        elif kind == "tx":
            await self._receive_transaction(peer, message)
        elif kind == "ping":
            await peer.send({"type": "pong"})
        elif kind == "pong":
            pass
        else:
            self._record("unknown_message", str(kind))

    async def _on_hello(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        if message.get("version") != PROTOCOL_VERSION:
            self._record("version_mismatch", f"{peer.address}: {message.get('version')}")
            peer.close()
            return
        try:
            peer.genesis = bytes.fromhex(message["genesis"])
            peer.height = int(message.get("height", 0))
            peer.work = int(message.get("work", 0))
        except (KeyError, TypeError, ValueError):
            self._record("bad_hello", peer.address)
            peer.close()
            return
        if peer.genesis != self.handler.chain.genesis_hash:
            self._record("wrong_network", peer.address)
            peer.close()
            return
        self._record("hello", f"{peer.address} height={peer.height}")
        # 双向交换定位器：只有这样才能发现「同高度但不同分支」的对端
        await peer.send({"type": "getblocks", "locator": self._locator(),
                         "limit": self.max_blocks_per_request})

    def _resolve_locator(self, locator) -> int:
        """在本地主链上找定位器里第一个已知的区块，返回「从哪个高度开始发」。"""
        chain = self.handler.chain
        for hexed in locator or ():
            try:
                raw = bytes.fromhex(hexed)
            except (TypeError, ValueError):
                continue
            height = chain.height_of(raw)
            if height is not None:
                return height + 1
        # 完全不认识对方的历史：从创世之后开始发（创世块人人都有）
        return 1

    async def _serve_blocks(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        if message.get("locator") is not None:
            from_height = self._resolve_locator(message.get("locator"))
        else:
            from_height = int(message.get("from_height", 0))
        limit = min(int(message.get("limit", self.max_blocks_per_request)),
                    self.max_blocks_per_request)
        blocks = self.handler.get_blocks(from_height, limit)
        await peer.send({
            "type": "blocks",
            "blocks": [block.to_hex() for block in blocks],
            "done": len(blocks) < limit,
            "from_height": from_height,
        })
        self._record("serve_blocks", f"{peer.address} from={from_height} count={len(blocks)}")

    def _guard_pow(self, block: Block) -> bool:
        """进孤儿池之前先验 PoW：否则任何人都能用垃圾块把池子灌满。"""
        if block.has_valid_pow():
            return True
        self._record("bad_pow", block.block_hash_hex()[:16])
        return False

    async def _receive_blocks(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        raw_blocks = message.get("blocks") or []
        for hexed in raw_blocks:
            try:
                block = Block.from_hex(hexed)
            except (ValueError, IndexError):
                self._record("malformed_block", peer.address)
                continue
            if not self._guard_pow(block):
                continue
            parent = block.header.prev_block
            chain = self.handler.chain
            if parent != chain.genesis_hash and not chain.known(parent):
                # 批次按高度递增发送，正常不会走到这里；真走到就先挂起来
                if len(self.orphans) < self.max_orphans:
                    self.orphans[block.block_hash()] = block
                continue
            result = await self._try_connect_block(block, exclude=peer)
            if result is not None:
                await self._process_orphans(block.block_hash())
        self._record("sync", f"{peer.address} +{len(raw_blocks)} blocks")
        if not message.get("done"):
            await peer.send({"type": "getblocks", "locator": self._locator(),
                             "limit": self.max_blocks_per_request})

    async def _on_inventory(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        kind = message.get("kind")
        missing = self._missing_ids(kind, message.get("ids") or [])
        if missing:
            await peer.send({"type": "getdata", "kind": kind, "ids": missing})

    def _missing_ids(self, kind: str, ids: list[str]) -> list[str]:
        chain = self.handler.chain
        missing = []
        for hexed in ids:
            try:
                raw = bytes.fromhex(hexed)
            except ValueError:
                continue
            if kind == "block":
                if not chain.known(raw):
                    missing.append(hexed)
            elif kind == "tx":
                if chain.get_transaction(raw) is None and raw not in self.handler.mempool:
                    missing.append(hexed)
        return missing

    async def _serve_data(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        kind = message.get("kind")
        for hexed in message.get("ids") or []:
            try:
                raw = bytes.fromhex(hexed)
            except ValueError:
                continue
            if kind == "block":
                block = self.handler.chain.get_block(raw)
                if block is not None:
                    await peer.send({"type": "block", "block": block.to_hex()})
            elif kind == "tx":
                entry = self.handler.mempool.get(raw)
                if entry is not None:
                    await peer.send({"type": "tx", "tx": entry.tx.to_hex()})

    async def _receive_block(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        try:
            block = Block.from_hex(message["block"])
        except (KeyError, ValueError, IndexError):
            self._record("malformed_block", peer.address)
            return
        if not self._guard_pow(block):
            return

        parent = block.header.prev_block
        chain = self.handler.chain
        if parent != chain.genesis_hash and not chain.known(parent):
            # 父块还没到：先存着并向对端要父块（否则这个块永远接不上）
            if len(self.orphans) < self.max_orphans:
                self.orphans[block.block_hash()] = block
            self._record("orphan", f"{block.block_hash_hex()[:16]} 缺少父块")
            await peer.send({"type": "getdata", "kind": "block", "ids": [parent.hex()]})
            return

        result = await self._try_connect_block(block, exclude=peer)
        if result is not None:
            # 即使这个块只是侧链，它也可能正是某个孤儿的父块 —— 必须继续解开
            await self._process_orphans(block.block_hash())

    async def _try_connect_block(self, block: Block,
                                 *, exclude: PeerConnection | None = None):
        """把一个区块交给链；若它成为链尖（或触发重组）则向其他对等体公告。"""
        result = self.handler.on_block(block)
        if result is not None and result.status in ("connected", "reorg"):
            self._record("accepted_block", f"高度 {result.height}（{result.status}）")
            await self.broadcast({"type": "inv", "kind": "block",
                                  "ids": [block.block_hash().hex()]}, exclude=exclude)
        else:
            self._record("ignored_block", block.block_hash_hex()[:16])
        return result

    async def _process_orphans(self, parent_hash: bytes) -> None:
        """父块到位后，把之前挂起来的孤儿块依次尝试接上（支持链式孤儿）。"""
        children = [block for block in self.orphans.values()
                    if block.header.prev_block == parent_hash]
        for child in children:
            self.orphans.pop(child.block_hash(), None)
            self._record("orphan_resolved", child.block_hash_hex()[:16])
            result = await self._try_connect_block(child)
            if result is not None:
                await self._process_orphans(child.block_hash())

    async def _receive_transaction(self, peer: PeerConnection, message: dict[str, Any]) -> None:
        try:
            tx = Transaction.from_hex(message["tx"])
        except (KeyError, ValueError, IndexError):
            self._record("malformed_tx", peer.address)
            return
        if self.handler.on_transaction(tx):
            self._record("accepted_tx", tx.txid_hex()[:16])
            await self.broadcast({"type": "inv", "kind": "tx", "ids": [tx.txid().hex()]},
                                 exclude=peer)

    # -- 广播 ------------------------------------------------------------- #

    async def broadcast(self, message: dict[str, Any], *, exclude: PeerConnection | None = None) -> int:
        sent = 0
        for peer in list(self.peers):
            if peer is exclude or peer.closed:
                continue
            try:
                await peer.send(message)
                sent += 1
            except (ConnectionError, OSError, RuntimeError):
                peer.close()
        return sent

    async def announce_block(self, block: Block) -> int:
        return await self.broadcast({"type": "inv", "kind": "block",
                                     "ids": [block.block_hash().hex()]})

    async def announce_transaction(self, tx: Transaction) -> int:
        return await self.broadcast({"type": "inv", "kind": "tx", "ids": [tx.txid().hex()]})

    # -- 展示 ------------------------------------------------------------- #

    def stats(self) -> dict:
        return {
            "name": self.name,
            "listen": f"{self.host}:{self.bound_port or self.port}",
            "peers": [{"address": peer.address, "direction": peer.direction,
                       "height": peer.height} for peer in self.peers],
            "events": len(self.events),
        }

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"P2PNode({self.name!r}, peers={len(self.peers)})"

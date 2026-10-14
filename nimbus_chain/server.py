"""区块链浏览器 / 存证验证页面（标准库 ``http.server``，零前端构建）。

页面刻意只有一个内联 HTML + 原生 JS：没有 npm、没有打包器、没有第三方 CDN。
这不是为了"炫技式的零依赖"，而是让评审可以在断网环境下 `python -m nimbus_chain
serve` 之后直接看到全部证据。

页面上的三件事：

* **浏览链**：高度、链尖、累计工作量、UTXO 数、每个区块的交易与 Merkle 根。
* **存证验证**：把一段文本上链，然后「验证通过」→「改一个字节」→「验证失败」。
  这是整个项目最直观的价值主张展示。
* **轻客户端对比**：同一个结论，全节点需要多少字节、SPV 只要多少字节。
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .block import bits_to_target
from .chain import Chain, InvalidBlock
from .mempool import Mempool, MempoolError
from .notary import DIGEST_SIZE, Notary
from .script import extract_op_return, is_op_return, is_p2pkh, is_p2sh
from .spv import SPVClient
from .wallet import Wallet, WalletError

__all__ = ["ExplorerConfig", "ExplorerServer", "PAGE_HTML"]


@dataclass
class ExplorerConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    max_blocks: int = 200
    max_transactions_per_block: int = 64


class ExplorerServer:
    """把一条链 + 钱包暴露成一个小型浏览器服务。

    既可以在 CLI 里阻塞运行，也可以在测试里以线程方式起停（``port=0`` 让系统分配）。
    """

    def __init__(self, chain: Chain, *, wallet: Wallet | None = None,
                 mempool: Mempool | None = None, notary: Notary | None = None,
                 config: ExplorerConfig | None = None, mine=None) -> None:
        self.chain = chain
        self.config = config or ExplorerConfig()
        self.wallet = wallet
        self.mempool = mempool if mempool is not None else Mempool(chain)
        self.notary = notary or (Notary(chain, wallet, self.mempool) if wallet else None)
        self.mine = mine                        # 可选的外部挖矿回调（例如 FullNode.mine_block）
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- 生命周期 --------------------------------------------------------- #

    @property
    def port(self) -> int | None:
        if self._httpd is None:
            return None
        return self._httpd.server_address[1]

    def url(self) -> str:
        port = self.port if self.port is not None else self.config.port
        return f"http://{self.config.host}:{port}/"

    def start(self) -> int:
        """在后台线程里启动服务，返回实际端口（非阻塞）。"""
        if self._httpd is not None:
            return self.port
        handler = _make_handler(self)
        self._httpd = ThreadingHTTPServer((self.config.host, self.config.port), handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def serve_forever(self) -> None:
        """阻塞式运行（CLI 用）。"""
        if self._httpd is None:
            self._httpd = ThreadingHTTPServer((self.config.host, self.config.port),
                                             _make_handler(self))
            self._httpd.daemon_threads = True
        try:
            self._httpd.serve_forever()
        finally:
            self._httpd.server_close()
            self._httpd = None

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- 挖矿 ------------------------------------------------------------- #

    def _mine_one(self):
        if self.mine is not None:
            return self.mine()
        if self.wallet is None or not self.wallet.key_count:
            raise WalletError("没有可用的收款地址，无法挖矿")
        transactions = self.mempool.select_for_block(
            max_transactions=self.config.max_transactions_per_block)
        block = self.chain.build_and_mine(transactions, self.wallet.first_script())
        self.chain.add_block(block)
        self.mempool.remove_for_block(block)
        self.mempool.refresh()
        return block

    # -- 序列化辅助 ------------------------------------------------------- #

    @staticmethod
    def _script_kind(script: bytes) -> str:
        if is_op_return(script):
            return "OP_RETURN"
        if is_p2pkh(script):
            return "P2PKH"
        if is_p2sh(script):
            return "P2SH"
        return "nonstandard"

    def _block_payload(self, block, *, include_transactions: bool = False) -> dict:
        height = self.chain.height_of(block.block_hash())
        payload = {
            "height": height,
            "hash": block.block_hash_hex(),
            "prev_block": block.header.prev_block[::-1].hex(),
            "merkle_root": block.header.merkle_root[::-1].hex(),
            "timestamp": block.header.timestamp,
            "bits": f"0x{block.header.bits:08x}",
            "difficulty": round(2 ** 256 / (bits_to_target(block.header.bits) + 1), 2),
            "nonce": block.header.nonce,
            "transactions": len(block.transactions),
            "size": block.size(),
            "on_main_chain": self.chain.is_on_main_chain(block.block_hash()) if height is not None else False,
        }
        if include_transactions:
            payload["txs"] = [self._transaction_payload(tx, block=block) for tx in block.transactions]
        return payload

    def _transaction_payload(self, tx, *, block=None) -> dict:
        location = self.chain.transaction_location(tx.txid())
        payload = {
            "txid": tx.txid_hex(),
            "coinbase": tx.is_coinbase(),
            "inputs": len(tx.inputs),
            "outputs": len(tx.outputs),
            "value": tx.total_out(),
            "size": len(tx.serialize()),
            "locktime": tx.locktime,
            "op_return": [payload.hex() for payload in tx.data_carrier_outputs()],
            "height": location[1] if location else None,
            "confirmations": self.chain.confirmations(tx.txid()),
            "inputs_detail": [
                {"txid": tx_in.prev_txid[::-1].hex(), "index": tx_in.prev_index,
                 "coinbase": tx_in.is_coinbase()}
                for tx_in in tx.inputs
            ],
            "outputs_detail": [
                {"value": tx_out.value, "script": self._script_kind(tx_out.script_pubkey),
                 "data": (extract_op_return(tx_out.script_pubkey).hex()
                          if is_op_return(tx_out.script_pubkey)
                          and extract_op_return(tx_out.script_pubkey) is not None else None)}
                for tx_out in tx.outputs
            ],
        }
        if block is not None:
            index = block.transaction_index(tx.txid())
            if index is not None:
                payload["merkle_proof_length"] = len(block.merkle_proof_for(index))
        return payload

    def _chain_payload(self) -> dict:
        blockchain_bytes = sum(block.size() for block in self.chain.main_blocks())
        header_bytes = 80 * (self.chain.height + 1)
        next_bits = self.chain.next_block_bits()
        return {
            "height": self.chain.height,
            "tip": self.chain.tip.block_hash_hex(),
            "genesis": self.chain.genesis_hash[::-1].hex(),
            "total_work": self.chain.total_work,
            "utxo_count": len(self.chain.utxo),
            "known_blocks": len(self.chain._index),
            "reorgs": self.chain.reorg_count,
            "next_bits": f"0x{next_bits:08x}",
            "next_difficulty": round(2 ** 256 / (bits_to_target(next_bits) + 1), 2),
            "retarget_interval": self.chain.params.retarget_interval,
            "coinbase_maturity": self.chain.params.coinbase_maturity,
            "blockchain_bytes": blockchain_bytes,
            "header_bytes": header_bytes,
            "header_ratio": round(header_bytes / blockchain_bytes, 5) if blockchain_bytes else None,
            "mempool": self.mempool.stats(),
            "wallet_address": (self.wallet.address()
                               if self.wallet is not None and self.wallet.key_count else None),
            "wallet_balance": (self.wallet.balance(self.chain)
                              if self.wallet is not None and self.wallet.key_count else None),
        }

    def _spv_payload(self, txid_hex: str) -> dict | None:
        try:
            raw_txid = bytes.fromhex(txid_hex)[::-1]
        except ValueError:
            return None
        location = self.chain.transaction_location(raw_txid)
        if location is None:
            return None
        block_hash, height, index = location
        block = self.chain.get_block(block_hash)
        if block is None:                                    # pragma: no cover - 侧链块
            return None
        proof = block.merkle_proof_for(index)
        client = SPVClient(self.chain.params)
        client.sync_from_chain(self.chain)
        verified = client.verify_transaction_inclusion(raw_txid, block_hash, proof)
        return {
            "txid": txid_hex,
            "block_hash": block_hash[::-1].hex(),
            "height": height,
            "confirmations": self.chain.confirmations(raw_txid),
            "proof_length": len(proof),
            "proof": [
                {"sibling": sibling.hex(), "direction": direction}
                for sibling, direction in proof
            ],
            "verified": verified,
            "headers_checked": len(client),
            "header_bytes": client.local_bytes(),
            "blockchain_bytes": sum(b.size() for b in self.chain.main_blocks()),
            "note": "轻客户端只校验了区块头与一条 Merkle 路径，没有下载任何交易列表",
        }

    def _anchors_payload(self, limit: int | None) -> list[dict]:
        if self.notary is None:
            return []
        return [record.to_dict() for record in self.notary.anchors(limit=limit)]

    # -- 路由 ------------------------------------------------------------- #

    def handle_get(self, request: BaseHTTPRequestHandler) -> None:  # noqa: C901 - 路由表
        parts = urlsplit(request.path)
        path = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query)

        try:
            if path == "/":
                self._send_html(request, PAGE_HTML)
            elif path in ("/api/chain", "/api/status"):
                self._send_json(request, self._chain_payload())
            elif path == "/api/blocks":
                limit = _int_arg(query, "limit", 10)
                offset = _int_arg(query, "offset", 0)
                blocks = []
                height = self.chain.height - offset
                while height >= 0 and len(blocks) < min(limit, self.config.max_blocks):
                    block = self.chain.block_at_height(height)
                    if block is None:
                        break
                    blocks.append(self._block_payload(block, include_transactions=True))
                    height -= 1
                self._send_json(request, {"blocks": blocks, "height": self.chain.height})
            elif path.startswith("/api/block/"):
                block_hash = path.rsplit("/", 1)[-1]
                block = self._lookup_block(block_hash)
                if block is None:
                    self._send_json(request, {"error": "block not found"}, status=404)
                else:
                    self._send_json(request, self._block_payload(block, include_transactions=True))
            elif path.startswith("/api/tx/"):
                txid = path.rsplit("/", 1)[-1]
                try:
                    raw = bytes.fromhex(txid)[::-1]
                except ValueError:
                    self._send_json(request, {"error": "malformed txid"}, status=400)
                    return
                tx = self.chain.get_transaction(raw)
                if tx is None:
                    entry = self.mempool.get(raw)
                    if entry is None:
                        self._send_json(request, {"error": "transaction not found"}, status=404)
                    else:
                        payload = self._transaction_payload(entry.tx)
                        payload["mempool"] = True
                        payload["fee"] = entry.fee
                        payload["fee_rate"] = round(entry.fee_rate, 3)
                        self._send_json(request, payload)
                else:
                    self._send_json(request, self._transaction_payload(tx))
            elif path == "/api/mempool":
                self._send_json(request, {
                    "stats": self.mempool.stats(),
                    "transactions": self.mempool.summary(limit=25),
                })
            elif path == "/api/anchors":
                limit_raw = query.get("limit", [None])[0]
                limit = int(limit_raw) if limit_raw else None
                self._send_json(request, {"anchors": self._anchors_payload(limit)})
            elif path == "/api/address":
                if self.wallet is None or not self.wallet.key_count:
                    self._send_json(request, {"error": "server has no wallet"}, status=503)
                else:
                    self._send_json(request, {
                        "addresses": self.wallet.addresses(),
                        "balance": self.wallet.balance(self.chain),
                        "utxos": len(self.wallet.utxos(self.chain)),
                    })
            elif path == "/api/spv":
                txid = query.get("txid", [""])[0]
                payload = self._spv_payload(txid) if txid else None
                if payload is None:
                    self._send_json(request, {"error": "transaction not found on the main chain"},
                                    status=404)
                else:
                    self._send_json(request, payload)
            elif path == "/api/verify":
                digest_hex = query.get("digest", [""])[0]
                try:
                    digest = bytes.fromhex(digest_hex)
                except ValueError:
                    digest = b""
                if len(digest) != DIGEST_SIZE:
                    self._send_json(request, {"error": "digest must be 32 bytes of hex"}, status=400)
                elif self.notary is None:
                    self._send_json(request, {"error": "server has no wallet, cannot verify"},
                                    status=503)
                else:
                    self._send_json(request, self.notary.verify_digest(digest).to_dict())
            elif path == "/api/spv-vs-full":
                blockchain_bytes = sum(b.size() for b in self.chain.main_blocks())
                self._send_json(request, {
                    "height": self.chain.height,
                    "blockchain_bytes": blockchain_bytes,
                    "header_bytes": 80 * (self.chain.height + 1),
                    "ratio": round((80 * (self.chain.height + 1)) / blockchain_bytes, 5)
                    if blockchain_bytes else None,
                })
            else:
                self._send_json(request, {"error": "not found", "path": path}, status=404)
        except (InvalidBlock, WalletError, MempoolError, ValueError) as error:
            self._send_json(request, {"error": str(error)}, status=400)
        except Exception as error:                            # pragma: no cover - 兜底
            self._send_json(request, {"error": f"internal error: {error}"}, status=500)

    def handle_post(self, request: BaseHTTPRequestHandler) -> None:  # noqa: C901 - 路由表
        parts = urlsplit(request.path)
        path = parts.path.rstrip("/") or "/"
        body = self._read_body(request)
        if body is None:
            return

        try:
            if path == "/api/notarize":
                if self.notary is None:
                    self._send_json(request, {"error": "server has no wallet, cannot notarise"},
                                    status=503)
                    return
                data = _document_from_body(body)
                if data is None:
                    self._send_json(request, {"error": "provide 'content' or 'hex'"}, status=400)
                    return
                notarization = self.notary.notarize(data)
                self.mempool.add_transaction(notarization.tx)
                mine = bool(body.get("mine"))
                mined = self._mine_one() if mine else None
                payload = notarization.to_dict()
                payload["in_mempool"] = True
                payload["mine_requested"] = mine
                if mined is not None:
                    payload["mined_block"] = mined.block_hash_hex()
                payload["verification"] = self.notary.verify(data).to_dict()
                self._send_json(request, payload)
            elif path == "/api/verify":
                if self.notary is None:
                    self._send_json(request, {"error": "server has no wallet, cannot verify"},
                                    status=503)
                    return
                data = _document_from_body(body)
                if data is None:
                    self._send_json(request, {"error": "provide 'content' or 'hex'"}, status=400)
                    return
                use_spv = bool(body.get("spv"))
                client = self._fresh_spv_client() if use_spv else None
                self._send_json(request, self.notary.verify(data, spv=client).to_dict())
            elif path == "/api/mine":
                block = self._mine_one()
                self._send_json(request, self._block_payload(block, include_transactions=True))
            else:
                self._send_json(request, {"error": "not found", "path": path}, status=404)
        except (InvalidBlock, WalletError, MempoolError, ValueError) as error:
            self._send_json(request, {"error": str(error)}, status=400)
        except Exception as error:                            # pragma: no cover - 兜底
            self._send_json(request, {"error": f"internal error: {error}"}, status=500)

    def _fresh_spv_client(self) -> SPVClient | None:
        """新建一个轻客户端并同步到链尖（模拟"另一个验证者"）。"""
        client = SPVClient(self.chain.params)
        client.sync_from_chain(self.chain)
        return client

    def _lookup_block(self, block_hash_hex: str):
        try:
            raw = bytes.fromhex(block_hash_hex)[::-1]
        except ValueError:
            return None
        return self.chain.get_block(raw)

    def _read_body(self, request: BaseHTTPRequestHandler) -> dict | None:
        try:
            length = int(request.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > 4 * 1024 * 1024:
            self._send_json(request, {"error": "request body too large"}, status=413)
            return None
        raw = request.rfile.read(length)
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            self._send_json(request, {"error": f"malformed json: {error}"}, status=400)
            return None
        if not isinstance(payload, dict):
            self._send_json(request, {"error": "json body must be an object"}, status=400)
            return None
        return payload

    # -- 响应 ------------------------------------------------------------- #

    def _send(self, request: BaseHTTPRequestHandler, body: bytes, content_type: str,
              status: int = 200) -> None:
        request.send_response(status)
        request.send_header("Content-Type", content_type)
        request.send_header("Content-Length", str(len(body)))
        request.send_header("Cache-Control", "no-store")
        request.end_headers()
        if request.command == "HEAD":
            return
        try:
            request.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):       # pragma: no cover - 客户端提前断开
            pass

    def _send_json(self, request: BaseHTTPRequestHandler, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=None).encode("utf-8")
        self._send(request, body, "application/json; charset=utf-8", status)

    def _send_html(self, request: BaseHTTPRequestHandler, text: str) -> None:
        self._send(request, text.encode("utf-8"), "text/html; charset=utf-8")


def _int_arg(query: dict, name: str, default: int) -> int:
    raw = query.get(name, [None])[0]
    try:
        return int(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default


def _document_from_body(body: dict) -> bytes | None:
    if isinstance(body.get("hex"), str):
        try:
            return bytes.fromhex(body["hex"])
        except ValueError:
            return None
    if isinstance(body.get("content"), str):
        return body["content"].encode("utf-8")
    return None


def _make_handler(server: ExplorerServer):
    """生成绑定到 ``server`` 的请求处理器类（避免全局状态）。"""

    class _Handler(BaseHTTPRequestHandler):
        server_version = "NimbusChainExplorer/1.0"
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            server.handle_get(self)

        def do_HEAD(self) -> None:
            server.handle_get(self)

        def do_POST(self) -> None:
            server.handle_post(self)

        def log_message(self, *args) -> None:                # 静音，避免污染 CLI 输出
            return

    return _Handler


PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NimbusChain · 浏览器与存证验证</title>
<style>
  :root {
    --bg: #0f1420; --panel: #171e2e; --panel2: #1e2739; --line: #2b3650;
    --text: #e6ecf7; --dim: #90a0bd; --accent: #5ee0b0; --accent2: #7cb2ff;
    --bad: #ff7a7a; --good: #5ee0b0; --warn: #ffd479;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font-family: system-ui, -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; }
  header { padding: 22px 28px 14px; border-bottom: 1px solid var(--line); }
  h1 { margin: 0 0 6px; font-size: 21px; letter-spacing: .3px; }
  header p { margin: 0; color: var(--dim); font-size: 13px; }
  main { padding: 20px 28px 60px; max-width: 1180px; }
  section { margin-bottom: 26px; }
  h2 { font-size: 15px; margin: 0 0 10px; color: var(--accent2);
       text-transform: uppercase; letter-spacing: .8px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
  .card .k { color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: .6px; }
  .card .v { font-family: var(--mono); font-size: 17px; margin-top: 6px; word-break: break-all; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
  textarea { width: 100%; min-height: 130px; background: var(--panel2); color: var(--text);
             border: 1px solid var(--line); border-radius: 8px; padding: 10px;
             font-family: var(--mono); font-size: 13px; resize: vertical; }
  button { background: #24304a; color: var(--text); border: 1px solid var(--line);
           border-radius: 8px; padding: 9px 14px; font-size: 13px; cursor: pointer; margin: 8px 8px 0 0; }
  button:hover { border-color: var(--accent2); }
  button.primary { background: #1f6f57; border-color: #2e9b7b; }
  button.danger { background: #5a2a33; border-color: #8a3b48; }
  .verdict { margin-top: 12px; padding: 12px 14px; border-radius: 8px;
             border: 1px solid var(--line); background: var(--panel2); font-size: 13px; }
  .verdict.good { border-color: var(--good); }
  .verdict.bad { border-color: var(--bad); }
  .verdict .badge { font-family: var(--mono); font-weight: 700; margin-right: 8px; }
  .verdict.good .badge { color: var(--good); }
  .verdict.bad .badge { color: var(--bad); }
  .verdict .why { color: var(--dim); margin-top: 6px; }
  dl.meta { display: grid; grid-template-columns: 116px 1fr; gap: 4px 12px; margin: 8px 0 0; font-size: 12px; }
  dl.meta dt { color: var(--dim); }
  dl.meta dd { margin: 0; font-family: var(--mono); word-break: break-all; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--line); }
  th { color: var(--dim); font-weight: 600; font-size: 11px; text-transform: uppercase; }
  td.mono, span.mono { font-family: var(--mono); }
  tr.detail td { background: var(--panel2); }
  .tag { font-family: var(--mono); font-size: 11px; padding: 1px 6px; border-radius: 5px;
         border: 1px solid var(--line); color: var(--accent2); }
  .tag.data { color: var(--warn); }
  .muted { color: var(--dim); }
  .bar { height: 8px; border-radius: 4px; background: var(--accent); min-width: 2px; }
  #toast { position: fixed; right: 20px; bottom: 20px; background: var(--panel2);
           border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px;
           font-size: 13px; opacity: 0; transition: opacity .25s; pointer-events: none; }
  #toast.show { opacity: 1; }
</style>
</head>
<body>
<header>
  <h1>NimbusChain · 链浏览器与存证验证</h1>
  <p>零第三方依赖、纯 Python 从零实现的区块链。下面所有数字都来自这个进程里真实运行的链。</p>
</header>
<main>
  <section>
    <h2>链状态</h2>
    <div class="grid" id="stats"></div>
  </section>

  <section>
    <h2>存证验证（tamper-evident notarisation）</h2>
    <div class="panel">
      <p class="muted" style="margin-top:0;font-size:13px">
        把一段文本的 SHA-256 写进链上的 OP_RETURN 输出。原始文件不会上链，链上只有 32 字节指纹。
        区块链保证的是「<b>可检测</b>篡改」，不是「阻止篡改」。
      </p>
      <textarea id="doc"></textarea>
      <div>
        <button class="primary" onclick="notarize()">存证上链（含挖矿确认）</button>
        <button onclick="verify()">验证</button>
        <button onclick="verifySpv()">验证（用 SPV 轻客户端）</button>
        <button class="danger" onclick="tamper()">篡改一个字节后验证</button>
        <button onclick="resetDoc()">重置文本</button>
      </div>
      <div id="verdict" class="verdict" style="display:none"></div>
      <dl class="meta" id="digestMeta"></dl>
    </div>
  </section>

  <section>
    <h2>轻客户端 vs 全节点</h2>
    <div class="grid" id="spvStats"></div>
    <div class="panel" style="margin-top:10px" id="spvPanel">
      <p class="muted" style="margin-top:0;font-size:13px">
        同一个「这笔交易确实在链上」的结论，全节点要保存全部区块；SPV 只保存区块头 + 一条 Merkle 路径。
      </p>
      <dl class="meta" id="spvMeta"></dl>
    </div>
  </section>

  <section>
    <h2>最近区块</h2>
    <table id="blocks"><thead><tr>
      <th>高度</th><th>区块哈希</th><th>交易</th><th>时间戳</th><th>难度</th><th>nonce</th><th>大小</th>
    </tr></thead><tbody></tbody></table>
  </section>

  <section>
    <h2>链上存证记录</h2>
    <table id="anchors"><thead><tr>
      <th>摘要 (SHA-256)</th><th>交易</th><th>高度</th><th>确认数</th>
    </tr></thead><tbody></tbody></table>
  </section>

  <section>
    <h2>交易池</h2>
    <div class="panel">
      <div id="mempoolStats" class="muted" style="font-size:13px"></div>
      <table id="mempool"><thead><tr>
        <th>交易</th><th>手续费</th><th>聪/字节</th><th>输入</th><th>输出</th>
      </tr></thead><tbody></tbody></table>
      <button onclick="mine()">立刻挖一个块</button>
    </div>
  </section>
</main>
<div id="toast"></div>
<script>
const API = "";
let CURRENT_DIGEST = null;

function esc(text) {
  return String(text).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function toast(message) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove("show"), 2600);
}
async function getJSON(path) {
  const response = await fetch(API + path);
  return await response.json();
}
async function postJSON(path, payload) {
  const response = await fetch(API + path, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  return await response.json();
}

function card(key, value) {
  return '<div class="card"><div class="k">' + esc(key) + '</div><div class="v">' + esc(value) + '</div></div>';
}
function renderStats(chain) {
  document.getElementById("stats").innerHTML =
    card("高度", chain.height) +
    card("链尖", chain.tip.slice(0, 20) + "…") +
    card("累计工作量", chain.total_work) +
    card("UTXO", chain.utxo_count) +
    card("已见区块", chain.known_blocks) +
    card("重组次数", chain.reorgs) +
    card("下一个 bits", chain.next_bits) +
    card("下一个难度", chain.next_difficulty) +
    card("交易池", chain.mempool.transactions) +
    card("钱包余额 (聪)", chain.wallet_balance === null ? "—" : chain.wallet_balance);
}
function renderSpv(chain) {
  const ratio = chain.header_ratio === null ? "—" : (chain.header_ratio * 100).toFixed(3) + " %";
  document.getElementById("spvStats").innerHTML =
    card("全节点存储", chain.blockchain_bytes + " B") +
    card("轻客户端存储", chain.header_bytes + " B") +
    card("占比", ratio) +
    card("难度重定目标间隔", chain.retarget_interval + " 块") +
    card("coinbase 成熟度", chain.coinbase_maturity + " 块");
}

function tag(text, cls) {
  return '<span class="tag' + (cls ? ' ' + cls : '') + '">' + esc(text) + '</span>';
}
function renderBlocks(payload) {
  const body = document.querySelector("#blocks tbody");
  body.innerHTML = payload.blocks.map(block => {
    const txs = block.txs.map(tx =>
      '<tr><td colspan="7" class="muted">' +
      '<span class="mono">' + esc(tx.txid.slice(0, 28)) + '…</span> · ' +
      (tx.coinbase ? tag("coinbase") : tag(tx.inputs + " in / " + tx.outputs + " out")) +
      (tx.op_return.length ? ' · ' + tag("OP_RETURN " + tx.op_return[0].slice(0, 16) + "…", "data") : '') +
      ' · Merkle 路径 ' + (tx.merkle_proof_length || 0) + ' 个哈希' +
      ' · ' + esc(tx.value) + ' 聪</td></tr>'
    ).join("");
    return '<tr><td class="mono">' + block.height + '</td>' +
      '<td class="mono" title="' + esc(block.hash) + '">' + esc(block.hash.slice(0, 22)) + '…</td>' +
      '<td>' + block.transactions + '</td>' +
      '<td class="mono">' + block.timestamp + '</td>' +
      '<td class="mono">' + block.difficulty + '</td>' +
      '<td class="mono">' + block.nonce + '</td>' +
      '<td class="mono">' + block.size + ' B</td></tr>' + txs;
  }).join("") || '<tr><td colspan="7" class="muted">还没有区块</td></tr>';
}
function renderAnchors(payload) {
  const body = document.querySelector("#anchors tbody");
  body.innerHTML = payload.anchors.map(record =>
    '<tr><td class="mono">' + esc(record.digest) + '</td>' +
    '<td class="mono">' + esc(record.txid.slice(0, 22)) + '…</td>' +
    '<td class="mono">' + record.height + '</td>' +
    '<td class="mono">' + record.confirmations + '</td></tr>'
  ).join("") || '<tr><td colspan="4" class="muted">还没有存证记录，试试上面的「存证上链」</td></tr>';
}
function renderMempool(payload) {
  const stats = payload.stats;
  document.getElementById("mempoolStats").textContent =
    stats.transactions + " 笔 · " + stats.bytes + " 字节 · 手续费合计 " + stats.total_fees + " 聪";
  const body = document.querySelector("#mempool tbody");
  body.innerHTML = payload.transactions.map(tx =>
    '<tr><td class="mono">' + esc(tx.txid.slice(0, 22)) + '…</td>' +
    '<td class="mono">' + tx.fee + '</td>' +
    '<td class="mono">' + tx.fee_rate + '</td>' +
    '<td class="mono">' + tx.inputs + '</td>' +
    '<td class="mono">' + tx.outputs + '</td></tr>'
  ).join("") || '<tr><td colspan="5" class="muted">空</td></tr>';
}
function renderVerdict(result) {
  const el = document.getElementById("verdict");
  el.style.display = "block";
  el.className = "verdict " + (result.valid ? "good" : "bad");
  el.innerHTML = '<span class="badge">' + (result.valid ? "✔ 验证通过" : "✘ 验证失败") + '</span>' +
    '<span class="mono">' + esc(result.digest.slice(0, 24)) + '…</span>' +
    '<div class="why">' + esc(result.reason) + '</div>' +
    '<dl class="meta">' +
    '<dt>链上已存在</dt><dd>' + result.present + '</dd>' +
    '<dt>已确认</dt><dd>' + result.confirmed + '</dd>' +
    '<dt>SPV 证明</dt><dd>' + (result.spv_verified === undefined ? "—" : result.spv_verified) + '</dd>' +
    '<dt>交易</dt><dd>' + esc(result.txid || "—") + '</dd>' +
    '<dt>高度</dt><dd>' + (result.height === null ? "—" : result.height) + '</dd>' +
    '<dt>确认数</dt><dd>' + result.confirmations + '</dd>' +
    '</dl>';
}

async function refresh() {
  const chain = await getJSON("/api/chain");
  renderStats(chain);
  renderSpv(chain);
  renderBlocks(await getJSON("/api/blocks?limit=6"));
  renderAnchors(await getJSON("/api/anchors?limit=12"));
  renderMempool(await getJSON("/api/mempool"));
}
async function digestOf(text) {
  // WebCrypto 需要安全上下文；通过非 localhost 的 http 访问时它不可用，
  // 此时退化：页面不显示本地指纹，验证仍以服务端的 SHA-256 为准。
  if (!window.crypto || !window.crypto.subtle) return null;
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function showDigest() {
  const digest = await digestOf(document.getElementById("doc").value);
  CURRENT_DIGEST = digest;
  document.getElementById("digestMeta").innerHTML =
    '<dt>本地 SHA-256</dt><dd>' + esc(digest || "（当前浏览器不提供 WebCrypto，以服务端计算为准）") + '</dd>';
}
function resetDoc() {
  document.getElementById("doc").value = SAMPLE;
  showDigest();
  document.getElementById("verdict").style.display = "none";
}
function tamper() {
  const box = document.getElementById("doc");
  const bytes = new TextEncoder().encode(box.value);
  bytes[0] = bytes[0] ^ 0x01;                       // 只翻转第一个字节的 1 个 bit
  box.value = new TextDecoder("utf-8", {fatal: false}).decode(bytes);
  toast("已翻转第一个字节的 1 个 bit");
  showDigest();
  verify();
}
async function notarize() {
  const content = document.getElementById("doc").value;
  const result = await postJSON("/api/notarize", {content: content, mine: true});
  if (result.error) { toast("存证失败：" + result.error); return; }
  toast("已上链确认：" + result.txid.slice(0, 16) + "…");
  renderVerdict(result.verification);
  await refresh();
}
async function verify() {
  const content = document.getElementById("doc").value;
  const result = await postJSON("/api/verify", {content: content});
  if (result.error) { toast("验证失败：" + result.error); return; }
  renderVerdict(result);
}
async function verifySpv() {
  const content = document.getElementById("doc").value;
  const result = await postJSON("/api/verify", {content: content, spv: true});
  if (result.error) { toast("验证失败：" + result.error); return; }
  renderVerdict(result);
  if (result.txid) {
    const spv = await getJSON("/api/spv?txid=" + encodeURIComponent(result.txid));
    if (!spv.error) {
      document.getElementById("spvMeta").innerHTML =
        '<dt>交易</dt><dd>' + esc(spv.txid) + '</dd>' +
        '<dt>所在区块</dt><dd>' + esc(spv.block_hash) + '</dd>' +
        '<dt>Merkle 路径</dt><dd>' + spv.proof_length + ' 个哈希</dd>' +
        '<dt>轻客户端校验的头</dt><dd>' + spv.headers_checked + ' 个（' + spv.header_bytes + ' B）</dd>' +
        '<dt>全节点需保存</dt><dd>' + spv.blockchain_bytes + ' B</dd>' +
        '<dt>证明结论</dt><dd>' + spv.verified + '</dd>' +
        '<dt>说明</dt><dd>' + esc(spv.note) + '</dd>';
    }
  }
}
async function mine() {
  const block = await postJSON("/api/mine", {});
  if (block.error) { toast("挖矿失败：" + block.error); return; }
  toast("挖出高度 " + block.height + " 的区块");
  await refresh();
}

const SAMPLE = "合作协议 v3\\n甲方：Nimbus Labs\\n乙方：某客户\\n金额：1000 NBC\\n签署日期：2026-01-01\\n";
document.getElementById("doc").value = SAMPLE;
showDigest();
refresh();
</script>
</body>
</html>
"""

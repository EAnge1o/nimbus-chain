"""浏览器 / 存证验证页面测试：真实启动 HTTP 服务并请求每个端点。"""

from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request

from nimbus_chain.chain import Chain, ChainParams
from nimbus_chain.crypto import sha256
from nimbus_chain.mempool import Mempool
from nimbus_chain.notary import Notary, document_digest
from nimbus_chain.secp256k1 import PrivateKey
from nimbus_chain.server import ExplorerConfig, ExplorerServer
from nimbus_chain.wallet import Wallet

PARAMS = ChainParams(retarget_interval=1_000, coinbase_maturity=1)
DOCUMENT = "合作协议 v3\n金额：1000 NBC\n"


class ExplorerServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = Chain(PARAMS)
        cls.wallet = Wallet(name="explorer", keys=[PrivateKey(0x5EED)])
        for _ in range(3):
            cls.chain.add_block(cls.chain.build_and_mine([], cls.wallet.first_script()))
        cls.mempool = Mempool(cls.chain)
        cls.notary = Notary(cls.chain, cls.wallet, cls.mempool)
        cls.server = ExplorerServer(cls.chain, wallet=cls.wallet, mempool=cls.mempool,
                                    notary=cls.notary,
                                    config=ExplorerConfig(host="127.0.0.1", port=0))
        cls.port = cls.server.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    # -- HTTP 辅助 -------------------------------------------------------- #

    def anchor(self, content: str) -> str:
        """确保 ``content`` 已被锚定在主链上（幂等），返回摘要的十六进制。"""
        data = content.encode("utf-8")
        digest = document_digest(data)
        if self.notary.lookup(digest) is None:
            notarization = self.notary.notarize(data)
            self.mempool.add_transaction(notarization.tx)
            self.server._mine_one()
        return digest.hex()

    def get(self, path: str) -> tuple[int, object, str]:
        try:
            with urllib.request.urlopen(self.base + path, timeout=10) as response:
                raw = response.read()
                content_type = response.headers.get("Content-Type", "")
                status = response.status
        except urllib.error.HTTPError as error:
            raw = error.read()
            content_type = error.headers.get("Content-Type", "")
            status = error.code
        return status, _parse(raw, content_type), content_type

    def post(self, path: str, payload: dict) -> tuple[int, object]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=body, method="POST",
                                        headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, _parse(response.read(), response.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as error:
            return error.code, _parse(error.read(), error.headers.get("Content-Type", ""))

    # -- 页面 ------------------------------------------------------------- #

    def test_index_serves_html(self):
        status, body, content_type = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn("NimbusChain", body)
        self.assertIn("存证验证", body)
        self.assertIn("/api/notarize", body)          # 页面里的端点确实被内联引用
        self.assertIn("crypto.subtle", body)

    def test_head_request_has_no_body(self):
        request = urllib.request.Request(self.base + "/", method="HEAD")
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"")
            self.assertGreater(int(response.headers["Content-Length"]), 0)

    # -- 只读端点 --------------------------------------------------------- #

    def test_chain_endpoint(self):
        status, payload, _ = self.get("/api/chain")
        self.assertEqual(status, 200)
        self.assertEqual(payload["height"], self.chain.height)
        self.assertEqual(payload["utxo_count"], len(self.chain.utxo))
        self.assertEqual(payload["wallet_address"], self.wallet.address())
        self.assertGreater(payload["blockchain_bytes"], payload["header_bytes"])
        self.assertGreater(payload["header_ratio"], 0)
        self.assertIn("mempool", payload)

    def test_status_alias(self):
        status, payload, _ = self.get("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(payload["height"], self.chain.height)

    def test_blocks_endpoint(self):
        status, payload, _ = self.get("/api/blocks?limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["blocks"]), 2)
        self.assertEqual(payload["blocks"][0]["height"], self.chain.height)   # 最新的在前
        self.assertEqual(payload["blocks"][1]["height"], self.chain.height - 1)
        tip = payload["blocks"][0]
        self.assertEqual(len(tip["txs"]), tip["transactions"])
        self.assertTrue(tip["txs"][0]["coinbase"])          # 首笔永远是 coinbase
        if len(tip["txs"]) == 1:
            self.assertEqual(tip["txs"][0]["merkle_proof_length"], 0)   # 单叶区块路径为空
        else:
            self.assertGreaterEqual(tip["txs"][0]["merkle_proof_length"], 1)

    def test_blocks_pagination(self):
        _, first, _ = self.get("/api/blocks?limit=2&offset=0")
        _, second, _ = self.get("/api/blocks?limit=2&offset=2")
        self.assertEqual(first["blocks"][0]["height"], self.chain.height)
        self.assertEqual(second["blocks"][0]["height"], self.chain.height - 2)

    def test_block_detail_by_hash(self):
        block_hash = self.chain.tip.block_hash_hex()
        status, payload, _ = self.get(f"/api/block/{block_hash}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["hash"], block_hash)
        self.assertEqual(payload["height"], self.chain.height)
        self.assertEqual(payload["transactions"], len(self.chain.tip.transactions))
        self.assertTrue(payload["on_main_chain"])

    def test_unknown_block_returns_404(self):
        status, payload, _ = self.get("/api/block/" + "ab" * 32)
        self.assertEqual(status, 404)
        self.assertIn("not found", payload["error"])

    def test_malformed_block_hash_returns_404(self):
        status, _, _ = self.get("/api/block/zzzz")
        self.assertEqual(status, 404)

    def test_transaction_detail(self):
        tx = self.chain.tip.transactions[0]
        status, payload, _ = self.get(f"/api/tx/{tx.txid_hex()}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["txid"], tx.txid_hex())
        self.assertEqual(payload["confirmations"], 1)
        self.assertTrue(payload["coinbase"])
        self.assertEqual(payload["outputs_detail"][0]["script"], "P2PKH")

    def test_unknown_transaction_returns_404(self):
        status, payload, _ = self.get("/api/tx/" + "cd" * 32)
        self.assertEqual(status, 404)
        self.assertIn("not found", payload["error"])

    def test_malformed_txid_returns_400(self):
        status, payload, _ = self.get("/api/tx/nothex")
        self.assertEqual(status, 400)
        self.assertIn("malformed", payload["error"])

    def test_mempool_endpoint(self):
        status, payload, _ = self.get("/api/mempool")
        self.assertEqual(status, 200)
        self.assertIn("stats", payload)
        self.assertIn("transactions", payload)

    def test_address_endpoint(self):
        status, payload, _ = self.get("/api/address")
        self.assertEqual(status, 200)
        self.assertEqual(payload["addresses"], [self.wallet.address()])
        self.assertGreater(payload["balance"], 0)

    def test_spv_vs_full_endpoint(self):
        status, payload, _ = self.get("/api/spv-vs-full")
        self.assertEqual(status, 200)
        self.assertEqual(payload["header_bytes"], 80 * (self.chain.height + 1))
        self.assertGreater(payload["blockchain_bytes"], payload["header_bytes"])
        self.assertLess(payload["ratio"], 1)

    def test_unknown_route_returns_404(self):
        status, payload, _ = self.get("/api/nope")
        self.assertEqual(status, 404)
        self.assertIn("not found", payload["error"])

    # -- 存证 ------------------------------------------------------------- #

    def test_notarize_then_verify_then_tamper(self):
        content = DOCUMENT
        status, payload = self.post("/api/notarize", {"content": content, "mine": True})
        self.assertEqual(status, 200, payload)
        digest = payload["digest"]
        self.assertEqual(digest, document_digest(content.encode()).hex())
        self.assertTrue(payload["verification"]["valid"])
        self.assertIsNotNone(payload["mined_block"])

        status, verified = self.post("/api/verify", {"content": content})
        self.assertEqual(status, 200)
        self.assertTrue(verified["valid"])
        self.assertGreaterEqual(verified["confirmations"], 1)

        status, spv_verified = self.post("/api/verify", {"content": content, "spv": True})
        self.assertEqual(status, 200)
        self.assertTrue(spv_verified["valid"])
        self.assertTrue(spv_verified["spv_verified"])

        tampered = content.replace("1000", "1001")
        status, failed = self.post("/api/verify", {"content": tampered})
        self.assertEqual(status, 200)
        self.assertFalse(failed["valid"])
        self.assertFalse(failed["present"])

    def test_notarize_with_hex_body(self):
        status, payload = self.post("/api/notarize", {"hex": "deadbeef", "mine": True})
        self.assertEqual(status, 200)
        self.assertEqual(payload["digest"], sha256(bytes.fromhex("deadbeef")).hex())

    def test_verify_by_digest(self):
        digest = self.anchor(DOCUMENT)
        status, payload, _ = self.get(f"/api/verify?digest={digest}")
        self.assertEqual(status, 200)
        self.assertTrue(payload["valid"])

    def test_verify_by_digest_rejects_wrong_length(self):
        status, payload, _ = self.get("/api/verify?digest=abcd")
        self.assertEqual(status, 400)
        self.assertIn("32 bytes", payload["error"])

    def test_anchors_listing(self):
        self.anchor("listing-test document body")
        status, payload, _ = self.get("/api/anchors")
        self.assertEqual(status, 200)
        self.assertTrue(payload["anchors"])
        record = payload["anchors"][0]
        self.assertEqual(len(record["digest"]), 64)
        self.assertIn("confirmations", record)

    def test_anchors_limit(self):
        status, payload, _ = self.get("/api/anchors?limit=1")
        self.assertEqual(status, 200)
        self.assertLessEqual(len(payload["anchors"]), 1)

    def test_mine_endpoint(self):
        before = self.chain.height
        status, payload = self.post("/api/mine", {})
        self.assertEqual(status, 200)
        self.assertEqual(payload["height"], before + 1)
        self.assertEqual(self.chain.height, before + 1)

    def test_notarize_without_body_content(self):
        status, payload = self.post("/api/notarize", {"nothing": True})
        self.assertEqual(status, 400)
        self.assertIn("content", payload["error"])

    def test_malformed_json_body(self):
        request = urllib.request.Request(self.base + "/api/verify", data=b"{not json",
                                        method="POST",
                                        headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        self.assertEqual(status, 400)
        self.assertIn("malformed json", json.loads(raw)["error"])

    def test_oversized_body_rejected(self):
        request = urllib.request.Request(
            self.base + "/api/verify", data=b"{}", method="POST",
            headers={"Content-Type": "application/json",
                     "Content-Length": str(8 * 1024 * 1024)})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        self.assertEqual(status, 413)

    def test_spv_proof_endpoint(self):
        tx = self.chain.tip.transactions[0]
        status, payload, _ = self.get(f"/api/spv?txid={tx.txid_hex()}")
        self.assertEqual(status, 200)
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["height"], self.chain.height)
        self.assertGreater(payload["header_bytes"], 0)
        self.assertIn("proof", payload)

    def test_spv_endpoint_without_txid(self):
        status, payload, _ = self.get("/api/spv")
        self.assertEqual(status, 404)
        self.assertIn("not found", payload["error"])


class ServerWithoutWalletTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(PARAMS)
        self.server = ExplorerServer(self.chain, config=ExplorerConfig(port=0))
        self.port = self.server.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.stop()

    def request(self, path: str, payload: dict | None = None) -> tuple[int, object]:
        if payload is None:
            try:
                with urllib.request.urlopen(self.base + path, timeout=10) as response:
                    return response.status, _parse(response.read(), "")
            except urllib.error.HTTPError as error:
                return error.code, _parse(error.read(), "")
        body = json.dumps(payload).encode()
        request = urllib.request.Request(self.base + path, data=body, method="POST",
                                        headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, _parse(response.read(), "")
        except urllib.error.HTTPError as error:
            return error.code, _parse(error.read(), "")

    def test_chain_still_browsable(self):
        status, payload = self.request("/api/chain")
        self.assertEqual(status, 200)
        self.assertIsNone(payload["wallet_address"])

    def test_notarize_needs_a_wallet(self):
        status, payload = self.request("/api/notarize", {"content": "x"})
        self.assertEqual(status, 503)
        self.assertIn("wallet", payload["error"])

    def test_verify_needs_a_wallet(self):
        status, payload = self.request("/api/verify", {"content": "x"})
        self.assertEqual(status, 503)

    def test_address_needs_a_wallet(self):
        status, payload = self.request("/api/address")
        self.assertEqual(status, 503)

    def test_stop_is_idempotent(self):
        self.server.stop()
        self.server.stop()
        self.assertIsNone(self.server.port)


def _parse(raw: bytes, content_type: str):
    if b"json" in content_type.encode() or raw[:1] in (b"[", b"{"):
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return raw.decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


if __name__ == "__main__":
    unittest.main()

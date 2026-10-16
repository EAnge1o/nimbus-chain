"""NimbusChain —— 零第三方依赖、从零实现的区块链（教学 / 竞赛 / 作品集项目）。

模块划分：

    crypto.py    纯 Python SHA-256 / SHA-256d / RIPEMD-160 / Base58Check + hashlib 快路径
    secp256k1.py 椭圆曲线点运算、ECDSA、RFC6979 确定性 nonce、DER、low-S
    merkle.py    Merkle 树与 Merkle 证明
    script.py    栈式脚本解释器（P2PKH / P2SH / 多签 / OP_RETURN / CLTV / CSV）
    tx.py        交易序列化、UTXO、sighash、coinbase 与减半
    block.py     区块头 / 区块、PoW、compact bits 难度
    chain.py     校验流水线、难度重定目标、累计工作量分叉选择与重组、UTXO set、持久化
    mempool.py   交易池：依赖、冲突、费用排序
    wallet.py    密钥 / 地址 / UTXO 追踪 / coin selection / 构造并签名交易
    p2p.py       asyncio gossip 协议与对等体管理
    node.py      全节点组装（chain + mempool + p2p + 挖矿）
    spv.py       只校验区块头的轻客户端 + Merkle 证明验证
    notary.py    应用层：文件哈希上链（OP_RETURN）与 SPV 验证
    server.py    标准库 http.server 的链浏览器 / 存证 Demo
    cli.py       命令行入口
"""

__version__ = "0.1.0"
__author__ = "EAnge1o"

__all__ = ["__version__", "enable_utf8_console"]

import sys as _sys


def enable_utf8_console() -> None:
    """把 stdout / stderr 切到 UTF-8 + 出错替换。

    本项目的输出里全是中文，还有 ``✔`` / ``✘`` 这类记号。而在 CI 或输出被重定向
    的场景下，Windows 上 Python 的 stdout 会退回 cp1252 / cp437 这类本地编码，
    于是 ``print`` 一句中文就会抛 ``UnicodeEncodeError``，把整个脚本打断。

    交互式终端本来就是 UTF-8（Windows 上 Python 直接走 WriteConsoleW），所以这里
    只在编码确实不是 UTF-8 时才动手，不影响正常终端体验。
    """
    for stream in (_sys.stdout, _sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").replace("-", "").lower()
        if encoding in ("utf8", ""):
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):     # pragma: no cover - 流不可重配
            pass

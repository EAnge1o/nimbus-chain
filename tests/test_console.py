"""控制台编码回归测试：CI / 输出被重定向时，打印中文不能把脚本打断。

这个 bug 真的在 CI 上发生过：Ubuntu 三个 Python 版本全绿，Windows 三个全挂在
``python demo.py`` 这一步。原因是输出被重定向后，Windows 上的 stdout 退回
cp1252 / cp437，``print("…中文…")`` 直接抛 ``UnicodeEncodeError``。

测试手法：用 ``PYTHONIOENCODING=cp1252`` 起子进程来**复现**那种环境——这个技巧在
Linux 上也有效（cp1252 是个合法 codec），所以它能在本地就挡住平台相关回归。
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


def run_with_console_encoding(encoding: str, args: list[str],
                              timeout: float = 300.0) -> subprocess.CompletedProcess:
    """在指定 stdout 编码下运行一个命令，捕获原始字节。"""
    environment = dict(os.environ)
    environment["PYTHONIOENCODING"] = encoding
    environment.pop("PYTHONUTF8", None)          # 避免被 UTF-8 模式覆盖
    return subprocess.run(
        [sys.executable, *args],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        timeout=timeout,
    )


def decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


class NonUtf8ConsoleTests(unittest.TestCase):
    """在「非 UTF-8 控制台」下，两个命令都必须正常跑完并输出中文。"""

    def test_demo_survives_a_legacy_console_encoding(self):
        result = run_with_console_encoding("cp1252", ["demo.py"])
        stdout = decode(result.stdout)
        self.assertEqual(result.returncode, 0,
                         f"demo.py 在 cp1252 控制台下失败\n"
                         f"--- stdout ---\n{stdout[-2000:]}\n"
                         f"--- stderr ---\n{decode(result.stderr)[-2000:]}")
        self.assertIn("演示结束", stdout)
        self.assertIn("全部通过", stdout)

    def test_cli_survives_a_legacy_console_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_with_console_encoding(
                "cp1252", ["-m", "nimbus_chain", "--data-dir", directory, "info"])
            stdout = decode(result.stdout)
            self.assertEqual(result.returncode, 0,
                             f"CLI 在 cp1252 控制台下失败\n{stdout[-2000:]}\n"
                             f"{decode(result.stderr)[-2000:]}")
            self.assertIn("高度", stdout)
            self.assertIn("共识参数", stdout)

    def test_cli_error_path_survives_too(self):
        """报错信息也是中文，同样不能在坏编码下崩掉。"""
        with tempfile.TemporaryDirectory() as directory:
            result = run_with_console_encoding(
                "cp1252", ["-m", "nimbus_chain", "--data-dir", directory,
                           "verify", "--text", "nothing was notarised"])
            self.assertEqual(result.returncode, 0)
            self.assertIn("验证失败", decode(result.stdout))

    def test_utf8_console_is_unaffected(self):
        """正常终端（UTF-8）下行为不变。"""
        with tempfile.TemporaryDirectory() as directory:
            result = run_with_console_encoding(
                "utf-8", ["-m", "nimbus_chain", "--data-dir", directory, "address"])
            stdout = decode(result.stdout)
            self.assertEqual(result.returncode, 0, stdout[-2000:])
            self.assertIn("地址", stdout)


class Utf8HelperTests(unittest.TestCase):
    def test_helper_is_idempotent_and_exported(self):
        from nimbus_chain import enable_utf8_console
        enable_utf8_console()
        enable_utf8_console()                    # 重复调用不应报错
        self.assertTrue(callable(enable_utf8_console))

    def test_helper_skips_streams_that_cannot_be_reconfigured(self):
        from nimbus_chain import enable_utf8_console
        import io
        original = sys.stdout
        try:
            sys.stdout = io.StringIO()           # 没有 encoding 属性、也不能重配
            enable_utf8_console()
        finally:
            sys.stdout = original


if __name__ == "__main__":
    unittest.main()

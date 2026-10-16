"""控制台编码回归测试：CI / 输出被重定向时，打印中文不能把脚本打断。

这个 bug 真的在 CI 上发生过两次：先是 Windows 三个 job 全挂在 ``python demo.py``，
修好 demo 之后又挂在 ``benchmarks/bench_crypto.py``——同一类问题的第二个受害脚本。
所以这里的做法是**把项目里所有会向控制台打印中文的入口集中列举**，逐个在
``PYTHONIOENCODING=cp1252`` 的子进程里跑一遍。以后新增入口时，把它加进
:func:`console_entry_points` 即可，遗漏会立刻被这个测试点名。

``PYTHONIOENCODING=cp1252`` 这个手法在 Linux 上也有效（cp1252 是合法 codec），
所以平台相关回归在本地就能挡住，不用等 CI。
"""

from __future__ import annotations

import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


def console_entry_points(data_dir: str) -> list[tuple[str, list[str]]]:
    """所有会向 stdout 打印中文的入口：``(标签, 命令参数)``。

    **新增控制台入口时请加到这里**，否则它不会被这条回归测试覆盖。
    """
    return [
        ("demo.py", ["demo.py"]),
        ("benchmarks/bench_crypto.py", ["benchmarks/bench_crypto.py", "--time", "0.02"]),
        ("benchmarks/bench_pow.py",
         ["benchmarks/bench_pow.py", "--time", "0.02", "--rounds", "2"]),
        ("cli info", ["-m", "nimbus_chain", "--data-dir", data_dir, "info"]),
        ("cli address", ["-m", "nimbus_chain", "--data-dir", data_dir, "address"]),
        # 挖 2 块：coinbase 成熟度 1，高度 2 时高度 1 的 coinbase 才可以花，
        # 后面那条 notarize 探针才有钱付手续费
        ("cli mine", ["-m", "nimbus_chain", "--data-dir", data_dir,
                      "--coinbase-maturity", "1", "mine", "--count", "2"]),
        ("cli notarize+verify", ["-m", "nimbus_chain", "--data-dir", data_dir,
                                 "--coinbase-maturity", "1",
                                 "notarize", "--text", "encoding probe", "--mine"]),
        ("cli spv", ["-m", "nimbus_chain", "--data-dir", data_dir,
                     "--coinbase-maturity", "1", "spv"]),
    ]


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


def has_cjk(text: str) -> bool:
    return any("\u4e00" <= character <= "\u9fff" for character in text)


class NonUtf8ConsoleTests(unittest.TestCase):
    """在「非 UTF-8 控制台」下，每个入口都必须跑完并真正输出中文。"""

    def test_every_console_entry_point_survives_a_legacy_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            for label, args in console_entry_points(directory):
                with self.subTest(entry_point=label):
                    result = run_with_console_encoding("cp1252", args)
                    stdout = decode(result.stdout)
                    self.assertEqual(
                        result.returncode, 0,
                        f"{label} 在 cp1252 控制台下失败：\n"
                        f"--- stdout ---\n{stdout[-1500:]}\n"
                        f"--- stderr ---\n{decode(result.stderr)[-1500:]}")
                    # 不只是「没崩」：中文必须真的写出来了（否则可能是被 replace 成了 '?'）
                    self.assertTrue(has_cjk(stdout),
                                    f"{label} 没输出中文，这条用例可能是空转")

    def test_cli_error_path_survives_too(self):
        """报错信息同样是中文，坏编码下也不能崩。"""
        with tempfile.TemporaryDirectory() as directory:
            result = run_with_console_encoding(
                "cp1252", ["-m", "nimbus_chain", "--data-dir", directory,
                           "verify", "--text", "nothing was notarised"])
            self.assertEqual(result.returncode, 0, decode(result.stderr)[-1500:])
            self.assertIn("验证失败", decode(result.stdout))

    def test_cp1252_really_reproduces_the_crash(self):
        """守住前提：如果这个环境不再能复现问题，上面的测试就失去意义了。"""
        result = run_with_console_encoding(
            "cp1252", ["-c", "print('中文')"])
        self.assertNotEqual(result.returncode, 0,
                            "cp1252 环境没能复现 UnicodeEncodeError，这条测试已失效")
        self.assertIn("UnicodeEncodeError", decode(result.stderr))

    def test_utf8_console_is_unaffected(self):
        """正常终端（UTF-8）下行为不变。"""
        with tempfile.TemporaryDirectory() as directory:
            result = run_with_console_encoding(
                "utf-8", ["-m", "nimbus_chain", "--data-dir", directory, "address"])
            stdout = decode(result.stdout)
            self.assertEqual(result.returncode, 0, stdout[-1500:])
            self.assertIn("地址", stdout)


class Utf8HelperTests(unittest.TestCase):
    def test_helper_is_idempotent_and_exported(self):
        from nimbus_chain import enable_utf8_console
        enable_utf8_console()
        enable_utf8_console()                    # 重复调用不应报错
        self.assertTrue(callable(enable_utf8_console))

    def test_helper_skips_streams_that_cannot_be_reconfigured(self):
        from nimbus_chain import enable_utf8_console
        original = sys.stdout
        try:
            sys.stdout = io.StringIO()           # 没有 encoding 属性、也不能重配
            enable_utf8_console()
        finally:
            sys.stdout = original


if __name__ == "__main__":
    unittest.main()

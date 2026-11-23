"""离线验证：`mcp_smoke_test.py` 的 Phase 0 失败是否**计入统计与退出码**。

背景（实测踩过）：`connect_wmpf` 曾因返回值类型错误（直接返回 dict，而工具签名是
`-> str`）**完全不可用**，但冒烟依然打印「61/61 通过」、退出码 0 —— 因为 Phase 0 的
`[FAIL]` 只 print 不计数。这个脚本用桩把 Phase 0 打成失败，断言它必须反映在结果里。

用假客户端替换 `McpHttpClient`，并用 `--only __none__` 让 61 条常规检查全部跳过，
于是最终数字只由 Phase 0 决定 —— 判定清晰、零副作用、不碰真机。
"""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mcp_smoke_test as smoke  # noqa: E402


def _text_result(text: str, *, is_error: bool = False) -> dict:
    """构造一个 tools/call 返回体。"""
    return {"result": {"isError": is_error, "content": [{"type": "text", "text": text}]}}


class FakeClient:
    """按脚本要求给每个工具返回预设结果。"""

    def __init__(self, *, host: str = "", port: int = 0, token: str = "", timeout: float = 0) -> None:
        self.script: dict[str, dict] = {}

    @property
    def endpoint_url(self) -> str:
        return "http://127.0.0.1:49999/mcp?token=stub"

    def initialize(self) -> dict:
        return {}

    def list_tools(self) -> list[dict]:
        return []

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        return self.script.get(name, _text_result("{}"))


def run_case(name: str, script: dict[str, dict]) -> tuple[int, str]:
    """跑一次 main()，返回 (退出码, 输出文本)。"""
    original = smoke.McpHttpClient
    fake = FakeClient()
    fake.script = script
    smoke.McpHttpClient = lambda **_kw: fake  # type: ignore[assignment]
    argv_backup = sys.argv[:]
    sys.argv = ["mcp_smoke_test.py", "--only", "__none__"]
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            code = smoke.main()
    finally:
        smoke.McpHttpClient = original  # type: ignore[assignment]
        sys.argv = argv_backup
    return code, buf.getvalue()


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        checks.append((label, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  —— {detail}" if detail and not ok else ""))

    print("=" * 78)
    print("Phase 0 计数修复验证（离线，桩客户端，零副作用）")
    print("=" * 78)

    # 场景 1：Phase 0 全通过 → 退出码 0，结果 2/2
    code, out = run_case(
        "all-ok",
        {
            "connect_wmpf": _text_result('{"ok": true, "connected": true}'),
            "network_enable": _text_result('{"ok": true}'),
        },
    )
    check("场景1 全通过 → 退出码 0", code == 0, f"实际 {code}")
    check("场景1 结果行 = 2/2", "=== 结果：2/2 通过 ===" in out, out.strip().splitlines()[-1] if out.strip() else "")
    check("场景1 无失败项", "失败项" not in out)

    # 场景 2：connect_wmpf 返回 ok:false → 必须计入失败 + 退出码 1
    code, out = run_case(
        "connect-fail",
        {
            "connect_wmpf": _text_result('{"ok": false, "error": "boom"}'),
            "network_enable": _text_result('{"ok": true}'),
        },
    )
    check("场景2 connect_wmpf 失败 → 退出码 1", code == 1, f"实际 {code}")
    check("场景2 结果行 = 1/2（失败被计入）", "=== 结果：1/2 通过 ===" in out, out.strip().splitlines()[-1] if out.strip() else "")
    check("场景2 失败项列出 phase0/connect_wmpf", "phase0/connect_wmpf" in out)

    # 场景 3：工具层直接报错（isError）→ 同样必须计入
    code, out = run_case(
        "transport-error",
        {
            "connect_wmpf": _text_result("pydantic validation error", is_error=True),
            "network_enable": _text_result('{"ok": true}'),
        },
    )
    check("场景3 isError → 退出码 1", code == 1, f"实际 {code}")
    check("场景3 结果行 = 1/2", "=== 结果：1/2 通过 ===" in out)

    # 场景 4：调用直接抛异常 → 也必须计入（此前 except 分支同样只 print）
    class Boom(FakeClient):
        def call_tool(self, name: str, arguments: dict | None = None) -> dict:
            if name == "connect_wmpf":
                raise RuntimeError("connection refused")
            return _text_result('{"ok": true}')

    original = smoke.McpHttpClient
    smoke.McpHttpClient = lambda **_kw: Boom()  # type: ignore[assignment]
    argv_backup = sys.argv[:]
    sys.argv = ["mcp_smoke_test.py", "--only", "__none__"]
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            code = smoke.main()
    finally:
        smoke.McpHttpClient = original  # type: ignore[assignment]
        sys.argv = argv_backup
    out = buf.getvalue()
    check("场景4 抛异常 → 退出码 1", code == 1, f"实际 {code}")
    check("场景4 结果行 = 1/2", "=== 结果：1/2 通过 ===" in out)
    check("场景4 失败项含 connection refused", "connection refused" in out)

    print()
    passed = sum(1 for _l, ok, _d in checks if ok)
    print("=" * 78)
    print(f"=== 结果：{passed} passed / {len(checks) - passed} failed ===")
    print("=" * 78)
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())

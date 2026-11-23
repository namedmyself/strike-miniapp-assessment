"""验证 network_ops 的参数透传语义（P0-2 / P0-3 的回归护栏）。

重点验证「值为 None 的参数不能透传」这条约束：
实现层用的是 `bool(kwargs.get("compact", True))` 这种「键不存在才取默认值」
的写法，一旦显式传 None 就会被 `bool(None) -> False` 顶掉默认值。

用法：
    "D:/Python 12.4/python.exe" scripts/verify_network_ops_passthrough.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "e0e1-wx"))

from package.mcp_control import skill_docs  # noqa: E402
from package.mcp_control.local_app import create_mcp_app  # noqa: E402


class FakeSession:
    """记录 session.network_ops 收到的 kwargs。"""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def network_ops(self, action: str, **kwargs: Any) -> str:
        self.calls.append({"action": action, **kwargs})
        return json.dumps({"ok": True, "action": action, "received": kwargs})


def check(label: str, cond: bool) -> bool:
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    return cond


async def call(mcp: Any, args: dict[str, Any]) -> dict[str, Any]:
    result = await mcp.call_tool("network_ops", args)
    # FastMCP 返回 (content_blocks, structured) 或 content list，统一取文本
    text = ""
    if isinstance(result, tuple):
        blocks = result[0]
    else:
        blocks = result
    for block in blocks or []:
        text += getattr(block, "text", "") or ""
    return json.loads(text) if text else {}


async def main() -> int:
    skill_docs.SKILL_GATE.mark_loaded()  # 绕过 skill 门禁，直测参数透传

    failed = False

    # --- 场景 1：只传 action，不传可选参数 ---
    print("场景 1：network_ops(action='get_recent_requests')，不传可选参数")
    fake = FakeSession()
    mcp = create_mcp_app(runtime=fake)
    await call(mcp, {"action": "get_recent_requests"})
    kw = fake.calls[-1]
    print(f"       透传到 session 的键: {sorted(kw)}")
    failed |= not check("excludeStatic 未被显式传 None（保住实现层默认 True）", "excludeStatic" not in kw)
    failed |= not check("compact 未被显式传 None（保住实现层默认 True）", "compact" not in kw)

    # --- 场景 2：显式传 excludeStatic=true ---
    print("\n场景 2：network_ops(action='get_all_requests', excludeStatic=true)")
    fake = FakeSession()
    mcp = create_mcp_app(runtime=fake)
    await call(mcp, {"action": "get_all_requests", "excludeStatic": True})
    kw = fake.calls[-1]
    print(f"       透传到 session 的键: {sorted(kw)}")
    failed |= not check("excludeStatic 已透传且为 True", kw.get("excludeStatic") is True)

    # --- 场景 3：snake_case 别名 ---
    print("\n场景 3：network_ops(action='get_all_requests', exclude_static=true)  [snake_case]")
    fake = FakeSession()
    mcp = create_mcp_app(runtime=fake)
    await call(mcp, {"action": "get_all_requests", "exclude_static": True})
    kw = fake.calls[-1]
    failed |= not check("exclude_static 归一化为 excludeStatic=True", kw.get("excludeStatic") is True)

    # --- 场景 4：excludeStatic=false 必须真的传出去（不能被当成「未传」） ---
    print("\n场景 4：network_ops(action='get_all_requests', excludeStatic=false)  [显式 false]")
    fake = FakeSession()
    mcp = create_mcp_app(runtime=fake)
    await call(mcp, {"action": "get_all_requests", "excludeStatic": False})
    kw = fake.calls[-1]
    failed |= not check("显式 false 被透传（不是被当作未传而丢失）", kw.get("excludeStatic") is False)

    # --- 场景 5：compact=false ---
    print("\n场景 5：network_ops(action='get_recent_requests', compact=false)")
    fake = FakeSession()
    mcp = create_mcp_app(runtime=fake)
    await call(mcp, {"action": "get_recent_requests", "compact": False})
    kw = fake.calls[-1]
    failed |= not check("compact=false 被透传", kw.get("compact") is False)

    # --- 场景 6：maxLength ---
    print("\n场景 6：network_ops(action='get_request_detail', requestId='x', maxLength=1234)")
    fake = FakeSession()
    mcp = create_mcp_app(runtime=fake)
    await call(mcp, {"action": "get_request_detail", "requestId": "x", "maxLength": 1234})
    kw = fake.calls[-1]
    failed |= not check("maxLength=1234 被透传", kw.get("maxLength") == 1234)

    print("\n=== 结果：" + ("FAIL" if failed else "ALL PASS") + " ===")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

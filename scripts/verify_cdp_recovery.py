#!/usr/bin/env python3
"""离线验证：CDP 链路卡死时的恢复路径（实战发现）。

背景（2026-09-22 实战踩到）：
链路卡死时 `status().cdp.pendingCalls > 0`（调用发出后收不到响应），
此时旧实现里 `connect_wmpf` 会因 `is_connected()` 仍为真而 `reused: true` 直接返回、
**什么都不做** —— 恢复路径变成死胡同，只能重启整个 MCP 服务（代价：丢掉已采集流量）。

修法：
1. `LocalCdpClient.connect(force=True)` 跳过复用分支，重建连接；
2. 重建时 `_close_locked(fail_pending=True)` —— 否则堆积的 pending 永远清不掉
   （旧代码是 `fail_pending=False`，那正是 `pendingCalls` 清不掉的直接原因）；
3. `McpRuntimeSession.connect_wmpf` 在检测到「已连接 + pendingCalls>0」时**自动重建**。

本脚本用假 WebSocket 跑真实 `LocalCdpClient`，不连真机。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "e0e1-wx"))

from package.mcp_control import cdp_client as cc  # noqa: E402
from package.mcp_control.cdp_client import LocalCdpClient, PendingCdpCall  # noqa: E402
from package.mcp_control.runtime_session import McpRuntimeSession  # noqa: E402

WS = "ws://127.0.0.1:62000"

PASSED = 0
FAILED = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  [PASS] {label}")
    else:
        FAILED += 1
        print(f"  [FAIL] {label}")
    if detail:
        print(f"         {detail}")


class FakeWs:
    """最小假 WebSocket：能被 close()，迭代时挂住（不产生事件）。"""

    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        await asyncio.sleep(3600)
        raise StopAsyncIteration


class FakeConnect:
    """替换 websockets.connect，记录每次调用的目标。"""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.sockets: list[FakeWs] = []

    async def __call__(self, target, **_kwargs):
        self.calls.append(target)
        ws = FakeWs()
        self.sockets.append(ws)
        return ws


def add_stuck_pending(client: LocalCdpClient, n: int) -> None:
    """塞入 n 个「已发出但永不返回」的调用，模拟链路卡死。"""
    loop = asyncio.get_event_loop()
    for i in range(n):
        client.pending[1000 + i] = PendingCdpCall(
            future=loop.create_future(), method=f"Runtime.evaluate#{i}"
        )


# —— 1. 客户端层：force 必须跳过复用分支 ——
async def test_client_force() -> None:
    print("\n[1] LocalCdpClient.connect —— force 跳过复用")
    fake = FakeConnect()
    original = cc.websockets.connect
    cc.websockets.connect = fake  # type: ignore[assignment]
    try:
        client = LocalCdpClient()
        r1 = await client.connect(WS)
        check("首次连接 reused=False", r1.get("reused") is False, f"{r1}")
        check("首次连接 connectionId=1", r1.get("connectionId") == 1, f"{r1}")

        r2 = await client.connect(WS)
        check("健康连接复用 reused=True", r2.get("reused") is True, f"{r2}")
        check("复用时不重建（connect 只被调 1 次）", len(fake.calls) == 1, f"calls={len(fake.calls)}")

        r3 = await client.connect(WS, force=True)
        check("force=True 时不复用 reused=False", r3.get("reused") is False, f"{r3}")
        check("force=True 确实重建了（connect 被调 2 次）", len(fake.calls) == 2, f"calls={len(fake.calls)}")
        check("force=True 后 connectionId 递增到 2", r3.get("connectionId") == 2, f"{r3}")

        await client.close()
    finally:
        cc.websockets.connect = original  # type: ignore[assignment]


# —— 2. 客户端层：force 重建必须清掉堆积的 pending ——
async def test_client_force_clears_pending() -> None:
    print("\n[2] force 重建必须清掉 pendingCalls（否则等于没修）")
    fake = FakeConnect()
    original = cc.websockets.connect
    cc.websockets.connect = fake  # type: ignore[assignment]
    try:
        client = LocalCdpClient()
        await client.connect(WS)
        add_stuck_pending(client, 3)
        check("已塞入 3 个卡住的调用", len(client.pending) == 3, f"pending={len(client.pending)}")

        await client.connect(WS, force=True)
        check("force 重建后 pending 被清空", len(client.pending) == 0, f"pending={len(client.pending)}")

        # 对照：非 force 的复用不会清（这是旧行为，保留给「健康连接」场景）
        add_stuck_pending(client, 2)
        await client.connect(WS)
        check("复用路径不清 pending（旧行为不变）", len(client.pending) == 2, f"pending={len(client.pending)}")

        await client.close()
    finally:
        cc.websockets.connect = original  # type: ignore[assignment]


# —— 3. 会话层：卡死时自动重建 ——
async def test_session_auto_rebuild() -> None:
    print("\n[3] McpRuntimeSession.connect_wmpf —— 卡死时自动重建")

    async def noop_enable(*, force: bool = False) -> None:
        return None

    async def fake_status() -> dict:
        return {"ok": True, "cdp": {"pendingCalls": 0}}

    session = McpRuntimeSession()
    session._enable_domains = noop_enable  # type: ignore[assignment]
    session.status = fake_status  # type: ignore[assignment]

    captured: dict = {}

    async def fake_connect(url=None, *, force=False):
        captured["force"] = force
        captured["url"] = url
        return {"connected": True, "wsUrl": WS, "reused": not force, "connectionId": 1}

    session.cdp.connect = fake_connect  # type: ignore[assignment]

    # 3a. 健康连接 → 不重建
    session.cdp.is_connected = lambda: True  # type: ignore[assignment]
    session.cdp.pending = {}
    r = await session.connect_wmpf()
    check("健康连接时不重建（force=False）", captured.get("force") is False, f"force={captured.get('force')}")
    check("健康连接时不给 rebuiltBecause", "rebuiltBecause" not in r, f"{list(r)}")

    # 3b. 卡死连接 → 自动重建
    loop = asyncio.get_event_loop()
    session.cdp.pending = {
        1: PendingCdpCall(future=loop.create_future(), method="Runtime.evaluate"),
        2: PendingCdpCall(future=loop.create_future(), method="Runtime.evaluate"),
    }
    r = await session.connect_wmpf()
    check("卡死时自动重建（force=True）", captured.get("force") is True, f"force={captured.get('force')}")
    check("rebuiltBecause=pending_calls", r.get("rebuiltBecause") == "pending_calls", f"{r.get('rebuiltBecause')}")
    check("如实报告丢弃了几个调用", r.get("droppedPendingCalls") == 2, f"{r.get('droppedPendingCalls')}")
    check("note 说明已自动重建", "重建" in str(r.get("note")), f"{str(r.get('note'))[:80]}")
    check("note 提醒需重新 find_appservice", "find_appservice" in str(r.get("note")))

    # 3c. 显式 force
    session.cdp.pending = {}
    r = await session.connect_wmpf(force=True)
    check("显式 force 也重建", captured.get("force") is True)
    check("rebuiltBecause=force", r.get("rebuiltBecause") == "force", f"{r.get('rebuiltBecause')}")

    # 3d. 未连接时不误报 rebuiltBecause
    session.cdp.is_connected = lambda: False  # type: ignore[assignment]
    r = await session.connect_wmpf()
    check("未连接时 force=False（正常首连）", captured.get("force") is False)
    check("未连接时不给 rebuiltBecause", "rebuiltBecause" not in r, f"{list(r)}")


# —— 4. ws_url 缺省走 DEFAULT_WS_URL ——
async def test_default_url() -> None:
    print("\n[4] ws_url 缺省时走 DEFAULT_WS_URL")

    async def noop_enable(*, force: bool = False) -> None:
        return None

    async def fake_status() -> dict:
        return {"ok": True}

    session = McpRuntimeSession()
    session._enable_domains = noop_enable  # type: ignore[assignment]
    session.status = fake_status  # type: ignore[assignment]
    captured: dict = {}

    async def fake_connect(url=None, *, force=False):
        captured["url"] = url
        return {"connected": True, "reused": False}

    session.cdp.connect = fake_connect  # type: ignore[assignment]
    session.cdp.is_connected = lambda: False  # type: ignore[assignment]
    session.cdp.pending = {}

    await session.connect_wmpf()
    check("缺省 url 不是 None/空串", bool(captured.get("url")), f"url={captured.get('url')!r}")
    check("缺省 url 是本地 ws", str(captured.get("url", "")).startswith("ws://127.0.0.1"), f"{captured.get('url')}")


def main() -> int:
    print("=" * 78)
    print("CDP 链路卡死时的恢复路径验证")
    print("=" * 78)

    asyncio.run(test_client_force())
    asyncio.run(test_client_force_clears_pending())
    asyncio.run(test_session_auto_rebuild())
    asyncio.run(test_default_url())

    print()
    print("=" * 78)
    print(f"结果：{PASSED} passed / {FAILED} failed")
    print("=" * 78)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

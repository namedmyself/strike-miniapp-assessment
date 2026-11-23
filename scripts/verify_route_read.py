#!/usr/bin/env python3
"""验证路由读取的降级链与时间契约（P0-4 / P0-5）。

## 背景

实测（2026-09-22）暴露两个同源缺陷：

* `wait_route_stable(timeout=8)` **实跑 15.01s** 且 `route: ""`；
* `get_basic_page_info().snapshot.route` **恒为空串**，而同一次返回里的
  `routeFromAppservice` 明明有值。

根因是两条独立缺陷叠加：

1. `current_route()` 用 `except Exception: return ""` 吞掉异常 —— 而 `runtime_eval`
   的 CDP 超时是 **15s**（`timeout_ms=15000`）。appservice context 失效时求值挂满
   15s，然后被伪装成「当前没有路由」，调用方据此把**成功的导航误判为失败**；
2. `wait_route_stable` 只在**每轮迭代开始时**检查 deadline，单次 `current_route()`
   的耗时完全不受 `timeout_seconds` 约束 —— 于是 `timeout` 参数形同虚设；
3. 快照 expr 读的是 `globalThis.__wxRoute`，该全局在 WMPF 里**不存在**。

## 本脚本验证什么

用注入式假 `runtime_eval` 离线复现上述场景（端到端测不到「context 失效」和
「求值挂死」），断言：

1. `route_from_eval` 的形态兼容；
2. `read_route_detail` 的降级链与失败上报；
3. **单次读路由受硬超时约束**（不再挂满 15s）；
4. **`wait_route_stable` 的时间契约**：总耗时 ≤ `timeout_seconds` + 余量；
5. **`dump_runtime_snapshot` 的 route 回填**：page-frame 空 → 用降级链值补齐；
6. `current_route()` 的向后兼容（仍返回裸字符串）。

用法：python scripts/verify_route_read.py
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "e0e1-wx"))

from package.mcp_control.runtime_session import (  # noqa: E402
    APPSERVICE_ROUTE_EXPR,
    NAVIGATOR_ROUTE_EXPR,
    ROUTE_READ_TIMEOUT_SECONDS,
    McpRuntimeSession,
    route_from_eval,
)

PASSED = 0
FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    """记录一条断言结果。"""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [PASS] {label}")
    else:
        FAILED += 1
        print(f"  [FAIL] {label}" + (f"  -> {detail}" if detail else ""))


def make_session(eval_fn, *, appservice_context_id: int | None = 4) -> McpRuntimeSession:
    """构造一个脱离 CDP 的会话，并把 `runtime_eval` 换成给定的假函数。"""
    session = McpRuntimeSession()
    session.selected_appservice_context_id = appservice_context_id
    session.runtime_eval = eval_fn  # type: ignore[method-assign]
    return session


async def fake_status() -> dict:
    """`dump_runtime_snapshot` 末尾会调 `status()`，这里给个最小实现。"""
    return {"ok": True, "stubbed": True}


async def test_route_from_eval() -> None:
    """[1] `route_from_eval` 要兼容对象与裸字符串两种返回形态。"""
    print("\n[1] route_from_eval 形态兼容")
    check("对象形态 {route}", route_from_eval({"ok": True, "value": {"route": "pages/a/b"}}) == "pages/a/b")
    check("裸字符串形态", route_from_eval({"ok": True, "value": "pages/c/d"}) == "pages/c/d")
    check("空 route 视为未取到", route_from_eval({"ok": True, "value": {"route": ""}}) == "")
    check("非 dict 结果不炸", route_from_eval("oops") == "")
    check("value 为 None 不炸", route_from_eval({"ok": True, "value": None}) == "")
    check("前后空白被裁掉", route_from_eval({"ok": True, "value": {"route": "  pages/e  "}}) == "pages/e")


async def test_read_route_detail_chain() -> None:
    """[2] 降级链：appservice 优先，取不到才走 `__routeNavigator`。"""
    print("\n[2] read_route_detail 降级链")
    seen: list[str] = []

    async def eval_appservice_ok(expr, **kwargs):
        seen.append(expr)
        return {"ok": True, "value": {"route": "pages/from/appservice"}}

    session = make_session(eval_appservice_ok)
    detail = await session.read_route_detail()
    check("appservice 命中 -> ok=True", detail.get("ok") is True)
    check("appservice 命中 -> source 正确", detail.get("source") == "appservice", repr(detail.get("source")))
    check("appservice 命中 -> 不再调 routeNavigator", len(seen) == 1, f"实际调用 {len(seen)} 次")

    async def eval_fallback(expr, **kwargs):
        if expr == APPSERVICE_ROUTE_EXPR:
            return {"ok": True, "value": {"route": ""}}
        if expr == NAVIGATOR_ROUTE_EXPR:
            return {"ok": True, "value": {"route": "pages/from/navigator"}}
        return {"ok": False, "error": "unexpected expression"}

    session = make_session(eval_fallback)
    detail = await session.read_route_detail()
    check("appservice 为空 -> 降级命中", detail.get("route") == "pages/from/navigator", repr(detail.get("route")))
    check("降级后 source=routeNavigator", detail.get("source") == "routeNavigator")
    check("attempts 记录两个源", len(detail.get("attempts") or []) == 2, str(detail.get("attempts")))

    async def eval_all_fail(expr, **kwargs):
        return {"ok": False, "error": "boom"}

    session = make_session(eval_all_fail)
    detail = await session.read_route_detail()
    check("全失败 -> ok=False（不再伪装成空串）", detail.get("ok") is False)
    check("全失败 -> route 为空", detail.get("route") == "")
    check("全失败 -> 带 error", bool(detail.get("error")))
    check("全失败 -> 带 hint", bool(detail.get("hint")))
    check("全失败 -> attempts 完整", len(detail.get("attempts") or []) == 2)

    session = make_session(eval_fallback, appservice_context_id=None)
    detail = await session.read_route_detail()
    check("未选中 appservice -> 仍能降级", detail.get("route") == "pages/from/navigator")
    check("未选中 appservice -> attempts 说明原因", "未选中" in str(detail.get("attempts")), str(detail.get("attempts")))


async def test_read_timeout_budget() -> None:
    """[3] 单次读路由必须被硬超时截断，不能挂满 `runtime_eval` 的 15s。"""
    print("\n[3] read_route_detail 硬超时（不再挂满 15s）")

    async def eval_hang(expr, **kwargs):
        await asyncio.sleep(30)
        return {"ok": True, "value": {"route": "too-late"}}

    session = make_session(eval_hang)
    started = time.time()
    detail = await session.read_route_detail(timeout_seconds=1.0)
    elapsed = time.time() - started
    check("挂死求值被截断", elapsed < 2.5, f"elapsed={elapsed:.2f}s")
    check("超时后 ok=False", detail.get("ok") is False)
    check("attempts 记录失败", any(not a.get("ok") for a in (detail.get("attempts") or [])))


async def test_wait_route_stable_contract() -> None:
    """[4] `wait_route_stable` 的时间契约与 ok 语义（P0-4 核心）。"""
    print("\n[4] wait_route_stable 时间契约（P0-4 核心）")

    async def eval_stable(expr, **kwargs):
        return {"ok": True, "value": {"route": "pages/stable/page"}}

    session = make_session(eval_stable)
    started = time.time()
    result = await session.wait_route_stable(timeout_seconds=8, settle_seconds=1.0)
    elapsed = time.time() - started
    check("稳定场景 -> ok=True", result.get("ok") is True)
    check("稳定场景 -> route 正确", result.get("route") == "pages/stable/page", repr(result.get("route")))
    check("稳定场景 -> routeSource 标注", result.get("routeSource") == "appservice", repr(result.get("routeSource")))
    check("稳定场景 -> elapsed 不超 timeout", elapsed <= 8.5, f"elapsed={elapsed:.2f}s")
    check("稳定场景 -> 回显 timeoutSeconds", result.get("timeoutSeconds") == 8.0, repr(result.get("timeoutSeconds")))

    async def eval_hang(expr, **kwargs):
        await asyncio.sleep(30)
        return {"ok": True, "value": {"route": "never"}}

    session = make_session(eval_hang)
    started = time.time()
    result = await session.wait_route_stable(timeout_seconds=3, settle_seconds=1.0)
    elapsed = time.time() - started
    ceiling = 3.0 + ROUTE_READ_TIMEOUT_SECONDS + 0.5
    check("读不到 -> 总耗时受 timeout 约束", elapsed <= ceiling, f"elapsed={elapsed:.2f}s > {ceiling:.2f}s")
    check("读不到 -> ok=False（不再假成功）", result.get("ok") is False)
    check("读不到 -> stable=False", result.get("stable") is False)
    check("读不到 -> 带 error", bool(result.get("error")))
    check("读不到 -> 带 hint", bool(result.get("hint")))
    check("读不到 -> 记录 failures", len(result.get("failures") or []) >= 1)


async def test_snapshot_route_backfill() -> None:
    """[5] `dump_runtime_snapshot` 在 page-frame 读不到 route 时要用降级链回填（P0-5 核心）。"""
    print("\n[5] dump_runtime_snapshot 的 route 回填（P0-5 核心）")

    async def eval_pageframe_empty(expr, **kwargs):
        if "document.title" in expr:
            return {
                "ok": True,
                "value": {
                    "href": "https://servicewechat.com/wxbc88787ccbada756/67/page-frame.html",
                    "title": "AppIndex",
                    "route": "",
                    "storage": {},
                    "visibleText": "",
                },
            }
        return {"ok": True, "value": {"route": "pages/other/tzs/collect"}}

    session = make_session(eval_pageframe_empty)
    session.status = fake_status  # type: ignore[method-assign]
    snapshot = await session.dump_runtime_snapshot()
    inner = snapshot.get("snapshot") or {}
    check("回填生效 -> snapshot.route 非空", inner.get("route") == "pages/other/tzs/collect", repr(inner.get("route")))
    check("回填生效 -> routeSource 标注", inner.get("routeSource") in {"appservice", "routeNavigator"}, repr(inner.get("routeSource")))
    check("顶层 routeSource 存在", "routeSource" in snapshot)
    check("顶层 routeReadOk=True", snapshot.get("routeReadOk") is True)
    check("顶层 routeFromAppservice 保留", snapshot.get("routeFromAppservice") == "pages/other/tzs/collect")

    async def eval_pageframe_ok(expr, **kwargs):
        if "document.title" in expr:
            return {
                "ok": True,
                "value": {
                    "href": "https://servicewechat.com/wxbc88787ccbada756/67/page-frame.html",
                    "title": "AppIndex",
                    "route": "pages/from/pageframe",
                    "storage": {},
                    "visibleText": "",
                },
            }
        return {"ok": True, "value": {"route": "pages/from/appservice"}}

    session = make_session(eval_pageframe_ok)
    session.status = fake_status  # type: ignore[method-assign]
    snapshot = await session.dump_runtime_snapshot()
    inner = snapshot.get("snapshot") or {}
    check("page-frame 有值 -> 不被覆盖", inner.get("route") == "pages/from/pageframe", repr(inner.get("route")))
    check("page-frame 有值 -> routeSource=page_frame", inner.get("routeSource") == "page_frame", repr(inner.get("routeSource")))


async def test_current_route_compat() -> None:
    """[6] `current_route()` 的签名不能变：既有调用点拿的是裸字符串。"""
    print("\n[6] current_route 向后兼容")

    async def eval_ok(expr, **kwargs):
        return {"ok": True, "value": {"route": "pages/compat/page"}}

    session = make_session(eval_ok)
    value = await session.current_route()
    check("成功 -> 返回裸字符串", isinstance(value, str) and value == "pages/compat/page", repr(value))

    async def eval_fail(expr, **kwargs):
        return {"ok": False, "error": "x"}

    session = make_session(eval_fail)
    value = await session.current_route()
    check("失败 -> 返回空串（兼容旧行为）", value == "", repr(value))


async def main() -> int:
    """跑完全部断言并汇总。"""
    print("=" * 62)
    print("路由读取验证（P0-4 时间契约 / P0-5 route 回填）")
    print("=" * 62)
    await test_route_from_eval()
    await test_read_route_detail_chain()
    await test_read_timeout_budget()
    await test_wait_route_stable_contract()
    await test_snapshot_route_backfill()
    await test_current_route_compat()
    print("\n" + "=" * 62)
    print(f"=== 结果：{PASSED} passed / {FAILED} failed ===")
    print("=" * 62)
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

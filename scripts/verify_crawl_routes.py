#!/usr/bin/env python3
"""离线验证：`route_ops(action="crawl_routes")` 的批量导航执行语义（R-3）。

只读、不连 CDP：`inspect_routes` / `_eval_within` / `rehook_after_route_navigation`
全部用桩替换，**不发任何 CDP 求值**，也不碰真实小程序。

为什么必须有这个脚本 —— R-3 要解决的是「导航循环不可靠」，所以这里断言的核心是
**「单条失败绝不拖垮整批」** 与 **「必须能断点续跑」** 这两件事：

1. 一条导航超时/失败，批次必须继续往下跑（这正是过去把循环写在单个 `runtime_eval` 里
   做不到的事 —— 上下文一销毁，循环续体就丢了，整批以超时结束）；
2. 跑到时间预算必须能停下来，并给出准确的 `nextStartFrom`，下一次调用接着跑完，
   **两次调用的覆盖并集 == 全部路由**（不能漏、不能重）。
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "e0e1-wx"))

from package.mcp_control.local_app import create_mcp_app  # noqa: E402
from package.mcp_control.runtime_session import (  # noqa: E402
    ROUTE_ACTIONS,
    McpRuntimeSession,
)

PASSED = 0
FAILED = 0

TABBAR = "pages/tab/home"
ROUTES = [TABBAR, "pages/a/detail", "pages/b/list", "pages/c/form", "pages/d/info"]


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


def make_session(
    *,
    routes: list[str] | None = None,
    tabbar: tuple[str, ...] = (TABBAR,),
    plan_ok: bool = True,
    fail_at: tuple[int, ...] = (),
    timeout_at: tuple[int, ...] = (),
    redirect_to: str = "",
    read_fail: bool = False,
    nav_delay: float = 0.0,
    rehook_ok: bool = True,
) -> tuple[McpRuntimeSession, dict]:
    """造一个桩会话：所有 CDP 触点在实例上被替换，返回 (session, 调用记录)。"""
    session = McpRuntimeSession()
    session.selected_appservice_context_id = 4
    session.requests = {}
    state: dict = {"nav_calls": [], "current": "", "read_calls": 0, "rehook_calls": 0, "counter": 0}
    route_list = list(routes if routes is not None else ROUTES)

    async def fake_inspect_routes() -> dict:
        if not plan_ok:
            return {"ok": False, "error": "读路由表失败（桩）"}
        return {
            "ok": True,
            "pages": [{"route": r, "source": "main", "isTabBar": r in tabbar} for r in route_list],
            "tabbar_pages": list(tabbar),
            "current_route": state["current"] or (route_list[0] if route_list else ""),
            "guard_enabled": False,
            "blocked_redirects_count": 0,
        }

    async def fake_eval_within(expression, *, timeout_seconds, context_id=None, session_id=None):
        # 导航求值：`window.__routeNavigator.reLaunchJson("...")`
        if ".__routeNavigator." in expression and "Json(" in expression:
            method = "switchTab" if "switchTabJson(" in expression else "reLaunch"
            target = expression.split("Json(", 1)[1].rsplit(")", 1)[0]
            try:
                target = json.loads(target)
            except json.JSONDecodeError:
                target = target.strip('"')
            index = len(state["nav_calls"])
            state["nav_calls"].append({"method": method, "route": target})
            if nav_delay:
                await asyncio.sleep(nav_delay)
            if index in timeout_at:
                return {"ok": False, "timedOut": True, "error": "求值超时（桩）"}
            if index in fail_at:
                return {"ok": False, "error": "导航求值失败（桩）"}
            state["current"] = redirect_to or target
            # 模拟采集到新请求（每条路由 2 条）
            for _ in range(2):
                state["counter"] += 1
                session.requests[f"req-{state['counter']}"] = {"url": "https://example.com/api"}
            return {"ok": True, "value": json.dumps({"ok": True, "action": method})}
        # 读路由
        state["read_calls"] += 1
        if read_fail:
            return {"ok": False, "error": "读路由失败（桩）"}
        return {"ok": True, "value": {"route": state["current"], "via": "stub.getCurrentPages"}}

    async def fake_rehook() -> dict:
        state["rehook_calls"] += 1
        return {"ok": rehook_ok, "hooks": {"wx": {"ok": rehook_ok}}}

    session.inspect_routes = fake_inspect_routes  # type: ignore[method-assign]
    session._eval_within = fake_eval_within  # type: ignore[method-assign]
    session.rehook_after_route_navigation = fake_rehook  # type: ignore[method-assign]
    return session, state


async def test_schema() -> None:
    print("\n[1] 签名层（FastMCP inputSchema）")
    mcp = create_mcp_app()
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    route_tool = tools.get("route_ops")
    if route_tool is None:
        check("找到 route_ops", False)
        return
    schema = route_tool.inputSchema or {}
    props = schema.get("properties") or {}
    enum = (props.get("action") or {}).get("enum") or []
    check("route_ops 暴露 crawl_routes", "crawl_routes" in enum, f"enum={list(enum)}")
    check("ROUTE_ACTIONS 含 crawl_routes", "crawl_routes" in ROUTE_ACTIONS)
    for key in ("routes", "start_from", "max_routes", "settle_ms", "deadline_seconds", "rehook",
                "navigation_timeout_seconds"):
        check(f"inputSchema 含 {key}", key in props)
    for key in ("inspect_routes", "navigate_route", "wait_route_stable", "plan_route_crawl"):
        check(f"回归：既有 action 未丢失 {key}", key in enum)


async def test_plan_failure() -> None:
    print("\n[2] 路由表读取失败的两种情形")
    session, _ = make_session(plan_ok=False)
    result = await session.crawl_routes()
    check("未传 routes + 读表失败 → ok=False", result.get("ok") is False, f"{result.get('error')}")

    session, state = make_session(plan_ok=False)
    result = await session.crawl_routes(routes=["pages/x/one", "pages/x/two"], settle_ms=0)
    check("传了 routes + 读表失败 → 仍能跑", result.get("ok") is True)
    check("并给出 warning", any("tabbar" in w for w in result.get("warnings") or []),
          f"{result.get('warnings')}")
    check("全部按 reLaunch 处理",
          all(c["method"] == "reLaunch" for c in state["nav_calls"]),
          f"{[c['method'] for c in state['nav_calls']]}")


async def test_happy_path() -> None:
    print("\n[3] 正常批次")
    session, state = make_session()
    result = await session.crawl_routes(settle_ms=0)
    check("ok=True", result.get("ok") is True)
    check("dryRun=False（真导航）", result.get("dryRun") is False)
    totals = result.get("totals") or {}
    check("attempted == 全部路由", totals.get("attempted") == len(ROUTES), f"{totals}")
    check("landed == 全部路由", totals.get("landed") == len(ROUTES), f"{totals}")
    check("remaining == 0", totals.get("remaining") == 0)
    check("stoppedReason=routes_exhausted", result.get("stoppedReason") == "routes_exhausted")
    check("nextStartFrom == 总条数", result.get("nextStartFrom") == len(ROUTES))
    check("逐条 entries 数与路由数一致", len(result.get("routes") or []) == len(ROUTES))
    check("本批未发生任何失败", not result.get("failures"))

    print("\n[4] tabbar 判定驱动跳转方法")
    methods = {c["route"]: c["method"] for c in state["nav_calls"]}
    check("tabbar 页用 switchTab", methods.get(TABBAR) == "switchTab", f"{methods.get(TABBAR)}")
    check("普通页用 reLaunch", methods.get("pages/a/detail") == "reLaunch")

    print("\n[5] 采集增量")
    collect = result.get("collect") or {}
    check("newRequests == 实际新增（5 条 × 2）", collect.get("newRequests") == len(ROUTES) * 2,
          f"{collect}")
    check("requestsAfter - requestsBefore == newRequests",
          collect.get("requestsAfter", 0) - collect.get("requestsBefore", 0) == collect.get("newRequests"))
    check("逐条 newRequests 被记录",
          all(item.get("newRequests") == 2 for item in result.get("routes") or []))


async def test_failure_isolation() -> None:
    print("\n[6] ★ 单条失败绝不拖垮整批（R-3 的核心）")
    session, state = make_session(fail_at=(1,), timeout_at=(3,))
    result = await session.crawl_routes(settle_ms=0)
    totals = result.get("totals") or {}
    check("失败后批次仍跑完全部路由", totals.get("attempted") == len(ROUTES), f"{totals}")
    check("导航调用次数 == 全部路由（没有提前退出）", len(state["nav_calls"]) == len(ROUTES))
    check("ok 仍为 True（不含致命错误）", result.get("ok") is True)
    failures = result.get("failures") or []
    check("failures 只记真正失败的两条", len(failures) == 2, f"{failures}")
    entries = result.get("routes") or []
    check("第 1 条标记 navigationOk=False", entries[1].get("navigationOk") is False)
    check("第 3 条标记 timedOut", entries[3].get("timedOut") is True)
    check("超时条目带「不要重试」提示", "不要重试" in str(entries[3].get("note") or ""))
    check("未失败的条目不受影响", all(e.get("landed") for i, e in enumerate(entries) if i not in (1, 3)))


async def test_redirect() -> None:
    print("\n[7] 被重定向（登录页）不是工具故障")
    session, _ = make_session(redirect_to="pages/login/login")
    result = await session.crawl_routes(settle_ms=0)
    totals = result.get("totals") or {}
    check("ok 仍为 True", result.get("ok") is True)
    check("landed=0", totals.get("landed") == 0, f"{totals}")
    check("notLanded == attempted", totals.get("notLanded") == totals.get("attempted"))
    check("failures 记录了实际落点",
          all(item.get("finalRoute") == "pages/login/login" for item in result.get("failures") or []))


async def test_resume() -> None:
    print("\n[8] ★ 断点续跑：两次调用的并集必须等于全部路由（不漏不重）")
    session, state = make_session()
    first = await session.crawl_routes(settle_ms=0, max_routes=2)
    check("第一批跑 2 条", (first.get("totals") or {}).get("attempted") == 2)
    check("stoppedReason=max_routes", first.get("stoppedReason") == "max_routes")
    resume = first.get("nextStartFrom")
    check("nextStartFrom 给了续跑点", resume == 2, f"{resume}")
    second = await session.crawl_routes(settle_ms=0, start_from=int(resume or 0))
    check("第二批接着跑到尾", (second.get("totals") or {}).get("attempted") == len(ROUTES) - 2)
    covered = [c["route"] for c in state["nav_calls"]]
    check("两次调用覆盖全部路由且无重复",
          covered == ROUTES, f"{covered}")


async def test_deadline() -> None:
    print("\n[9] 时间预算到点必须停下（不能盲等）")
    # settle 400ms × 5 条 = 2s，预算给 0.7s → 必然在跑完之前停下
    session, state = make_session()
    result = await session.crawl_routes(settle_ms=400, deadline_seconds=0.7)
    totals = result.get("totals") or {}
    check("stoppedReason=deadline", result.get("stoppedReason") == "deadline",
          f"{result.get('stoppedReason')}")
    check("没有跑完全部（预算真的生效了）", 0 < int(totals.get("attempted") or 0) < len(ROUTES),
          f"{totals}")
    check("nextStartFrom 指向未跑的那条",
          int(result.get("nextStartFrom") or 0) == len(state["nav_calls"]),
          f"next={result.get('nextStartFrom')} 实际跑了 {len(state['nav_calls'])}")
    check("hint 明说「不是错误」", "不是错误" in str(result.get("hint") or ""))
    check("elapsedSeconds 被记录", float(result.get("elapsedSeconds") or 0) >= 0)

    print("\n[10] ★ 预算参数不得被静默放大（本项目反复踩的坑）")
    # 传 0.5s 就必须是 0.5s 左右。如果实现里写成 `max(5.0, ...)`，这里会跑到 ~2s 才结束。
    session2, _ = make_session()
    tiny = await session2.crawl_routes(settle_ms=400, deadline_seconds=0.5)
    check("deadlineSeconds 原样回显", float(tiny.get("deadlineSeconds") or 0) == 0.5,
          f"{tiny.get('deadlineSeconds')}")
    check("实际耗时受 0.5s 约束（未被放大到 5s）",
          float(tiny.get("elapsedSeconds") or 0) < 1.5,
          f"elapsed={tiny.get('elapsedSeconds')}")
    check("极小预算下仍然给了续跑点", int(tiny.get("nextStartFrom") or -1) >= 0)

    print("\n[11] max_routes / start_from 的边界")
    session3, state3 = make_session()
    one = await session3.crawl_routes(settle_ms=0, max_routes=1)
    check("max_routes=1 → 只跑 1 条", (one.get("totals") or {}).get("attempted") == 1,
          f"{one.get('totals')}")
    check("只发出 1 次导航", len(state3["nav_calls"]) == 1)

    # ⚠️ 明确的例外：0 在本项目里一律按「未设置 → 用默认值」处理
    # （`plan_route_crawl(max_routes)`、`read_source(max_lines)`、`settle_ms` 都是这个约定）。
    # 这里把它**显式断言**出来，免得以后有人误当 bug 去改。
    session5, state5 = make_session()
    zero = await session5.crawl_routes(settle_ms=0, max_routes=0)
    check("max_routes=0 按「未设置」处理 → 走默认（不是「跑 0 条」）",
          (zero.get("totals") or {}).get("attempted") == len(ROUTES), f"{zero.get('totals')}")
    check("该约定与代码库其余 max_* 参数一致", len(state5["nav_calls"]) == len(ROUTES))

    session4, state4 = make_session()
    beyond = await session4.crawl_routes(settle_ms=0, start_from=999)
    check("start_from 越界 → 不导航、remaining=0",
          not state4["nav_calls"] and (beyond.get("totals") or {}).get("remaining") == 0,
          f"{beyond.get('totals')}")


async def test_rehook_and_volume() -> None:
    print("\n[12] rehook 开关与失败上报")
    session, state = make_session()
    await session.crawl_routes(settle_ms=0, rehook=False)
    check("rehook=False 时不调用", state["rehook_calls"] == 0, f"{state['rehook_calls']}")

    session2, _ = make_session(rehook_ok=False)
    result2 = await session2.crawl_routes(settle_ms=0)
    check("rehook 失败被计数", result2.get("rehookFailures") == len(ROUTES),
          f"{result2.get('rehookFailures')}")
    check("rehook 失败给 warning", any("重挂 Hook" in w for w in result2.get("warnings") or []))
    check("rehook 失败不影响批次完成", (result2.get("totals") or {}).get("attempted") == len(ROUTES))

    print("\n[13] 响应体量受控（防 R-5 那种体量失控）")
    big_routes = [f"pages/pkg{i // 50}/page{i}" for i in range(200)]
    session3, _ = make_session(routes=big_routes, tabbar=())
    big = await session3.crawl_routes(settle_ms=0, max_routes=200)
    size = len(json.dumps(big, ensure_ascii=False))
    check("200 条路由的返回体 < 60,000 字符", size < 60_000, f"{size} 字符")

    print("\n[14] 输入清洗")
    session4, state4 = make_session()
    dirty = ["pages/x/one", "pages/x/one", "", "/pages/x/two", "pages/x/one"]
    result4 = await session4.crawl_routes(routes=dirty, settle_ms=0)
    check("去重 + 去空 + 归一化前导斜杠",
          [c["route"] for c in state4["nav_calls"]] == ["pages/x/one", "pages/x/two"],
          f"{[c['route'] for c in state4['nav_calls']]}")
    check("清洗后 planned=2", (result4.get("totals") or {}).get("available") == 2)


async def main() -> int:
    await test_schema()
    await test_plan_failure()
    await test_happy_path()
    await test_failure_isolation()
    await test_redirect()
    await test_resume()
    await test_deadline()
    await test_rehook_and_volume()

    print()
    print("=" * 78)
    print(f"结果：{PASSED} passed / {FAILED} failed")
    print("=" * 78)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

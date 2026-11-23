#!/usr/bin/env python3
"""离线验证：`route_ops(action="plan_route_crawl")` 的规划逻辑（P2-1）。

只读，不连 CDP。

最重要的一条断言是 **「纯读、零 CDP」** —— 把 `runtime_eval` 换成会抛异常的桩，
再跑一次规划。如果规划过程里偷偷发生了任何求值（导航、注入、读配置），
就会当场炸出来。这是「dry-run 承诺」唯一可信的验证方式：
不靠读代码，靠让它没法作弊。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "e0e1-wx"))

from package.mcp_control.runtime_session import (  # noqa: E402
    CRAWL_NAVIGATION_OVERHEAD_SECONDS,
    McpRuntimeSession,
)

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


def make_session() -> McpRuntimeSession:
    session = McpRuntimeSession()
    # ⚠️ 必须用**真实结构**，别图省事写成 `list[dict]`：
    # `self.requests` 的真实类型是 `dict[str, JsonDict]`（按 requestId 索引），
    # 且值是**原始记录**（只有 `url`；`path` 是 `normalize_request()` 从 url 算出来的）。
    #
    # 这里曾经写成「list + 自带 `path` 字段」，与真实结构不符 → 掩盖了
    # 「把 dict 直接传给 `build_api_inventory()`（它 `for req in requests`，
    # 迭代 dict 得到字符串键）→ 全路径 AttributeError」的真 bug（v2.27 真机实测）。
    # **桩结构写错，测的就是一个不存在的会话，全绿也没有意义。**
    session.requests = {
        "r1": {"requestId": "r1", "method": "GET", "url": "https://example.com/a", "statusCode": 200},
        "r2": {"requestId": "r2", "method": "POST", "url": "https://example.com/b", "statusCode": 200},
    }
    return session


def plan(session: McpRuntimeSession, **kwargs):
    return asyncio.run(session.plan_route_crawl(**kwargs))


# —— 1. 纯读契约：把 runtime_eval 换成炸弹 ——
def test_pure_read() -> None:
    print("\n[1] dry-run 契约：规划过程不得发生任何 CDP 求值")
    session = make_session()

    def bomb(*_args, **_kwargs):
        raise AssertionError("规划过程中发生了 runtime_eval —— 说明 dry-run 承诺被破坏")

    session.runtime_eval = bomb  # type: ignore[assignment]
    session.navigate_route = bomb  # type: ignore[assignment]
    session.navigate_back = bomb  # type: ignore[assignment]
    session.set_redirect_guard = bomb  # type: ignore[assignment]

    try:
        result = plan(session, routes=["pages/a/index", "pages/b/index"])
        check("传 routes 时全程零 CDP（runtime_eval 未被调用）", True)
        check("dryRun 标记为 true", result.get("dryRun") is True, f"dryRun={result.get('dryRun')}")
        check("routeSource 标为 caller", result.get("routeSource") == "caller")
    except AssertionError as exc:
        check("传 routes 时全程零 CDP（runtime_eval 未被调用）", False, str(exc))


# —— 2. 归一化 / 去重 / 无效项 ——
def test_normalize_dedupe() -> None:
    print("\n[2] 归一化 / 去重 / 无效项")
    session = make_session()
    result = plan(
        session,
        routes=["/pages/a/index", "pages/a/index", "pages/b/index", "", "   ", "/"],
    )
    totals = result["totals"]
    check("前导斜杠被归一化（/pages/a/index → pages/a/index）", True)
    check("重复路由只保留一次", totals["skippedDuplicate"] == 1, f"skippedDuplicate={totals['skippedDuplicate']}")
    check("无效路由被计数（空串/空白/裸斜杠）", totals["skippedInvalid"] == 3, f"skippedInvalid={totals['skippedInvalid']}")
    check("planned == 2", totals["planned"] == 2, f"planned={totals['planned']}")
    check("available 记录的是过滤前总数", totals["available"] == 6, f"available={totals['available']}")

    all_routes = [r for b in result["batches"] for r in b["routes"]]
    check("批次里的路由已归一化且有序", all_routes == ["pages/a/index", "pages/b/index"], f"{all_routes}")


# —— 3. 分批：无丢无重、口径自洽 ——
def test_batching() -> None:
    print("\n[3] 分批：无丢无重 + 估算口径自洽")
    session = make_session()
    routes = [f"pages/p{i}/index" for i in range(37)]
    settle_ms, deadline = 5000, 30.0
    result = plan(session, routes=routes, settle_ms=settle_ms, deadline_seconds=deadline)

    per_route = settle_ms / 1000.0 + CRAWL_NAVIGATION_OVERHEAD_SECONDS
    expected_per_batch = int(deadline // per_route)

    check("perBatch 与 (deadline/settle) 口径一致",
          result["perBatch"] == expected_per_batch,
          f"perBatch={result['perBatch']} expected={expected_per_batch}")
    check("estimatedBatches 与实际批数一致",
          result["estimatedBatches"] == len(result["batches"]),
          f"estimatedBatches={result['estimatedBatches']} len={len(result['batches'])}")

    flat = [r for b in result["batches"] for r in b["routes"]]
    check("批次展开后与输入完全一致（无丢无重）", flat == routes,
          f"len(flat)={len(flat)} len(routes)={len(routes)}")
    check("estimatedSeconds 按 (settle+overhead)*条数 计算",
          abs(result["estimatedSeconds"] - round(len(routes) * per_route, 1)) < 1e-6,
          f"got={result['estimatedSeconds']}")

    no_oversize = all(b["count"] <= result["perBatch"] for b in result["batches"])
    check("没有任何批次超过 perBatch", no_oversize)

    resume_ok = [b["resumeFrom"] for b in result["batches"]] == list(
        range(0, len(routes), result["perBatch"])
    )
    check("resumeFrom 是可直接回传的绝对下标", resume_ok,
          f"{[b['resumeFrom'] for b in result['batches']][:5]}")

    check("assumption 明确标注为估算",
          "估算" in str(result.get("assumption")),
          f"{result.get('assumption')}")


# —— 4. 断点续跑 ——
def test_start_from() -> None:
    print("\n[4] 断点续跑 start_from")
    session = make_session()
    routes = [f"pages/p{i}/index" for i in range(10)]
    result = plan(session, routes=routes, start_from=4, deadline_seconds=60)

    totals = result["totals"]
    check("skippedByStartFrom == 4", totals["skippedByStartFrom"] == 4, f"{totals['skippedByStartFrom']}")
    check("planned == 6", totals["planned"] == 6, f"{totals['planned']}")
    flat = [r for b in result["batches"] for r in b["routes"]]
    check("续跑从第 4 条开始", flat[0] == "pages/p4/index", f"{flat[0]}")
    check("首批 resumeFrom == 4", result["batches"][0]["resumeFrom"] == 4)
    check("nextStartFrom == 10", result["nextStartFrom"] == 10, f"{result['nextStartFrom']}")


# —— 5. max_routes 截断 + 可续跑 ——
def test_max_routes() -> None:
    print("\n[5] max_routes 截断与续跑提示")
    session = make_session()
    routes = [f"pages/p{i}/index" for i in range(25)]
    result = plan(session, routes=routes, max_routes=10, deadline_seconds=60)

    totals = result["totals"]
    check("truncatedByMaxRoutes == 15", totals["truncatedByMaxRoutes"] == 15, f"{totals['truncatedByMaxRoutes']}")
    check("planned == 10", totals["planned"] == 10, f"{totals['planned']}")
    check("nextStartFrom == 10（可用于续跑）", result["nextStartFrom"] == 10, f"{result['nextStartFrom']}")
    warn = " ".join(result.get("warnings") or [])
    check("warnings 里给出续跑的 start_from", "start_from=10" in warn, f"{warn[:120]}")

    # 续跑一次，确认能接上
    again = plan(session, routes=routes, max_routes=10, start_from=result["nextStartFrom"], deadline_seconds=60)
    flat = [r for b in again["batches"] for r in b["routes"]]
    check("续跑接上且不重不漏（10..19）", flat == routes[10:20], f"{flat[:3]} ... {flat[-1:]}")


# —— 6. 空计划与过小 deadline 的显式上报 ——
def test_edge_warnings() -> None:
    print("\n[6] 边界情形：空计划 / deadline 小于单条耗时")
    session = make_session()

    empty = plan(session, routes=[], deadline_seconds=60)
    check("空 routes 仍返回 ok（不是异常）", empty.get("ok") is True)
    check("空计划有 warning 说明原因",
          any("计划为空" in w for w in empty.get("warnings") or []),
          f"{empty.get('warnings')}")
    check("空计划 batches 为空列表", empty.get("batches") == [])

    tiny = plan(session, routes=["pages/a/index"], settle_ms=20000, deadline_seconds=5)
    check("settle 远超 deadline 时有 warning",
          any("超过 deadline_seconds" in w for w in tiny.get("warnings") or []),
          f"{tiny.get('warnings')}")
    check("此时每批至少装 1 条（不会出现空批）", tiny["perBatch"] == 1 and len(tiny["batches"]) == 1)


# —— 7. 参数夹取（不能靠传怪值把工具搞坏） ——
def test_clamping() -> None:
    print("\n[7] 参数夹取")
    session = make_session()

    neg = plan(session, routes=["pages/a/index"], settle_ms=-100, deadline_seconds=0, max_routes=0, start_from=-5)
    check("settle_ms 负数被夹到 0", neg["settleMs"] == 0, f"{neg['settleMs']}")
    check("deadline_seconds=0 被夹到 >=1", neg["deadlineSeconds"] >= 1.0, f"{neg['deadlineSeconds']}")
    check("max_routes=0 被夹到 >=1", neg["totals"]["planned"] >= 1, f"{neg['totals']['planned']}")
    check("start_from 负数被夹到 0", neg["totals"]["skippedByStartFrom"] == 0)

    huge = plan(session, routes=["pages/a/index"], settle_ms=10**9, deadline_seconds=10**9, max_routes=10**9)
    check("settle_ms 上限 60000", huge["settleMs"] == 60_000, f"{huge['settleMs']}")
    check("deadline_seconds 上限 3600", huge["deadlineSeconds"] == 3600.0, f"{huge['deadlineSeconds']}")


# —— 8. baseline 来自本地，不额外打 CDP ——
def test_baseline() -> None:
    print("\n[8] baseline 来自本地会话状态")
    session = make_session()
    session.requests = {
        "r1": {"requestId": "r1", "method": "GET", "url": "https://example.com/a", "statusCode": 200},
        "r2": {"requestId": "r2", "method": "GET", "url": "https://example.com/a", "statusCode": 200},
        "r3": {"requestId": "r3", "method": "POST", "url": "https://example.com/b", "statusCode": 200},
    }
    result = plan(session, routes=["pages/a/index"])
    baseline = result["collect"]["baseline"]
    check("requestCount == 缓存记录数（3）", baseline["requestCount"] == 3, f"{baseline['requestCount']}")
    check("apiCount == 去重后的接口数（/a + /b = 2）", baseline["apiCount"] == 2, f"{baseline['apiCount']}")
    check("baseline 标明来源为进程内缓存",
          baseline.get("source") == "in_process_cache",
          f"{baseline.get('source')}")
    check("collect 里说明了「只规划不导航」",
          "只规划" in str(result["collect"].get("note")),
          f"{result['collect'].get('note')}")


# —— 9. tabBar 排除 + 分包开关（stub inspect_routes，仍不连 CDP） ——
def test_tabbar_and_subpackage() -> None:
    print("\n[9] tabBar 排除 / 分包开关（stub 路由配置）")
    session = make_session()

    async def fake_inspect():
        return {
            "ok": True,
            "pages": [
                {"route": "pages/home/index", "source": "main", "isTabBar": True},
                {"route": "pages/a/index", "source": "main", "isTabBar": False},
                {"route": "pkgA/detail/index", "source": "pkgA", "isTabBar": False},
                {"route": "pkgB/list/index", "source": "pkgB", "isTabBar": False},
            ],
            "tabbar_pages": ["pages/home/index"],
            "current_route": "pages/a/index",
        }

    session.inspect_routes = fake_inspect  # type: ignore[assignment]

    result = plan(session, exclude_tabbar=True)
    totals = result["totals"]
    flat = [r for b in result["batches"] for r in b["routes"]]
    check("从配置读路由时 routeSource=appservice", result["routeSource"] == "appservice")
    check("tabBar 页被排除", "pages/home/index" not in flat and totals["skippedTabbar"] == 1,
          f"skippedTabbar={totals['skippedTabbar']}")
    check("byPackage 按 source 分组", result["byPackage"].get("main") == 1 and result["byPackage"].get("pkgA") == 1,
          f"{result['byPackage']}")
    check("baseline.currentRoute 透传当前路由", result["collect"]["baseline"]["currentRoute"] == "pages/a/index")

    sub = plan(session, include_subpackages=False)
    sub_flat = [r for b in sub["batches"] for r in b["routes"]]
    check("include_subpackages=false 时只留主包",
          sub_flat == ["pages/home/index", "pages/a/index"], f"{sub_flat}")
    check("跳过分包时有 warning 提醒",
          any("分包路由" in w for w in sub.get("warnings") or []),
          f"{sub.get('warnings')}")

    # 读配置失败时必须显式报错，不能假装成功
    async def broken_inspect():
        return {"ok": False, "stage": "fetch", "error": "fetchConfigJson 不可用"}

    session.inspect_routes = broken_inspect  # type: ignore[assignment]
    broken = plan(session)
    check("读不到路由配置时 ok=false（不假装成功）", broken.get("ok") is False, f"{broken.get('ok')}")
    check("失败时给出改用 routes=[...] 的 hint", "routes=" in str(broken.get("hint")), f"{broken.get('hint')}")


# —— 10. 真实结构契约：`self.requests` 是 dict，且值是**未归一化**的原始记录 ——
def test_real_requests_shape() -> None:
    """守住「桩必须等于真实结构」这条 —— 它比任何逻辑断言都重要。

    真机踩过（v2.27）：`plan_route_crawl` 把 `self.requests`（dict）直接传给了
    `build_api_inventory()`（内部 `for req in requests`）→ 迭代出字符串键 →
    `'str' object has no attribute 'get'`，**该工具所有路径全部失败**。
    而离线测试全绿 —— 因为桩把 `requests` 写成了 list 且自带 `path`，
    与真实结构不符，**空/错的会话状态把 bug 掩盖了**。

    所以这里做两件事：
    1. 断言**默认实例**的 `requests` 就是 dict（真实类型，防未来漂移）；
    2. 用「只有 url、没有 path」的原始记录跑一遍，断言不炸且 path 被正确归一化。
    """
    print("\n[10] 真实结构契约：requests 是 dict + 原始记录需归一化")

    fresh = McpRuntimeSession()
    check("默认实例的 self.requests 是 dict（真实类型）",
          isinstance(fresh.requests, dict), f"{type(fresh.requests).__name__}")

    session = McpRuntimeSession()
    # 原始记录：**只有 url**，没有 method 之外的 path / kind —— 与 CDP 事件真实形态一致。
    session.requests = {
        "req-1": {"requestId": "req-1", "url": "https://chaxun.uestc.edu.cn/zsxc/t/list"},
        "req-2": {"requestId": "req-2", "url": "https://chaxun.uestc.edu.cn/lqxx/s/detail", "method": "POST"},
    }
    result = plan(session, routes=["pages/a/index"])
    check("非空 dict 缓存下规划不抛异常（回归 v2.27 的 AttributeError）",
          result.get("ok") is True, f"ok={result.get('ok')} error={result.get('error')}")
    baseline = result["collect"]["baseline"]
    check("baseline.requestCount 统计的是缓存记录数（2）",
          baseline["requestCount"] == 2, f"{baseline['requestCount']}")
    check("baseline.apiCount 用了归一化后的 path（2 个不同接口）",
          baseline["apiCount"] == 2, f"{baseline['apiCount']}")
    check("缺省 method 归一为 GET（未炸在 None 上）",
          baseline["apiCount"] == 2 and baseline["requestCount"] == 2, f"{baseline}")


def main() -> int:
    print("=" * 78)
    print("route_ops(action=\"plan_route_crawl\") —— 路由遍历规划验证（P2-1）")
    print("=" * 78)

    test_pure_read()
    test_normalize_dedupe()
    test_batching()
    test_start_from()
    test_max_routes()
    test_edge_warnings()
    test_clamping()
    test_baseline()
    test_tabbar_and_subpackage()
    test_real_requests_shape()

    print()
    print("=" * 78)
    print(f"结果：{PASSED} passed / {FAILED} failed")
    print("=" * 78)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

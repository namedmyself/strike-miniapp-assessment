#!/usr/bin/env python3
"""离线验证：体量与假阳性护栏（2026-09-23 一轮实测报出的 A-1 / A-2 / B-2 / B-3）。

只读、不连 CDP。全部用桩与合成数据。

四条对应关系：
  * **B-3** CJK 守卫 —— 中文业务文案不再被判成 `possible_hardcoded_secret`
  * **A-1** `get_recent_console` 的 `maxBytes` / `maxTextLength` 硬护栏
  * **A-2** `navigate_route` 返回体不再内联两张完整路由表（`verbose=true` 才给）
  * **B-2** JSON payload 键名不再无过滤塞进 `idFields`

每条都同时断言「**新行为成立**」与「**老锚点没被改坏**」——只验前者容易把已有能力改坏。
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "e0e1-wx"))

from package.mcp_control import runtime_session as rs  # noqa: E402
from package.mcp_control.local_app import create_mcp_app  # noqa: E402
from package.mcp_control.runtime_session import McpRuntimeSession  # noqa: E402

PASSED = 0
FAILED = 0

CN_COPY = (
    "您本次提交的业务办理申请已受理，当前状态为待审核，审核通过后系统将以短信方式通知您，"
    "请注意查收并保持手机畅通；如需撤销请在工作时间内前往服务大厅办理，谢谢配合。"
)


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


def test_b3_cjk() -> None:
    print("\n[1] B-3 CJK 守卫（中文文案不再误报，真密钥不受影响）")
    check(f"中文业务文案（{len(CN_COPY)} 字）不判为疑似密钥",
          rs.looks_like_hardcoded_secret(CN_COPY) is False,
          f"CJK 数={rs.cjk_char_count(CN_COPY)}  熵={rs.shannon_entropy(CN_COPY):.2f}")
    check("中文 + 数字混排（实测误报样本形态）不判为疑似密钥",
          rs.looks_like_hardcoded_secret(CN_COPY + "20230923 办理编号 A001") is False)
    # 老锚点：改完不能把真密钥放过去
    for value, why in (
        ("Adf123098SSddfdg", "实测真密钥 jjmData"),
        ("omEG45HbNADHJY5j0NTwTfSb5cek", "openId 形态（由 PII 路径另行抑制）"),
    ):
        check(f"老锚点仍命中：{value[:18]}…（{why}）",
              rs.looks_like_hardcoded_secret(value) is True)
    for value, why in (
        ("wxfile://store/1a0c8ee50cd_1c2.png", "路径形态"),
        ("1ebb927375304fd1bb67163d5eaa356e", "32 位纯 hex"),
        ("1790077453712602847", "纯数字"),
        ("search_show_type", "snake_case 标识符"),
        ("2023-01-09 00:00:00", "时间格式，熵低于阈值"),
    ):
        check(f"老锚点仍不命中：{value[:26]}（{why}）",
              rs.looks_like_hardcoded_secret(value) is False)
    check("cjk_char_count 对中文标点也计数（全角区）", rs.cjk_char_count("，。（）：") == 5)


async def test_a1_console() -> None:
    print("\n[2] A-1 get_recent_console 体量护栏")
    session = McpRuntimeSession()

    # 造一条巨长事件 + 若干小事件（复现「单条巨长异常撑爆返回体」）
    session.console_events = [{"method": "Log.entryAdded", "params": {"text": f"small-{i}"}} for i in range(20)]
    session.console_events.append(
        {"method": "Runtime.exceptionThrown", "params": {"text": "E" * 20_000, "stack": ["S" * 5_000] * 50}}
    )

    result = await session.get_recent_console(limit=50)
    size = len(json.dumps(result, ensure_ascii=False))
    check("返回 ok", bool(result.get("ok")))
    check("返回体被压到上限附近（< 40KB）", size < 40_000, f"实际 {size} 字符")
    check("至少返回 1 条（不会全被丢掉）", int(result.get("returned") or 0) >= 1,
          f"returned={result.get('returned')}")
    check("截断处数被如实上报", int(result.get("truncatedFields") or 0) >= 1,
          f"truncatedFields={result.get('truncatedFields')}")
    check("上限被回显（便于核对参数真的传进去了）",
          int(result.get("maxBytes") or 0) == 24_000, f"{result.get('maxBytes')}")
    check("把更早的事件记为 droppedByBytes（而不是静默吞掉）",
          int(result.get("droppedByBytes") or 0) >= 1, f"droppedByBytes={result.get('droppedByBytes')}")
    check("available 反映 limit 内的条数", int(result.get("available") or 0) == 21,
          f"available={result.get('available')}")

    # limit 仍然控制条数
    few = await session.get_recent_console(limit=3, max_bytes=400_000, max_text_length=200_000)
    check("limit 仍控制条数（limit=3 → available=3）", int(few.get("available") or 0) == 3,
          f"available={few.get('available')}")
    small = await session.get_recent_console(limit=20, max_bytes=1_500, max_text_length=64)
    check("显式小 maxBytes 生效（返回体更小）",
          len(json.dumps(small, ensure_ascii=False)) < len(json.dumps(result, ensure_ascii=False)))
    check("参数回显与实际一致（小 maxBytes）", int(small.get("maxBytes") or 0) == 1_500,
          f"{small.get('maxBytes')}")


def test_a2_slim() -> None:
    print("\n[3] A-2 navigate_route 返回摘要")
    full = {
        "ok": True,
        "pages": [{"route": f"pages/p{i}/index", "source": "main", "isTabBar": False} for i in range(27)],
        "tabbar_pages": ["pages/tab/home"],
        "current_route": "pages/p9/index",
        "guard_enabled": True,
        "blocked_redirects_count": 3,
    }
    slim = rs._slim_route_table(full)
    full_size = len(json.dumps(full, ensure_ascii=False))
    slim_size = len(json.dumps(slim, ensure_ascii=False))
    check("摘要体积比完整路由表小一个数量级以上（<10%）", slim_size < full_size * 0.10,
          f"{full_size} → {slim_size} 字符（降幅 {100 - slim_size * 100 / full_size:.1f}%）")
    for key in ("ok", "currentRoute", "guardEnabled", "blockedRedirects"):
        check(f"摘要保留判断所需字段 {key}", key in slim)
    check("摘要给出 routeCount（替代 pages 明细）", slim.get("routeCount") == 27)
    check("摘要不再携带 pages 明细", "pages" not in slim)

    rehook_full = {
        "ok": True, "mode": "runtime_context",
        "previousContextId": 4, "selectedContextId": 5,
        "hooks": {"wx": {"ok": True, "count": 12, "raw": "x" * 5000},
                  "upload": {"ok": False, "error": "e"}, "fetch_xhr": {"ok": True}},
    }
    rehook_slim = rs._slim_rehook(rehook_full)
    check("rehook 摘要只留每个 hook 是否成功",
          rehook_slim.get("hooks") == {"wx": True, "upload": False, "fetch_xhr": True},
          f"{rehook_slim.get('hooks')}")
    check("rehook 摘要保留 context 变化信息",
          rehook_slim.get("previousContextId") == 4 and rehook_slim.get("selectedContextId") == 5)
    check("rehook 摘要体积远小于完整版",
          len(json.dumps(rehook_slim, ensure_ascii=False)) < len(json.dumps(rehook_full, ensure_ascii=False)) * 0.1)


def test_b2_idor_fields() -> None:
    print("\n[4] B-2 JSON payload 键名不再冒充 idFields")
    accept = ["id", "uid", "userId", "fileId", "bizId", "orderId", "user_id", "record_id", "USERID"]
    reject = ["isList", "page", "size", "type", "paid", "valid", "android", "name", "keyword"]
    for name in accept:
        check(f"JSON ID 正则接受 {name}", bool(rs.JSON_ID_FIELD_RE.search(name)))
    for name in reject:
        check(f"JSON ID 正则拒绝 {name}", not rs.JSON_ID_FIELD_RE.search(name))

    session = McpRuntimeSession()
    payload = json.dumps({"isList": False, "page": 1, "size": 20, "type": "a", "userId": 123})
    req = {
        "id": "r1", "method": "GET", "url": "https://x/api/list?params=" + payload,
        "path": "/api/list", "query": {"params": payload},
    }
    result = session.find_idor_candidates([req])
    cands = result.get("candidates") or []
    check("仍然产出候选（真 ID 没被漏掉）", len(cands) == 1, f"count={result.get('count')}")
    if cands:
        idf = cands[0].get("idFields") or []
        jpf = cands[0].get("jsonPayloadFields") or []
        check("idFields 只含真 ID（userId）", idf == ["userId"], f"{idf}")
        check("isList/page/size/type 不再进 idFields",
              not ({"isList", "page", "size", "type"} & set(idf)))
        check("完整键名仍保留在 jsonPayloadFields（不丢线索）",
              set(jpf) >= {"isList", "page", "size", "type", "userId"}, f"{jpf}")

    # 只有非 ID 信号时，不应再凭空造出候选
    only_noise = [{
        "id": "r2", "method": "GET", "url": "https://x/api/list?isList=false&page=1",
        "path": "/api/list", "query": {"isList": "false", "page": "1"},
    }]
    noise = session.find_idor_candidates(only_noise)
    check("只有 isList/page 信号的请求不再产生候选（噪声归零）",
          int(noise.get("count") or 0) == 0, f"count={noise.get('count')}")
    check("note 说明了 idFields 与 jsonPayloadFields 的区别",
          "jsonPayloadFields" in str(noise.get("note") or ""))


async def test_schema() -> None:
    print("\n[5] 签名层（FastMCP 签名即契约，实现层改了必须同步）")
    tools = {t.name: t for t in await create_mcp_app().list_tools()}
    props = (tools["get_recent_console"].inputSchema or {}).get("properties") or {}
    for key in ("limit", "maxBytes", "maxTextLength"):
        check(f"get_recent_console.inputSchema 含 {key}", key in props)
    rprops = (tools["route_ops"].inputSchema or {}).get("properties") or {}
    check("route_ops.inputSchema 含 verbose（A-2）", "verbose" in rprops)
    check("route_ops 仍含 crawl_routes（回归）",
          "crawl_routes" in ((rprops.get("action") or {}).get("enum") or []))


async def main() -> int:
    test_b3_cjk()
    await test_a1_console()
    test_a2_slim()
    test_b2_idor_fields()
    await test_schema()
    print()
    print("=" * 78)
    print(f"结果：{PASSED} passed / {FAILED} failed")
    print("=" * 78)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

#!/usr/bin/env python3
"""MCP 工具链自检：对着运行中的小程序跑一遍检查矩阵。

用途：改完工具后确认没有回归；接手环境时快速判断链路到底哪一层断了。

默认**只跑只读检查**。会改变小程序状态的检查（导航、点击、写 Vuex、下断点）
需要显式加 `--include-mutating`。

用法：
  python scripts\\mcp_smoke_test.py                 # 只读矩阵
  python scripts\\mcp_smoke_test.py --verbose       # 打印每项返回摘要
  python scripts\\mcp_smoke_test.py --only debugger_ops
  python scripts\\mcp_smoke_test.py --include-mutating
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wxmcp import McpHttpClient, extract_text, result_is_error  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

Validator = Callable[[Any], tuple[bool, str]]


def has_key(*keys: str) -> Validator:
    """校验返回里存在指定键（支持 a.b 形式的浅层路径）。"""

    def _check(payload: Any) -> tuple[bool, str]:
        if not isinstance(payload, dict):
            return False, f"返回不是对象：{type(payload).__name__}"
        for key in keys:
            cursor: Any = payload
            for part in key.split("."):
                if not isinstance(cursor, dict) or part not in cursor:
                    return False, f"缺少字段 {key}"
                cursor = cursor[part]
        return True, "ok"

    return _check


def ok_true() -> Validator:
    """校验 ok 字段为真。"""

    def _check(payload: Any) -> tuple[bool, str]:
        if not isinstance(payload, dict):
            return False, f"返回不是对象：{type(payload).__name__}"
        if payload.get("ok") is True:
            return True, "ok"
        return False, str(payload.get("error") or payload.get("stage") or "ok != true")[:160]

    return _check


def truthy(path: str, minimum: int = 1) -> Validator:
    """校验某个数值字段 >= minimum。"""

    def _check(payload: Any) -> tuple[bool, str]:
        cursor: Any = payload
        for part in path.split("."):
            if not isinstance(cursor, dict) or part not in cursor:
                return False, f"缺少字段 {path}"
            cursor = cursor[part]
        if isinstance(cursor, (int, float)) and cursor >= minimum:
            return True, f"{path}={cursor}"
        return False, f"{path}={cursor!r}，期望 >= {minimum}"

    return _check


def any_of(*validators: Validator) -> Validator:
    """任一校验通过即可。"""

    def _check(payload: Any) -> tuple[bool, str]:
        last = "无可用校验"
        for validator in validators:
            passed, detail = validator(payload)
            if passed:
                return True, detail
            last = detail
        return False, last

    return _check


# (分组, 工具名, 参数, 校验器, 是否只读)
CHECKS: list[tuple[str, str, dict, Validator, bool]] = [
    # —— 连接层 ——
    ("connection", "status", {}, has_key("cdp.connected"), True),
    ("connection", "list_targets", {}, truthy("count"), True),
    ("connection", "find_appservice", {}, any_of(ok_true(), has_key("mode")), True),
    ("connection", "select_appservice_context", {"force": False}, any_of(ok_true(), has_key("mode")), True),
    ("connection", "cdp_call", {"method": "Target.getTargets"}, any_of(ok_true(), has_key("result")), True),
    # —— 运行时 ——
    ("runtime", "runtime_eval", {"expression": "1+1"}, ok_true(), True),
    ("runtime", "runtime_eval_appservice", {"expression": "(typeof wx)+'|'+(typeof getCurrentPages)"}, ok_true(), True),
    ("runtime", "probe_bridge", {}, ok_true(), True),
    ("runtime", "wait_route_stable", {"timeout": 6, "settle": 1.5}, ok_true(), True),
    ("runtime", "dump_runtime_snapshot", {}, ok_true(), True),
    ("runtime", "get_basic_page_info", {}, any_of(ok_true(), has_key("snapshot")), True),
    ("runtime", "scan_sensitive_storage", {}, ok_true(), True),
    ("runtime", "inspect_upload_surface", {}, any_of(ok_true(), has_key("indicators")), True),
    ("runtime", "get_document_html", {}, any_of(ok_true(), has_key("html")), True),
    ("runtime", "inspect_window_keys", {"limit": 20}, any_of(ok_true(), has_key("keys")), True),
    ("runtime", "search_global_string", {"keyword": "wx"}, any_of(ok_true(), has_key("result")), True),
    ("runtime", "list_interactive_elements", {}, has_key("count"), True),
    ("runtime", "inspect_vuex_store", {}, any_of(ok_true(), has_key("store"), has_key("error")), True),
    # —— 网络 ——
    ("network", "network_enable", {}, ok_true(), True),
    ("network", "hook_wx_request", {}, any_of(ok_true(), has_key("value")), True),
    ("network", "hook_upload_apis", {}, any_of(ok_true(), has_key("value")), True),
    ("network", "hook_fetch_and_xhr", {}, any_of(ok_true(), has_key("value")), True),
    ("network", "get_all_requests", {"limit": 20}, any_of(ok_true(), has_key("requests")), True),
    ("network", "get_recent_requests", {"limit": 20}, any_of(ok_true(), has_key("requests")), True),
    ("network", "get_hooked_requests", {"limit": 20}, has_key("requests"), True),
    ("network", "get_recent_console", {"limit": 10}, any_of(ok_true(), has_key("events")), True),
    ("network", "inspect_wx_config", {}, any_of(ok_true(), has_key("value"), has_key("error")), True),
    ("network", "search_runtime_keywords", {"keywords": ["wx"]}, any_of(ok_true(), has_key("hits")), True),
    # —— 调试器（list_scripts / get_paused_info / get_websocket_messages 只有 debugger_ops 入口，没有独立工具）——
    ("debugger", "debugger_ops", {"action": "list_scripts"}, has_key("summary.byKind"), True),
    ("debugger", "debugger_ops", {"action": "list_scripts", "named_only": True}, has_key("count"), True),
    # search_in_sources 必须报告搜索统计（用于判断噪声过滤是否生效），且不能因失效脚本中断
    ("debugger", "debugger_ops", {"action": "search_in_sources", "query": "wx", "max_results": 3}, has_key("searchedScripts", "scope"), True),
    ("debugger", "debugger_ops", {"action": "search_in_sources", "query": "wx", "max_results": 3, "scope": "all"}, any_of(has_key("matches"), has_key("hint")), True),
    ("debugger", "debugger_ops", {"action": "get_paused_info"}, any_of(ok_true(), has_key("recentConsole")), True),
    ("debugger", "debugger_ops", {"action": "get_websocket_messages"}, any_of(ok_true(), has_key("events")), True),
    ("debugger", "debugger_ops", {"action": "list_breakpoints"}, has_key("xhrBreakpoints"), True),
    # 断点对：pattern 永不匹配，且紧随其后就撤销，属自清理
    ("debugger", "debugger_ops", {"action": "break_on_xhr", "url": "__smoke_test_never_match__"}, any_of(ok_true(), has_key("error")), True),
    ("debugger", "debugger_ops", {"action": "remove_breakpoints"}, any_of(ok_true(), has_key("remaining")), True),
    ("debugger", "debugger_ops", {"action": "resume_execution"}, lambda p: (isinstance(p, dict), "结构化返回（未暂停时 ok=false 属正常）"), True),
    # —— 分析（纯 Python，不依赖小程序）——
    ("analysis", "get_api_inventory", {"limit": 50}, any_of(ok_true(), has_key("apis"), has_key("total")), True),
    ("analysis", "analyze_auth_surface", {}, any_of(ok_true(), has_key("findings"), has_key("summary")), True),
    ("analysis", "find_idor_candidates", {}, any_of(ok_true(), has_key("candidates"), has_key("findings")), True),
    ("analysis", "find_sensitive_data_exposure", {}, any_of(ok_true(), has_key("findings")), True),
    ("analysis", "find_upload_surfaces", {}, any_of(ok_true(), has_key("findings")), True),
    ("analysis", "find_payment_and_order_surfaces", {}, any_of(ok_true(), has_key("findings")), True),
    ("analysis", "find_debug_admin_surfaces", {}, any_of(ok_true(), has_key("findings")), True),
    ("analysis", "find_sign_related_requests", {}, any_of(ok_true(), has_key("findings")), True),
    ("analysis", "passive_param_fuzz_suggestions", {}, any_of(ok_true(), has_key("suggestions")), True),
    ("analysis", "generate_security_notes", {}, any_of(ok_true(), has_key("markdown"), has_key("notes")), True),
    ("analysis", "generate_api_table_markdown", {}, lambda p: (bool(p), "非空") if p else (False, "空返回"), True),
    # —— 解密（离线，用固定样本；注意 crypto_helpers 用的是 snake_case 字段）——
    ("decrypt", "decrypt_ops", {"action": "auto_detect_encoding", "value": "SGVsbG8="}, has_key("candidates"), True),
    ("decrypt", "decrypt_ops", {"action": "decode_payload", "value": "SGVsbG8=", "input_encoding": "base64"}, has_key("text"), True),
    ("decrypt", "decrypt_ops", {"action": "detect_ecb_pattern", "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "input_encoding": "base64"}, has_key("possible_ecb"), True),
    ("decrypt", "decrypt_ops", {"action": "discover_runtime_crypto_functions"}, any_of(has_key("candidates"), has_key("hint")), True),
    # 用 JSON.stringify 验证点分路径调用（无副作用）
    ("decrypt", "decrypt_ops", {"action": "call_runtime_crypto_function", "function_name": "JSON.stringify", "args": [{"a": 1}]}, any_of(ok_true(), has_key("result")), True),
    # —— 逆向辅助 ——
    ("reverse", "reverse_ops", {"action": "identify_crypto_pattern", "text": "CryptoJS.AES.encrypt(data, key)"}, any_of(ok_true(), has_key("patterns"), has_key("pattern")), True),
    ("reverse", "reverse_ops", {"action": "match_reverse_cases", "text": "webpackJsonp"}, any_of(ok_true(), has_key("matched"), has_key("cases")), True),
    ("reverse", "reverse_ops", {"action": "detect_reverse_strategy", "text": "_0x1a2b('0x3')"}, any_of(ok_true(), has_key("strategy")), True),
    # —— 任务类 ——
    ("replay", "replay_ops", {"action": "get_replay_job", "job_id": "not-exist"}, lambda p: (isinstance(p, dict), "结构化返回"), True),
    ("pentest", "pentest_ops", {"action": "list_pentest_jobs"}, lambda p: (isinstance(p, list), "列表返回"), True),
    # —— 路由（只读部分）——
    ("route", "route_ops", {"action": "inspect_routes"}, any_of(ok_true(), has_key("pages")), True),
    # plan_route_crawl 是纯规划（dry-run）：不导航，但要能拿到分批计划。
    # 只规划 3 条，避免冒烟时把整份 143 路由计划塞进输出。
    (
        "route",
        "route_ops",
        {"action": "plan_route_crawl", "max_routes": 3},
        lambda p: (
            isinstance(p, dict) and p.get("ok") is True and p.get("dryRun") is True and isinstance(p.get("batches"), list),
            "dryRun 计划（含 batches）"
            if isinstance(p, dict) and p.get("dryRun") is True and isinstance(p.get("batches"), list)
            else f"缺少 dryRun/batches：{str(p)[:140]}",
        ),
        True,
    ),

    # —— 会改变状态，需 --include-mutating ——
    # selector 故意用一个不存在的，只验证「结构化返回」而不真的改界面
    ("mutating", "runtime_ops", {"action": "input_text_and_observe", "selector": "#nonexistent", "text": "x"}, any_of(ok_true(), has_key("result"), has_key("hint")), False),
    ("mutating", "route_ops", {"action": "enable_redirect_guard"}, any_of(ok_true(), has_key("enabled")), False),
    ("mutating", "route_ops", {"action": "disable_redirect_guard"}, any_of(ok_true(), has_key("enabled")), False),
    # selector 故意不存在，只验证结构化返回，不会真的点到东西
    ("mutating", "runtime_ops", {"action": "safe_click_and_observe", "selector": "#nonexistent"}, any_of(ok_true(), has_key("click"), has_key("hint")), False),
]


def run_checks(client: McpHttpClient, *, only: str, verbose: bool, include_mutating: bool) -> tuple[int, int, list[tuple[str, str, str]]]:
    """执行检查矩阵，返回 (通过数, 总数, 失败列表)。"""
    passed = 0
    total = 0
    failures: list[tuple[str, str, str]] = []

    for group, tool, args, validator, readonly in CHECKS:
        if only and group != only and tool != only:
            continue
        if not readonly and not include_mutating:
            continue

        total += 1
        label = f"{group}/{tool}"
        if args.get("action"):
            label += f"[{args['action']}]"

        started = time.time()
        try:
            result = client.call_tool(tool, args)
            text = extract_text(result)
        except Exception as exc:  # noqa: BLE001 - 自检要把任何异常都记下来
            passed_ok, detail = False, f"调用异常：{exc}"
        else:
            if result_is_error(result):
                # MCP 层把异常包成了 isError；正文才是真正原因
                passed_ok, detail = False, text.replace("[isError] ", "")[:180]
            else:
                payload: Any = text
                try:
                    payload = json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    pass
                passed_ok, detail = validator(payload)

        elapsed = time.time() - started
        if passed_ok:
            passed += 1
            mark = "PASS"
        else:
            mark = "FAIL"
            failures.append((label, detail, text if verbose else text[:200]))
        print(f"[{mark}] {label:<52} {elapsed:5.2f}s  {detail}")
        if verbose and not passed_ok:
            print(f"       ↳ {text[:600]}")

    return passed, total, failures


def main() -> int:
    """入口。"""
    parser = argparse.ArgumentParser(description="MCP tool chain smoke test.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=49999)
    parser.add_argument("--token", default="")
    parser.add_argument("--only", default="", help="只跑某个分组或某个工具")
    parser.add_argument("--verbose", action="store_true", help="失败时打印完整返回")
    parser.add_argument("--include-mutating", action="store_true", help="包含会改变小程序状态的检查")
    args = parser.parse_args()

    client = McpHttpClient(host=args.host, port=args.port, token=args.token, timeout=120.0)

    print("=== MCP 工具链自检 ===")
    print(f"端点: {client.endpoint_url}")
    print(f"模式: {'含可变检查' if args.include_mutating else '只读'}")
    print()

    try:
        client.initialize()
        tools = {tool.get("name") for tool in client.list_tools()}
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] 无法连接 MCP：{exc}")
        print("       请先运行 `02-一键启动.bat`，并确认 49999 在监听。")
        return 2

    print(f"已注册工具: {len(tools)} 个")
    print()

    # 先读评估流程 —— 这是 README 规定的正确客户端行为，也是门禁（SKILL_GATE）的放行条件。
    #
    # ⚠️ 必须放在 Phase 0 **之前**，否则冒烟结果会依赖 MCP 进程状态：
    # 门禁是**进程级**的（`SkillGate._loaded` / `_pushed` 是模块级单例的实例字段，
    # 没有会话维度、也没有重置时机），所以每次重启 MCP 后的**第一次**冒烟里，
    # 第一个受门禁的工具调用会被拦下、返回 `type: "skill_required"`
    # → 实测表现为「重启后第一次必假红 1 条（62/63），再跑一次才 63/63」。
    # 那不是工具坏了，但会让「冒烟红了」和「真有回归」分不清 —— 正是 N-4 那类问题。
    # 按真实客户端的正确顺序先读 skill，冒烟就与这个状态无关了。
    try:
        client.call_tool("skill_ops", {"action": "guide"})
        print("[OK] 已读取评估流程（skill_ops guide）—— 门禁放行条件已满足")
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] 读取 skill_ops 失败（不影响后续检查）：{exc}")
    print()

    # Phase 0：连接 CDP（对应 SKILL.md 的启动顺序）。
    # 新版本工具已支持按需自动连接，这里仍然显式做一次，便于定位是「连接」还是「工具」的问题。
    #
    # ⚠️ 这里的失败**必须计入最终统计与退出码**。此前只打印 `[FAIL]` 而不计数，
    # 于是 `connect_wmpf` 因返回值类型错误**完全不可用**时，冒烟依然报「61/61 通过」、
    # 退出码 0 —— 一个真实的回归就这样溜过去了（实测踩过）。
    print("--- Phase 0：连接 ---")
    phase_failures: list[tuple[str, str, Any]] = []
    phase_total = 0
    phase_passed = 0
    for phase_tool, phase_args in (("connect_wmpf", {}), ("network_enable", {})):
        phase_total += 1
        label = f"phase0/{phase_tool}"
        try:
            phase_result = client.call_tool(phase_tool, phase_args)
            phase_text = extract_text(phase_result)
            phase_error = result_is_error(phase_result)
            try:
                phase_payload: Any = json.loads(phase_text)
            except (json.JSONDecodeError, TypeError):
                phase_payload = phase_text
            good = (not phase_error) and not (
                isinstance(phase_payload, dict) and phase_payload.get("ok") is False
            )
            print(f"[{'PASS' if good else 'FAIL'}] {label}")
            if good:
                phase_passed += 1
            else:
                print(f"       ↳ {str(phase_payload)[:240]}")
                print("       Phase 0 未通过，后续依赖 CDP 的检查大概率也会失败。")
                phase_failures.append((label, str(phase_payload)[:240], phase_result))
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] {label}: {exc}")
            phase_failures.append((label, str(exc), None))
    print()

    missing = sorted({tool for _g, tool, _a, _v, _r in CHECKS if tool not in tools})
    if missing:
        print(f"[WARN] 自检引用了未注册的工具：{', '.join(missing)}")
        print()

    passed, total, failures = run_checks(
        client, only=args.only, verbose=args.verbose, include_mutating=args.include_mutating
    )

    # Phase 0 的检查同样计入总数与退出码 —— 否则「连不上 CDP」会被静默吞掉。
    passed += phase_passed
    total += phase_total
    failures = phase_failures + list(failures)

    print()
    print(f"=== 结果：{passed}/{total} 通过 ===")
    if failures:
        print()
        print("失败项：")
        for label, detail, _raw in failures:
            print(f"  - {label}: {detail}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

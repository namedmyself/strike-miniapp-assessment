#!/usr/bin/env python3
"""审计全部 MCP 工具的 inputSchema 严格性（P1-7）。

## 背景与结论（2026-09-22 定论）

实测 `runtime_ops(action="wait_route_stable", nonexistent_param=123)` **不报错**，
未知参数被静默忽略 —— 服务端（FastMCP）**从不设置 `additionalProperties`**，
这是它的默认宽松行为。

P0-2 / P0-3 当时记录的是 `InputValidationError: additionalProperties: false 不接受...`。
**该报错来自 MCP 客户端侧**（客户端按自己的 schema 校验），不是服务端 ——
直连（`scripts/wxmcp.py`）绕过了那一层，所以不报错。已实测确认：
`tools/list` 返回的 `runtime_ops.inputSchema` 顶层只有
`properties` / `required` / `title` / `type`，**没有 `additionalProperties`**。

## 结论：不改 schema

补 `additionalProperties: false` 会让**直连也变脆**（现在能跑的多传参数会变成报错），
风险大于收益。让「参数名写错」可见的正确手段是**返回值回显**
（如 `wait_route_stable` 回显 `timeoutSeconds`），而不是收紧 schema。

## 本脚本做什么

把每个工具的 `inputSchema` 打出来，统计 `additionalProperties` 的取值分布 ——
**作为现状基线**（防止将来有人无意间引入严格模式，造成行为不一致）。

纯离线：注入一个空的 `McpRuntimeSession`，不连 CDP、不碰真机。

用法：
    python scripts/audit_tool_schema.py              # 汇总 + 非严格工具清单
    python scripts/audit_tool_schema.py --verbose    # 列出全部工具
    python scripts/audit_tool_schema.py --strict     # 出现非预期状态时退出码 1
"""

from __future__ import annotations

import asyncio
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "e0e1-wx"))

from package.mcp_control.local_app import create_mcp_app  # noqa: E402
from package.mcp_control.runtime_session import McpRuntimeSession  # noqa: E402

UNSET = "<未设置>"


def field(obj, name: str, default=None):
    """从 pydantic 对象或 dict 里取字段，兼容两种返回形态。"""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


async def collect_rows() -> list[dict]:
    """把每个工具的 schema 关键信息抽成一行。"""
    mcp = create_mcp_app(runtime=McpRuntimeSession())
    tools = await mcp.list_tools()
    rows: list[dict] = []
    for tool in tools:
        schema = field(tool, "inputSchema", None) or {}
        if not isinstance(schema, dict):
            schema = {}
        additional = schema.get("additionalProperties", UNSET)
        properties = schema.get("properties")
        required = schema.get("required")
        rows.append({
            "name": str(field(tool, "name", "")),
            "additionalProperties": additional,
            "propertyCount": len(properties) if isinstance(properties, dict) else 0,
            "requiredCount": len(required) if isinstance(required, list) else 0,
            "schemaKeys": sorted(schema.keys()),
        })
    return sorted(rows, key=lambda r: r["name"])


def describe(value) -> str:
    """把 additionalProperties 的取值渲染成人能读的标签。"""
    if value is UNSET:
        return "未设置（宽松，未知键被静默忽略）"
    if value is False:
        return "false（严格，未知键直接拒收）"
    if value is True:
        return "true（显式宽松）"
    return repr(value)


async def main() -> int:
    """跑审计并汇总。"""
    verbose = "--verbose" in sys.argv
    strict_mode = "--strict" in sys.argv

    rows = await collect_rows()
    print("=" * 74)
    print(f"MCP 工具 inputSchema 严格性审计（共 {len(rows)} 个工具）")
    print("=" * 74)

    distribution = Counter(str(r["additionalProperties"]) for r in rows)
    print("\n[additionalProperties 取值分布]")
    for value, count in distribution.most_common():
        print(f"  {count:3d} 个  {describe(value) if value != UNSET else describe(UNSET)}")

    strict = [r for r in rows if r["additionalProperties"] is False]
    loose = [r for r in rows if r["additionalProperties"] is not False]

    print(f"\n[严格（拒收未知键）] {len(strict)} 个")
    for row in strict[:12]:
        print(f"    {row['name']}")
    if len(strict) > 12:
        print(f"    ... 另有 {len(strict) - 12} 个")

    print(f"\n[非严格（静默忽略未知键）] {len(loose)} 个")
    for row in loose:
        print(f"    {row['name']:<34} 参数 {row['propertyCount']:2d} 个")

    if verbose:
        print("\n[全部工具明细]")
        for row in rows:
            print(
                f"    {row['name']:<34} additionalProperties={str(row['additionalProperties']):<8} "
                f"props={row['propertyCount']:2d} required={row['requiredCount']:2d}"
            )

    print("\n" + "=" * 74)
    if loose:
        print(
            f"结论：{len(loose)} 个工具处于宽松模式 —— 这是**预期状态**，不是缺陷。\n"
            "      服务端（FastMCP）默认不设 additionalProperties，未知键被静默忽略。\n"
            "      当年 P0-2 / P0-3 记录的 InputValidationError 来自**客户端侧**校验，\n"
            "      与本文测的服务端行为不是一回事（直连已实测不报错）。\n"
            "      ⚠️ 不要为此补 additionalProperties=false —— 那会让直连也变脆（负收益）。\n"
            "      让「参数名写错」可见的正确手段是返回值回显（如 timeoutSeconds）。"
        )
        print("=" * 74)
        return 0
    print(
        "结论：全部工具均为严格模式 —— ⚠️ 与既定结论不符！\n"
        "      本项目已定论「统一宽松、不改 schema」（见 P1-7）。\n"
        "      出现严格模式说明 schema 被改动过，请复核是否有意为之。"
    )
    print("=" * 74)
    return 1 if strict_mode else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

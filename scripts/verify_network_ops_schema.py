"""验证 network_ops 的 inputSchema 是否已暴露 excludeStatic 等参数。

用法：
    "D:/Python 12.4/python.exe" scripts/verify_network_ops_schema.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "e0e1-wx"))

from package.mcp_control.local_app import create_mcp_app  # noqa: E402

# P0-2 / P0-3 要求必须出现在 network_ops 签名里的参数
REQUIRED = [
    "excludeStatic",
    "excludeTelemetry",
    "compact",
    "maxLength",
]
# 这两个是已有参数，顺带确认没被改坏
REGRESSION = ["action", "limit", "keyword", "domain", "pathPrefix", "requestId"]


async def main() -> int:
    mcp = create_mcp_app()
    tools = await mcp.list_tools()
    by_name = {t.name: t for t in tools}

    if "network_ops" not in by_name:
        print("[FAIL] 未找到 network_ops 工具")
        return 1

    schema = by_name["network_ops"].inputSchema or {}
    props = set((schema.get("properties") or {}).keys())
    print(f"network_ops.inputSchema.properties ({len(props)}):")
    for key in sorted(props):
        print(f"  - {key}")

    failed = False
    print("\n--- P0-2 / P0-3 新增参数 ---")
    for key in REQUIRED:
        ok = key in props
        print(f"  [{'PASS' if ok else 'FAIL'}] {key}")
        failed |= not ok

    print("\n--- 回归：既有参数不得丢失 ---")
    for key in REGRESSION:
        ok = key in props
        print(f"  [{'PASS' if ok else 'FAIL'}] {key}")
        failed |= not ok

    # additionalProperties 仍应为 false（保持严格），但参数已齐
    ap = schema.get("additionalProperties", None)
    print(f"\nadditionalProperties = {ap}")

    # 确认 get_all_requests / get_recent_requests 仍在 action enum 里
    enum = (schema.get("properties", {}).get("action", {}) or {}).get("enum") or []
    print(f"action enum 共 {len(enum)} 项")
    for act in ("get_all_requests", "get_recent_requests"):
        ok = act in enum
        print(f"  [{'PASS' if ok else 'FAIL'}] enum 含 {act}")
        failed |= not ok

    # 顺带确认独立工具仍暴露同样的参数（两边必须一致）
    print("\n--- 独立工具参数一致性 ---")
    for tool_name, expect in (
        ("get_all_requests", ["excludeStatic", "limit", "pathPrefix"]),
        ("get_recent_requests", ["excludeStatic", "compact", "pathPrefix"]),
    ):
        tool = by_name.get(tool_name)
        if tool is None:
            print(f"  [FAIL] 未找到 {tool_name}")
            failed = True
            continue
        tprops = set((tool.inputSchema or {}).get("properties", {}).keys())
        for key in expect:
            ok = key in tprops
            print(f"  [{'PASS' if ok else 'FAIL'}] {tool_name}.{key}")
            failed |= not ok

    # P0-1 / P2-4：storage 扫描的 raw 护栏必须能从工具层传进去
    print("\n--- scan_sensitive_storage 的 raw 护栏参数 ---")
    for tool_name, expect in (
        ("scan_sensitive_storage", ["includeRaw", "maxRawChars"]),
        ("runtime_ops", ["includeRaw", "maxRawChars"]),
    ):
        tool = by_name.get(tool_name)
        if tool is None:
            print(f"  [FAIL] 未找到 {tool_name}")
            failed = True
            continue
        tprops = set((tool.inputSchema or {}).get("properties", {}).keys())
        for key in expect:
            ok = key in tprops
            print(f"  [{'PASS' if ok else 'FAIL'}] {tool_name}.{key}")
            failed |= not ok

    print("\n=== 结果：" + ("FAIL" if failed else "ALL PASS") + " ===")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

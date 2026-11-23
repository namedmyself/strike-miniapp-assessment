#!/usr/bin/env python3
"""离线验证：analyze_auth_surface 是否把「空 token」误判为「有认证」（P2-7②）。

只读，不连 CDP。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "e0e1-wx"))

from package.mcp_control.runtime_session import McpRuntimeSession  # noqa: E402


def req(rid: str, headers, status: int = 200) -> dict:
    return {
        "id": rid,
        "url": f"https://example.com/api/{rid}",
        "method": "GET",
        "path": f"/api/{rid}",
        "query": {},
        "statusCode": status,
        "requestHeaders": headers,
    }


def main() -> int:
    session = McpRuntimeSession()

    cases = [
        ("空 token（应为【未认证】，需上报）", req("empty-token", {"token": "", "cookie": ""})),
        ("完全没有认证头（应为【未认证】，需上报）", req("no-headers", {})),
        ("空 Authorization（应为【未认证】，需上报）", req("empty-auth", {"Authorization": ""})),
        ("有效 token（应为【已认证】，不该上报）", req("valid-token", {"token": "eyJhbGciOiJIUzI1NiJ9.abc"})),
        ("只有 User-Agent（应为【未认证】，需上报）", req("ua-only", {"User-Agent": "MicroMessenger"})),
    ]

    requests = [item for _, item in cases]
    result = session.analyze_auth_surface(requests)
    reported = {f.get("requestId") for f in result.get("findings") or []}

    print("=" * 78)
    print("analyze_auth_surface —— 空认证头识别验证（P2-7②）")
    print("=" * 78)
    print(f"count = {result.get('count')}\n")

    expect_report = {
        "empty-token": True,
        "no-headers": True,
        "empty-auth": True,
        "valid-token": False,
        "ua-only": True,
    }

    bad = 0
    for label, item in cases:
        rid = item["id"]
        got = rid in reported
        want = expect_report[rid]
        ok = got == want
        if not ok:
            bad += 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        print(f"         期望上报={want}  实际上报={got}   headers={item['requestHeaders']}")

    print()
    print("=" * 78)
    if bad == 0:
        print("结论：空认证头全部被正确识别为「未认证」。")
    else:
        print(f"结论：{bad} 项判定错误 —— 空认证头被误判为「有认证」，会【漏报未授权访问】。")
    print("=" * 78)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())

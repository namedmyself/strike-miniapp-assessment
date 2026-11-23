"""验证 safe_tool 的异常兜底：error 永远非空，超时类异常带副作用告警。

用法：
    "D:/Python 12.4/python.exe" scripts/verify_safe_tool_error.py
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


class RaisingSession:
    """session.network_ops 抛指定异常。"""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    async def network_ops(self, action: str, **kwargs: Any) -> str:
        raise self.exc


def check(label: str, cond: bool) -> bool:
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    return cond


async def call(mcp: Any, args: dict[str, Any]) -> dict[str, Any]:
    result = await mcp.call_tool("network_ops", args)
    blocks = result[0] if isinstance(result, tuple) else result
    text = "".join(getattr(b, "text", "") or "" for b in (blocks or []))
    return json.loads(text) if text else {}


async def scenario(label: str, exc: BaseException, expect_timeout: bool) -> bool:
    print(f"\n{label}")
    fake = RaisingSession(exc)
    mcp = create_mcp_app(runtime=fake)
    payload = await call(mcp, {"action": "get_all_requests"})
    print(f"       error     = {payload.get('error')!r}")
    print(f"       errorType = {payload.get('errorType')!r}")
    print(f"       timedOut  = {payload.get('timedOut')}")

    failed = False
    failed |= not check("error 非空（不再出现 error:'' 的零信息返回）", bool(str(payload.get("error") or "").strip()))
    failed |= not check("errorType 已给出异常类名", bool(payload.get("errorType")))
    if expect_timeout:
        failed |= not check("timedOut=True", payload.get("timedOut") is True)
        failed |= not check(
            "sideEffectMayHaveApplied=True（提示调用方别盲目重试）",
            payload.get("sideEffectMayHaveApplied") is True,
        )
    else:
        failed |= not check("非超时异常不应带 timedOut", payload.get("timedOut") is None)
    return failed


async def main() -> int:
    skill_docs.SKILL_GATE.mark_loaded()

    failed = False
    # 核心回归：空消息异常（实测就是这种，导致 error:""）
    failed |= await scenario("场景 A：TimeoutError() —— 消息为空字符串", TimeoutError(), True)
    failed |= await scenario("场景 B：asyncio.TimeoutError()", asyncio.TimeoutError(), True)
    failed |= await scenario("场景 C：RuntimeError('boom') —— 有消息", RuntimeError("boom"), False)
    failed |= await scenario("场景 D：ValueError() —— 消息为空的非超时异常", ValueError(), False)

    print("\n=== 结果：" + ("FAIL" if failed else "ALL PASS") + " ===")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

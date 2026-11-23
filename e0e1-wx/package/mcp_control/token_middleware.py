"""MCP Streamable HTTP 的鉴权与会话头校验中间件。"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qs

# 不需要携带 Mcp-Session-Id 的 JSON-RPC 方法（建立会话本身 + 保活）
SESSION_FREE_METHODS = {"initialize", "notifications/initialized", "notifications/cancelled", "ping"}


def header_value(scope: dict, name: bytes) -> str:
    """从 ASGI scope 中取首个同名请求头。"""
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value.decode("utf-8", errors="ignore")
    return ""


async def read_body(receive: Callable[..., Awaitable[dict]]) -> bytes:
    """把 ASGI 请求体完整读出，便于后续重新放回。

    注意：`http.disconnect` 必须显式收口 —— 否则 `continue` 会在这里空转成死循环。
    """
    chunks: list[bytes] = []
    while True:
        message = await receive()
        msg_type = message.get("type")
        if msg_type == "http.disconnect":
            break
        if msg_type != "http.request":
            continue
        chunks.append(message.get("body") or b"")
        if not message.get("more_body"):
            break
    return b"".join(chunks)


def replay_body(body: bytes, original_receive: Callable[..., Awaitable[dict]] | None = None) -> Callable[..., Awaitable[dict]]:
    """把读过的请求体放回下游，之后把 receive **交还给原始连接**。

    ⚠️ 这里踩过一个会让整个传输层瘫痪的坑：
    早期实现是「只吐一次 body，之后固定返回 `http.disconnect`」。但 FastMCP 的
    SSE 响应生成器在写事件流期间**还会再等一次 receive** 来感知客户端是否断开 ——
    拿到伪造的 `http.disconnect` 就误判「客户端走了」，于是提前终止响应。
    现象是**响应头完全正常（200 + text/event-stream + mcp-session-id）但 body 为空**，
    uvicorn 侧报 `ASGI callable returned without completing response`，
    任何标准 MCP 客户端都会卡到超时。

    正确做法：首次给缓存 body，**之后的每次调用都委托给原始 receive**。
    """
    delivered = False

    async def _receive() -> dict:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        if original_receive is not None:
            return await original_receive()
        return {"type": "http.request", "body": b"", "more_body": False}

    return _receive


def extract_token(scope: dict, query: dict[str, list[str]]) -> tuple[str, str]:
    """按 query -> X-MCP-Token -> Authorization 的顺序取出调用方提供的 token。"""
    supplied = (query.get("token") or [""])[0]
    if supplied:
        return supplied, "query"
    header_token = header_value(scope, b"x-mcp-token")
    if header_token:
        return header_token, "header:X-MCP-Token"
    authorization = header_value(scope, b"authorization")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip(), "header:Authorization"
    return "", ""


class TokenMiddleware:
    """校验 MCP HTTP 调用的 token；支持 query 与请求头两种传法。"""

    def __init__(self, app: Callable, token: str) -> None:
        """保存下游 ASGI 应用与期望的 token。"""
        self.app = app
        self.token = str(token or "")

    async def __call__(self, scope: dict, receive: Callable[..., Awaitable[dict]], send: Callable[..., Awaitable[None]]) -> None:
        """拦截 HTTP 请求并校验 token，不通过则返回 401。"""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path") or "")
        if path == "/":
            await self.app(scope, receive, send)
            return
        raw_query = bytes(scope.get("query_string") or b"").decode("utf-8", errors="ignore")
        supplied, _source = extract_token(scope, parse_qs(raw_query))
        if self.token and supplied != self.token:
            body = (
                "Unauthorized MCP token\n"
                "请带上 token：\n"
                "  - URL query：/mcp?token=<token>\n"
                "  - 或请求头：X-MCP-Token: <token>\n"
                "  - 或请求头：Authorization: Bearer <token>\n"
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


class SessionHeaderMiddleware:
    """缺少 Mcp-Session-Id 时返回明确的 400，而不是静默的空工具列表。

    MCP Streamable HTTP 的会话是两步的：先 `initialize` 拿 `mcp-session-id` 响应头，
    后续所有请求都要带上它。旧行为是「不带会话头调 tools/list 返回空数组」，
    很容易被误判成「服务没起来」。
    """

    def __init__(self, app: Callable) -> None:
        """保存下游 ASGI 应用。"""
        self.app = app

    async def __call__(self, scope: dict, receive: Callable[..., Awaitable[dict]], send: Callable[..., Awaitable[None]]) -> None:
        """检查会话头，必要时提前返回结构化错误。"""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "")
        if method != "POST" or not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        if header_value(scope, b"mcp-session-id"):
            await self.app(scope, receive, send)
            return

        body = await read_body(receive)
        rpc_method = ""
        try:
            payload: Any = json.loads(body.decode("utf-8", errors="ignore") or "{}")
            if isinstance(payload, dict):
                rpc_method = str(payload.get("method") or "")
            elif isinstance(payload, list) and payload and isinstance(payload[0], dict):
                rpc_method = str(payload[0].get("method") or "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            rpc_method = ""

        if not rpc_method or rpc_method in SESSION_FREE_METHODS:
            await self.app(scope, replay_body(body, receive), send)
            return

        message = (
            f"400 Missing Mcp-Session-Id：{rpc_method} 需要先建立会话。\n"
            "正确姿势：\n"
            "  1) POST /mcp 发送 {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",...}\n"
            "  2) 从响应头取 mcp-session-id\n"
            "  3) 后续所有请求带请求头 Mcp-Session-Id: <session-id>\n"
            "注意：不带会话头时旧行为是返回空列表（不是报错），容易误判为服务未启动。\n"
        )
        payload_out = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": f"Missing Mcp-Session-Id for method {rpc_method}"},
                "hint": message,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(payload_out)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload_out})

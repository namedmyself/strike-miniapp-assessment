#!/usr/bin/env python3
"""最小可用 MCP 直连客户端（只用标准库）。

用途：当 AI 客户端没有把 wxcdp 的 61+ 个工具注册成会话工具时，
可以直接用这个脚本走 Streamable HTTP 调用，不用自己手搓 JSON-RPC 帧和会话头。

关键点（也是最容易踩的坑）：
  1) 必须先 `initialize`，再从**响应头**取 `mcp-session-id`；
  2) 后续每个请求都要带 `Mcp-Session-Id` 请求头，
     否则旧行为会返回**空工具列表**（不是报错），极易误判成「服务没起来」；
  3) token 可以走 URL query，也可以走 `X-MCP-Token` / `Authorization: Bearer` 请求头。

示例：
  python scripts\\wxmcp.py list
  python scripts\\wxmcp.py call connection_ops --args '{"action":"find_appservice"}'
  python scripts\\wxmcp.py call capture_screenshot --args '{"file_path":"tmp\\shot.png"}'
  python scripts\\wxmcp.py call route_ops --args '{"action":"inspect_routes"}'
  python scripts\\wxmcp.py raw tools/list
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 49999
DEFAULT_TOKEN = "CHANGE_ME_SET_STRIKE_MCP_TOKEN"
PROTOCOL_VERSION = "2025-06-18"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def load_default_token() -> str:
    """尽量从项目内的 config.py 读取 token，读不到就用内置默认值。"""
    config_path = PROJECT_ROOT / "e0e1-wx" / "package" / "mcp_control" / "config.py"
    if config_path.is_file():
        try:
            for line in config_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("DEFAULT_MCP_TOKEN"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            pass
    return DEFAULT_TOKEN


def parse_sse_or_json(raw: str) -> dict | None:
    """MCP 可能返回 application/json，也可能返回 text/event-stream。"""
    text = (raw or "").strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    payloads: list[str] = []
    for line in text.splitlines():
        if line.startswith("data:"):
            payloads.append(line[5:].strip())
    for payload in payloads:
        if not payload or payload == "[DONE]":
            continue
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            return decoded
    return None


class McpHttpClient:
    """极简 Streamable HTTP MCP 客户端：负责 initialize / 会话头 / 调用。"""

    def __init__(self, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, token: str = "", path: str = "/mcp", timeout: float = 60.0) -> None:
        """记录端点参数，token 同时支持 query 与请求头两种传法。"""
        self.host = host
        self.port = int(port)
        self.token = token or load_default_token()
        self.path = path
        self.timeout = float(timeout)
        self.session_id = ""
        self.next_id = 1

    @property
    def base_url(self) -> str:
        """不带 token 的端点地址。"""
        return f"http://{self.host}:{self.port}{self.path}"

    @property
    def endpoint_url(self) -> str:
        """带 token 的端点地址（与 02-一键启动.bat 打印的一致）。"""
        return f"{self.base_url}?token={self.token}"

    def _post(self, payload: dict, *, extra_headers: dict | None = None) -> tuple[dict | None, dict]:
        """发送一条 JSON-RPC 消息，返回 (解析后的消息, 响应头)。"""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            # 走请求头传 token，避免 token 进 URL 日志 / 历史记录
            "X-MCP-Token": self.token,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        headers.update(extra_headers or {})

        request = urllib.request.Request(self.endpoint_url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                # 通知（如 notifications/initialized）会返回 202 且没有响应体
                if response.status in {202, 204}:
                    return None, response_headers
                try:
                    raw = response.read().decode("utf-8", errors="replace")
                except http.client.IncompleteRead as exc:
                    raw = (exc.partial or b"").decode("utf-8", errors="replace")
                return parse_sse_or_json(raw), response_headers
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {exc.reason}\n{detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"连不上 {self.endpoint_url}：{exc.reason}\n"
                "请先运行 02-一键启动.bat，并确认 49999 在监听。"
            ) from exc

    def initialize(self) -> dict:
        """建立会话：initialize 后从响应头取 mcp-session-id，再回一条 initialized。"""
        message, headers = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.next_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "wxmcp-minimal", "version": "1.0.0"},
                },
            }
        )
        self.next_id += 1
        self.session_id = headers.get("mcp-session-id", "")
        if not self.session_id:
            raise RuntimeError(
                "initialize 的响应头里没有 mcp-session-id。\n"
                "如果你把 streamable_http 配成了无状态模式，会话头不会下发；"
                "请检查服务端 stateless_http 是否为 False。"
            )
        # initialized 是通知，不需要 id，也不期待响应
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return message or {}

    def request(self, method: str, params: dict | None = None) -> dict:
        """发送一条带会话头的 JSON-RPC 请求。"""
        if not self.session_id:
            self.initialize()
        message, _headers = self._post(
            {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        )
        self.next_id += 1
        if message is None:
            raise RuntimeError("服务端返回了空响应体（既不是 JSON 也不是 SSE data 帧）。")
        return message

    def list_tools(self) -> list[dict]:
        """列出全部工具。"""
        message = self.request("tools/list")
        result = message.get("result") or {}
        tools = result.get("tools") or []
        return tools if isinstance(tools, list) else []

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """调用一个工具。"""
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})


def result_is_error(result: dict) -> bool:
    """判断 tools/call 是否以错误结束。"""
    payload = result.get("result") if isinstance(result, dict) else None
    return bool(isinstance(payload, dict) and payload.get("isError"))


def extract_text(result: dict) -> str:
    """把 tools/call 的结果整理成可读文本。

    注意：`isError` 时正文才是真正有用的报错信息，直接把它拿出来，
    不要把整个 envelope 丢给调用方（否则只会看到一坨 JSON）。
    """
    payload = result.get("result") or {}
    content = payload.get("content") if isinstance(payload, dict) else None
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                chunks.append(str(item.get("text") or ""))
            else:
                chunks.append(json.dumps(item, ensure_ascii=False))
        text = "\n".join(chunks)
        return f"[isError] {text}" if result_is_error(result) else text
    return json.dumps(payload, ensure_ascii=False, indent=2)


def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="Minimal stdlib MCP client for the wxcdp endpoint.")
    parser.add_argument("command", choices=["list", "call", "raw", "info"], help="要执行的动作")
    parser.add_argument("target", nargs="?", default="", help="call 时是工具名；raw 时是 JSON-RPC 方法名")
    parser.add_argument("--args", default="{}", help="call/raw 的参数，JSON 字符串或 @文件路径")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token", default="")
    parser.add_argument("--path", default="/mcp")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--pretty", action="store_true", help="格式化输出 JSON")
    return parser.parse_args()


def load_args(raw: str) -> dict:
    """支持直接传 JSON，或 @path 从文件读取。"""
    text = raw.strip()
    if text.startswith("@"):
        text = Path(text[1:]).read_text(encoding="utf-8")
    if not text:
        return {}
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise SystemExit("--args 必须是一个 JSON 对象")
    return parsed


def main() -> int:
    """入口。"""
    args = parse_args()
    client = McpHttpClient(host=args.host, port=args.port, token=args.token, path=args.path, timeout=args.timeout)

    if args.command == "info":
        print(f"端点: {client.endpoint_url}")
        print(f"token 传法: URL query 与请求头 X-MCP-Token 均可")
        return 0

    if args.command == "list":
        client.initialize()
        tools = client.list_tools()
        print(f"工具数量: {len(tools)}")
        for tool in tools:
            schema = tool.get("inputSchema") or {}
            action = (schema.get("properties") or {}).get("action") or {}
            enum = action.get("enum")
            suffix = f"  action enum: {len(enum)} 项" if enum else ""
            print(f"  - {tool.get('name')}{suffix}")
        return 0

    if args.command == "call":
        if not args.target:
            raise SystemExit("call 需要工具名，例如：call connection_ops --args '{\"action\":\"status\"}'")
        client.initialize()
        result = client.call_tool(args.target, load_args(args.args))
        text = extract_text(result)
        if args.pretty:
            try:
                print(json.dumps(json.loads(text), ensure_ascii=False, indent=2))
                return 0
            except json.JSONDecodeError:
                pass
        print(text)
        return 0

    if args.command == "raw":
        if not args.target:
            raise SystemExit("raw 需要 JSON-RPC 方法名，例如：raw tools/list")
        client.initialize()
        message = client.request(args.target, load_args(args.args))
        print(json.dumps(message, ensure_ascii=False, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

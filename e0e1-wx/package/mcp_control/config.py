"""摘要：集中生成 MCP 固定本机地址、客户端添加命令和内部进程配置载荷。"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode

DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 49999
DEFAULT_MCP_TOKEN = "CHANGE_ME_SET_STRIKE_MCP_TOKEN"


def default_mcp_project_root() -> Path:
    """返回当前项目根目录，允许测试环境用 MCP_PROJECT_ROOT 覆盖。"""
    raw_root = str(os.getenv("MCP_PROJECT_ROOT", "")).strip()
    if raw_root:
        return Path(raw_root).expanduser()
    return Path(__file__).resolve().parents[2]


@dataclass(slots=True)
class McpServerConfig:
    """描述内置 MCP HTTP 服务配置；host 固定为 127.0.0.1，不对外开放。"""

    port: int = DEFAULT_MCP_PORT
    token: str = DEFAULT_MCP_TOKEN
    project_root: Path | None = None
    host: str = field(default=DEFAULT_MCP_HOST, init=False)

    def resolved_project_root(self) -> Path:
        """返回已经补齐默认值的当前项目目录。"""
        return Path(self.project_root).expanduser() if self.project_root is not None else default_mcp_project_root()

    def endpoint_url(self) -> str:
        """生成固定 127.0.0.1 的 Streamable HTTP MCP 地址。"""
        query = urlencode({"token": self.token})
        return f"http://{DEFAULT_MCP_HOST}:{int(self.port)}/mcp?{query}"

    def install_commands(self) -> dict[str, str]:
        """生成外部 MCP 客户端的接入信息：通用 JSON 配置 + 常见 CLI 命令。

        `json` 是可直接贴进任何 MCP 客户端配置文件的片段 ——
        市面上客户端众多（Cursor / Windsurf / Cline / Cherry Studio / Claude Desktop …），
        与其逐个适配，不如给出通用格式让用户自己贴。
        """
        url = self.endpoint_url()
        return {
            "json": json.dumps(
                {"mcpServers": {"wxcdp": {"type": "http", "url": url}}},
                indent=2,
                ensure_ascii=False,
            ),
            "claude": f"claude mcp add wxcdp --tool-mode full --transport http --scope user {url}",
            "codex": f"codex mcp add wxcdp --url {url}",
        }

    def delete_commands(self) -> dict[str, str]:
        """生成外部 MCP 客户端删除 wxcdp 配置的命令。"""
        return {
            "claude": "claude mcp remove --scope user wxcdp",
            "codex": "codex mcp remove wxcdp",
        }

    def to_payload(self) -> dict[str, str | int]:
        """转成可安全传入 multiprocessing 的普通字典。"""
        return {
            "host": DEFAULT_MCP_HOST,
            "port": int(self.port),
            "token": str(self.token),
            "project_root": str(self.resolved_project_root()),
        }

    @classmethod
    def from_payload(cls, payload: dict) -> "McpServerConfig":
        """从 worker 收到的普通字典恢复配置对象，并忽略任何 host 覆盖。"""
        return cls(
            port=int(payload.get("port") or DEFAULT_MCP_PORT),
            token=str(payload.get("token") or DEFAULT_MCP_TOKEN),
            project_root=Path(str(payload.get("project_root") or default_mcp_project_root())),
        )

    def state_payload(self, *, status: str, message: str, pid: int | None = None, last_error: str = "") -> dict:
        """生成 UI 可直接消费的 MCP 状态快照。"""
        return {
            "status": str(status),
            "message": str(message),
            "running": str(status) == "running",
            "pid": pid,
            "url": self.endpoint_url(),
            "commands": self.install_commands(),
            "delete_commands": self.delete_commands(),
            "project_root": str(self.resolved_project_root()),
            "last_error": str(last_error or ""),
        }

"""Start the package-local MCP server without opening the GUI."""

from __future__ import annotations

import os
from pathlib import Path

from package.mcp_control.config import McpServerConfig
from package.mcp_control.http_entry import start_http_server_inside_process

# 自己写 pid 文件：否则手工 `python e0e1-wx\start_mcp_server.py` 启动时没有 pid，
# 停止脚本只能靠端口反查，而且会读到陈旧的 pid 文件。
PID_FILE = Path(__file__).resolve().parent.parent / "logs" / "start-mcp-server.pid"


def write_pid_file() -> None:
    """把当前进程 PID 写到 logs/start-mcp-server.pid。"""
    try:
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(f"{os.getpid()}\n", encoding="ascii")
    except OSError as exc:
        print(f"[WARN] 写入 pid 文件失败（不影响服务）：{exc}")


def main() -> None:
    config = McpServerConfig()
    write_pid_file()
    print(f"[OK] MCP endpoint: {config.endpoint_url()}")
    print(f"[OK] PID: {os.getpid()} -> {PID_FILE}")
    commands = config.install_commands()
    print("[OK] 接入任意 MCP 客户端 —— 把下面这段贴进它的配置文件（mcpServers）即可:")
    print(commands["json"])
    print(f"[OK] Codex add command: {commands['codex']}")
    print(f"[OK] Claude add command: {commands['claude']}")
    print("[INFO] Press Ctrl+C to stop the MCP server.")
    try:
        start_http_server_inside_process(config)
    finally:
        try:
            PID_FILE.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    main()

"""只重启 MCP Server 进程（不动 WMPFDebugger / CDP 代理）。

为什么需要它：改完 `package/` 下的 Python 代码后必须重启 MCP 服务才生效，
而 `05-一键停止.bat` + `02-一键启动.bat` 会**整条链**重启 —— WMPFDebugger
（9421 / 62000）被一起重启会打断已经建立好的小程序 CDP 会话，
重建代价很高（要重新 connect_wmpf + 重扫路由）。

本脚本只按 `logs/start-mcp-server.pid` 停掉 MCP 服务，再按项目原有的启动方式
（同解释器 / 同 cwd / CREATE_NO_WINDOW + CREATE_NEW_PROCESS_GROUP）拉起来，
CDP 代理保持存活，重启后 `connect_wmpf` 即可恢复。

用法：
    "D:/Python 12.4/python.exe" scripts/restart_mcp_server.py
    "D:/Python 12.4/python.exe" scripts/restart_mcp_server.py --timeout 60
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
E0E1_WX_DIR = PROJECT_ROOT / "e0e1-wx"
MCP_SCRIPT = E0E1_WX_DIR / "start_mcp_server.py"
LOG_DIR = PROJECT_ROOT / "logs"
MCP_LOG = LOG_DIR / "start-mcp-server.log"
MCP_PID = LOG_DIR / "start-mcp-server.pid"
MCP_PORT = 49999


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def read_pid() -> int | None:
    try:
        return int(MCP_PID.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def process_alive(pid: int) -> bool:
    """用 tasklist 判断进程是否还在（比 os.kill(pid, 0) 在 Windows 上可靠）。"""
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return str(pid) in (result.stdout or "")


def stop_mcp(pid: int, timeout: float = 15.0) -> bool:
    print(f"[1/4] 停止 MCP Server (PID {pid}) ...")
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not process_alive(pid):
            print("      [OK] 进程已退出")
            return True
        time.sleep(0.5)
    print(f"      [FAIL] 进程 {pid} 在 {timeout}s 内未退出")
    return False


def wait_port_free(timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not port_open(MCP_PORT):
            print(f"      [OK] 端口 {MCP_PORT} 已释放")
            return True
        time.sleep(0.5)
    print(f"      [FAIL] 端口 {MCP_PORT} 仍被占用")
    return False


def start_mcp() -> int:
    print("[3/4] 启动 MCP Server ...")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    # 与 scripts/start_full_chain.py 的 launch_hidden_python 保持一致
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    with MCP_LOG.open("a", encoding="utf-8") as log_file:
        log_file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] restart_mcp_server.py launching\n")
        log_file.flush()
        process = subprocess.Popen(
            [sys.executable, str(MCP_SCRIPT)],
            cwd=str(E0E1_WX_DIR),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )
    MCP_PID.write_text(f"{process.pid}\n", encoding="ascii")
    print(f"      [OK] 新 PID {process.pid}（解释器 {sys.executable}）")
    return int(process.pid)


def wait_port_open(timeout: float = 45.0) -> bool:
    print(f"[4/4] 等待端口 {MCP_PORT} 就绪 ...")
    started = time.time()
    deadline = started + timeout
    while time.time() < deadline:
        if port_open(MCP_PORT):
            print(f"      [OK] {MCP_PORT} 已监听（耗时 {time.time() - started:.1f}s）")
            return True
        time.sleep(0.5)
    print(f"      [FAIL] {timeout}s 内未监听，请看日志：{MCP_LOG}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="只重启 MCP Server，保留 WMPFDebugger。")
    parser.add_argument("--timeout", type=float, default=45.0, help="等待端口就绪的秒数")
    args = parser.parse_args()

    if not MCP_SCRIPT.exists():
        print(f"[FAIL] 找不到 {MCP_SCRIPT}")
        return 1

    old_pid = read_pid()
    print(f"MCP 脚本 : {MCP_SCRIPT}")
    print(f"日志     : {MCP_LOG}")
    print(f"旧 PID   : {old_pid if old_pid else '(无 pid 文件)'}")
    print()

    print("[2/4] 等待端口释放 ...")
    if old_pid and process_alive(old_pid):
        if not stop_mcp(old_pid):
            return 1
    else:
        print(f"      旧进程不存在，跳过停止；检查端口 {MCP_PORT} 占用 ...")
    if not wait_port_free():
        return 1

    start_mcp()
    if not wait_port_open(args.timeout):
        return 1

    print("\n[OK] MCP Server 已重启完成。WMPFDebugger（9421 / 62000）未受影响。")
    print("     下一步：调用 connect_wmpf 恢复 CDP 会话。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

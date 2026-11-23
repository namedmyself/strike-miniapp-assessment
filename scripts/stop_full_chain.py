#!/usr/bin/env python3
"""一键停止：关闭调试链路占用的端口并结束相关进程。

对应根目录按钮 `05-一键停止.bat`。

它做三件事：
  1) 按 logs/*.pid 与 WMPFDebugger/logs/*.pid 定位本工具启动的进程；
  2) 兜底扫描 9421 / 62000 / 49999 三个端口的实际监听进程；
  3) 结束后校验端口已释放，并清理过期 pid 文件。

注意：Frida 的 hook 活在**微信小程序进程的内存里**，关闭端口不会解除注入。
需要彻底回到「未注入」状态时，加 `--kill-wechat`（会关掉微信小程序窗口），
或者自己手动关掉再打开小程序。
"""

from __future__ import annotations

import argparse
import json
import locale
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
WMPF_DEBUGGER_DIR = PROJECT_ROOT / "WMPFDebugger"
DEBUGGER_LOG_DIR = WMPF_DEBUGGER_DIR / "logs"

WATCHED_PORTS: tuple[int, ...] = (9421, 62000, 49999)
PORT_ROLES = {
    9421: "小程序回连的调试服务",
    62000: "CDP 代理",
    49999: "MCP HTTP 服务",
}
PID_FILES: tuple[tuple[Path, str], ...] = (
    (LOG_DIR / "start-engine.pid", "调试引擎"),
    (LOG_DIR / "start-mcp-server.pid", "MCP Server"),
    (DEBUGGER_LOG_DIR / "wmpfdebugger-admin.pid", "WMPFDebugger 注入器"),
)

# PID 复用保护：只有这些进程名才允许被结束，避免误杀同名无关进程。
ALLOWED_PROCESS_NAMES = {
    "python.exe",
    "pythonw.exe",
    "node.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
}
# 微信侧进程名（用于 --kill-wechat 清除注入态）
WECHAT_PROCESS_NAMES = (
    "WeChatAppEx.exe",
    "WeChatAppEx",
    "WeChat.exe",
    "Weixin.exe",
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def info(message: str) -> None:
    """打印普通信息。"""
    print(f"[INFO] {message}")


def ok(message: str) -> None:
    """打印成功信息。"""
    print(f"[OK] {message}")


def warn(message: str) -> None:
    """打印警告信息。"""
    print(f"[WARN] {message}")


def decode_console(data: bytes) -> str:
    """解码外部命令输出。

    Windows 自带工具（taskkill / netstat / tasklist）按**控制台代码页**输出，
    中文系统上是 cp936，直接按 UTF-8 解会变成乱码。
    """
    for encoding in ("utf-8", locale.getpreferredencoding(False), "cp936", "mbcs", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def run_command(args: list[str]) -> tuple[int, str]:
    """执行外部命令并返回 (返回码, 合并输出)。"""
    try:
        completed = subprocess.run(args, capture_output=True, check=False)
    except FileNotFoundError:
        return 127, ""
    output = decode_console((completed.stdout or b"") + (completed.stderr or b"")).strip()
    return int(completed.returncode), output


def is_elevated() -> bool:
    """判断当前进程是否具有管理员权限（用于解释「拒绝访问」类失败）。"""
    code, _output = run_command(["net", "session"])
    return code == 0


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    """判断本机端口是否处于监听/可连接状态。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((host, port)) == 0


def open_ports() -> list[int]:
    """返回当前仍在监听的受管端口。"""
    return [port for port in WATCHED_PORTS if port_open(port)]


def listening_pids(port: int) -> set[int]:
    """从 netstat 结果中取出监听指定端口的 PID 集合。"""
    code, output = run_command(["netstat", "-ano", "-p", "TCP"])
    if code != 0 and not output:
        return set()
    pids: set[int] = set()
    suffix = f":{port}"
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if not parts[1].endswith(suffix):
            continue
        if parts[3].upper() != "LISTENING":
            continue
        if parts[4].isdigit():
            pids.add(int(parts[4]))
    return pids


def process_name(pid: int) -> str | None:
    """查询进程名；进程不存在时返回 None。"""
    code, output = run_command(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
    if code != 0 or not output:
        return None
    first_line = output.splitlines()[0].strip()
    if not first_line.startswith('"'):
        return None
    return first_line.split('"')[1]


def read_pid_file(path: Path) -> int | None:
    """读取 pid 文件内容。"""
    if not path.is_file():
        return None
    raw = path.read_text(encoding="ascii", errors="ignore").strip()
    return int(raw) if raw.isdigit() else None


def kill_tree(pid: int) -> tuple[bool, str]:
    """结束进程及其子进程树。"""
    code, output = run_command(["taskkill", "/PID", str(pid), "/T", "/F"])
    return code == 0, output


def collect_targets() -> tuple[list[dict], list[str]]:
    """汇总需要结束的进程，返回 (目标列表, 提示信息)。"""
    targets: dict[int, dict] = {}
    notes: list[str] = []

    for pid_file, label in PID_FILES:
        pid = read_pid_file(pid_file)
        if pid is None:
            continue
        name = process_name(pid)
        if name is None:
            notes.append(f"{label} 的 pid 文件是陈旧的（PID {pid} 已不存在），稍后清理。")
            continue
        targets.setdefault(pid, {"pid": pid, "name": name, "sources": []})
        targets[pid]["sources"].append(f"{label} pid 文件")

    for port in WATCHED_PORTS:
        for pid in sorted(listening_pids(port)):
            name = process_name(pid) or "unknown"
            targets.setdefault(pid, {"pid": pid, "name": name, "sources": []})
            targets[pid]["sources"].append(f"监听 {port}（{PORT_ROLES.get(port, '')}）")

    for target in targets.values():
        target["sources"] = sorted(set(target["sources"]))

    return sorted(targets.values(), key=lambda item: item["pid"]), notes


def kill_wechat() -> list[dict]:
    """结束微信小程序宿主进程，用于清除内存中的 Frida hook。"""
    killed: list[dict] = []
    for name in WECHAT_PROCESS_NAMES:
        code, output = run_command(["taskkill", "/IM", name, "/T", "/F"])
        if code == 0:
            killed.append({"name": name, "output": output.strip()})
    return killed


def wait_ports_closed(timeout_seconds: float = 15.0) -> list[int]:
    """等待端口释放，返回超时后仍在监听的端口。"""
    deadline = time.time() + timeout_seconds
    remaining = open_ports()
    while remaining and time.time() < deadline:
        time.sleep(0.4)
        remaining = open_ports()
    return remaining


def remove_pid_files() -> list[str]:
    """删除已知的 pid 文件。"""
    removed: list[str] = []
    for pid_file, _label in PID_FILES:
        try:
            pid_file.unlink()
            removed.append(str(pid_file))
        except FileNotFoundError:
            continue
        except OSError as exc:
            warn(f"删除 pid 文件失败：{pid_file}（{exc}）")
    return removed


def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="Stop the packaged WMP workflow and free its ports.")
    parser.add_argument("--dry-run", action="store_true", help="只列出将要结束的进程，不实际执行")
    # .bat 会把命令行原样透传过来，`--no-elevate` 是 bat 层的开关（决定要不要弹 UAC），
    # Python 侧不需要处理；但必须接受，否则 argparse 会直接报
    # "unrecognized arguments: --no-elevate" 退出 —— 文档里的 --no-elevate 用法就废了。
    parser.add_argument("--no-elevate", action="store_true", help="（由 .bat 处理，Python 侧忽略；仅为参数透传兼容）")
    # `05-一键停止.bat` 提权重启时会把 `--elevated` 一起透传下来，用来告诉 bat 那一轮
    # 不要再提权（防止反复弹 UAC）。Python 侧同样只做兼容，不处理。
    parser.add_argument("--elevated", action="store_true", help="（由 .bat 处理，Python 侧忽略；仅为参数透传兼容）")
    parser.add_argument("--kill-wechat", action="store_true", help="同时结束微信小程序宿主进程，清除 Frida 注入态")
    parser.add_argument("--yes", "-y", action="store_true", help="跳过交互确认")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    return parser.parse_args()


def confirm(question: str) -> bool:
    """在终端询问是/否。"""
    try:
        answer = input(f"{question} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def main() -> int:
    """入口：定位并结束调试链路进程，最后校验端口。"""
    args = parse_args()
    report: dict = {"projectRoot": str(PROJECT_ROOT), "ports": {}, "killed": [], "notes": []}

    if not args.json:
        print("=== WMP 一键停止 ===")
        print(f"项目目录: {PROJECT_ROOT}")
        print(f"关注端口: {', '.join(f'{port}（{PORT_ROLES[port]}）' for port in WATCHED_PORTS)}")
        print()

    targets, notes = collect_targets()
    report["targets"] = targets
    report["notes"].extend(notes)

    for note in notes:
        if not args.json:
            warn(note)

    if not targets:
        if not args.json:
            ok("没有发现本工具链的残留进程。")
    else:
        if not args.json:
            print("将要结束以下进程：")
            for target in targets:
                print(f"  - PID {target['pid']:<8} {target['name']:<16} 来源: {', '.join(target['sources'])}")
            print()

        unsafe = [item for item in targets if item["name"].lower() not in ALLOWED_PROCESS_NAMES]
        if unsafe:
            for item in unsafe:
                warn(f"PID {item['pid']} 的进程名 {item['name']} 不在预期白名单内，已跳过。")
            targets = [item for item in targets if item["name"].lower() in ALLOWED_PROCESS_NAMES]
            report["targets"] = targets
            report["notes"].append("存在不在白名单内的监听进程，已跳过，请自行确认。")

        if args.dry_run:
            if not args.json:
                info("--dry-run：未执行任何结束操作。")
            report["ports"] = {str(port): ("open" if port_open(port) else "closed") for port in WATCHED_PORTS}
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0

        if not args.yes and sys.stdin.isatty() and not confirm(f"确认结束以上 {len(targets)} 个进程？"):
            warn("已取消。")
            return 1

        denied: list[dict] = []
        for target in targets:
            success, output = kill_tree(target["pid"])
            entry = {"pid": target["pid"], "name": target["name"], "ok": success, "output": output.strip()}
            report["killed"].append(entry)
            if not success and ("拒绝访问" in output or "Access is denied" in output):
                denied.append(entry)
            if args.json:
                continue
            if success:
                ok(f"已结束 PID {target['pid']}（{target['name']}）")
            else:
                warn(f"结束 PID {target['pid']} 失败：{output.strip()}")

        if denied:
            report["needsAdmin"] = [item["pid"] for item in denied]
            report["elevated"] = is_elevated()
            if not args.json:
                print()
                warn(f"有 {len(denied)} 个进程因权限不足无法结束（它们是提权运行的注入器）：")
                for item in denied:
                    print(f"       PID {item['pid']}  {item['name']}")
                info("端口已经释放，调试链路可用；但注入器进程还活着。")
                info("要彻底清干净，请用管理员身份重跑：右键 `05-一键停止.bat` → 以管理员身份运行，")
                info("或先关掉再打开小程序（hook 会随进程重建失效）。")

    if args.kill_wechat:
        if not args.json:
            print()
            warn("--kill-wechat：将结束微信小程序宿主进程，小程序窗口会关闭。")
        if args.yes or args.dry_run or not sys.stdin.isatty() or confirm("确认结束微信进程？"):
            killed_wechat = kill_wechat()
            report["wechatKilled"] = killed_wechat
            if not args.json:
                if killed_wechat:
                    for item in killed_wechat:
                        ok(f"已结束 {item['name']}")
                else:
                    warn("没有找到正在运行的微信进程（或结束失败）。")
        elif not args.json:
            warn("已跳过微信进程。")

    if not args.dry_run:
        remaining = wait_ports_closed()
        remove_pid_files()

        report["ports"] = {str(port): ("open" if port_open(port) else "closed") for port in WATCHED_PORTS}
        if not args.json:
            print()
            print("=== 端口状态 ===")
            for port in WATCHED_PORTS:
                state = "仍在监听" if port_open(port) else "已释放"
                flag = "[WARN]" if port_open(port) else "[OK]"
                print(f"{flag} {port}（{PORT_ROLES[port]}）: {state}")

            if remaining:
                print()
                warn(f"以下端口仍在监听：{', '.join(str(p) for p in remaining)}")
                info("可能被代理 / 抓包工具或其他程序占用，可用 `netstat -ano | findstr \"9421 62000 49999\"` 自查。")
            else:
                print()
                ok("调试链路已关闭，三个端口全部释放。")

            print()
            if not args.kill_wechat:
                info("提示：Frida 的 hook 仍留在微信小程序进程内存里。")
                info("      要彻底回到未注入状态，请重开小程序，或下次运行 `05-一键停止.bat --kill-wechat`。")
    else:
        report["ports"] = {str(port): ("open" if port_open(port) else "closed") for port in WATCHED_PORTS}

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""One-click launcher for the packaged WMP workflow."""

from __future__ import annotations

import argparse
import csv
import re
import sys
import time
from pathlib import Path
import subprocess

import project_doctor as doctor

PROJECT_ROOT = Path(__file__).resolve().parents[1]  # scripts/ 的上一级才是项目根
LOG_DIR = PROJECT_ROOT / "logs"
ENGINE_LOG = LOG_DIR / "start-engine.log"
ENGINE_PID = LOG_DIR / "start-engine.pid"
MCP_LOG = LOG_DIR / "start-mcp-server.log"
MCP_PID = LOG_DIR / "start-mcp-server.pid"
ADMIN_LOG = doctor.WMPF_DEBUGGER_DIR / "logs" / "wmpfdebugger-admin.log"
ADMIN_PID = doctor.WMPF_DEBUGGER_DIR / "logs" / "wmpfdebugger-admin.pid"
SYNC_SCRIPT = PROJECT_ROOT / "偏移提取工具" / "sync_latest_wmpf_offsets.py"
ENGINE_SCRIPT = doctor.E0E1_WX_DIR / "start_engine.py"
MCP_SCRIPT = doctor.E0E1_WX_DIR / "start_mcp_server.py"
SUCCESS_MARKERS = (
    "script loaded, WMPF version:",
    "Frida script loaded, keeping process alive...",
)
FAIL_MARKERS = (
    "Unable to access process",
    "WMPFDebugger exited with an error",
    "Traceback",
    "Error:",
)

sys.path.insert(0, str(doctor.E0E1_WX_DIR))
from package.mcp_control.config import McpServerConfig  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def info(message: str) -> None:
    print(f"[INFO] {message}")


def ok(message: str) -> None:
    print(f"[OK] {message}")


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def fail(message: str) -> int:
    print(f"[FAIL] {message}")
    return 1


def read_pid_file(path: Path) -> int | None:
    if not path.is_file():
        return None
    raw = path.read_text(encoding="ascii", errors="ignore").strip()
    if not raw.isdigit():
        return None
    return int(raw)


def write_pid_file(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{pid}\n", encoding="ascii")


def remove_stale_pid_file(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def process_alive(pid: int) -> bool:
    command = f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p) {{ 'alive' }}"
    code, output = doctor.run_command(["powershell.exe", "-NoProfile", "-Command", command])
    return code == 0 and "alive" in output


def count_processes(name: str) -> int:
    command = (
        f"$items = Get-Process -Name '{name}' -ErrorAction SilentlyContinue; "
        "if ($items) { ($items | Measure-Object).Count } else { 0 }"
    )
    code, output = doctor.run_command(["powershell.exe", "-NoProfile", "-Command", command])
    if code != 0 or not output.strip():
        return 0
    try:
        return int(output.strip().splitlines()[-1])
    except ValueError:
        return 0


def read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    return text.replace("\x00", "").lstrip("\ufeff")


def tail_text(path: Path, limit: int = 20) -> str:
    text = read_text(path).splitlines()
    return "\n".join(text[-limit:])


def log_contains_any(path: Path, markers: tuple[str, ...]) -> bool:
    text = read_text(path)
    return any(marker in text for marker in markers)


def admin_log_looks_recent(max_age_hours: int = 6) -> bool:
    """历史注入日志「看起来较新」。

    ⚠️ **这只说明「过去某个时刻注入成功过」，不代表现在还有注入。**
    微信重启小程序会重建整棵 `WeChatAppEx` 进程树、旧注入随之失效，而日志的 mtime 不会变。
    所以它**只能用于诊断信息**，不能单独作为「已注入，可以跳过」的依据
    （2026-09-22 的事故就是这么来的，见 `ensure_wmpfdebugger` 的注释）。
    """
    if not ADMIN_LOG.is_file():
        return False
    age_seconds = time.time() - ADMIN_LOG.stat().st_mtime
    if age_seconds > max_age_hours * 3600:
        return False
    return log_contains_any(ADMIN_LOG, SUCCESS_MARKERS)


# WMPFDebugger 的进程特征：两个启动脚本（`launch-wmpfdebugger.bat` /
# `launch-wmpfdebugger-admin.ps1`）都是 `node -r ts-node/register src/index.ts`。
# 注意脚本会先 `cd` 进组件目录、用相对路径，所以**命令行里不会出现 `WMPFDebugger` 这个词** ——
# 这就是「只数 node 进程个数」识别不出来的根本原因。
WMPFDEBUGGER_CMD_RE = re.compile(r"ts-node[\\/]register|src[\\/]index\.ts|WMPFDebugger", re.I)


def list_node_processes() -> list[dict[str, str]]:
    """列出所有 `node.exe` 的 pid / 可执行路径 / **命令行**。

    一定要取命令行：只按进程名数 node 是数不出 WMPFDebugger 的（见上面的说明）。
    返回空列表表示「查不到」（比如 PowerShell 不可用），调用方应把它当作「无法确认」，
    而不是「确认没有」——但两者的处置都是「继续启动」，所以不影响正确性。
    """
    command = (
        "$items = Get-CimInstance Win32_Process -Filter \"name='node.exe'\"; "
        "if ($items) { $items | ForEach-Object { "
        "\"$($_.ProcessId)`t$($_.ExecutablePath)`t$($_.CommandLine)\" } }"
    )
    code, output = doctor.run_command(["powershell.exe", "-NoProfile", "-Command", command])
    if code != 0 or not output.strip():
        return []
    rows: list[dict[str, str]] = []
    for line in output.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        rows.append(
            {
                "pid": parts[0].strip(),
                "exe": parts[1].strip(),
                "commandLine": "\t".join(parts[2:]).strip(),
            }
        )
    return rows


def wmpfdebugger_processes() -> list[dict[str, str]]:
    """从 node 进程里**尽力**识别 WMPFDebugger（按命令行特征）。**仅用于诊断提示。**

    ⚠️ 有已知盲区：WMPFDebugger 是由提权助手启动的（`-Verb RunAs`），
    非提权的 PowerShell 通过 CIM 查它时 `ExecutablePath` 与 `CommandLine` **都是空的**
    （2026-09-23 实测：提权实例 pid 20700 在 CIM 里两个字段都空），因此这里**匹配不到它**。
    所以**绝不能拿它当「注入是否活着」的判据** —— 判据请用 `wechatappex_frida_injected()`。
    保留它只是为了在「命令行可读」的场景（比如用户手工用 `launch-wmpfdebugger.bat` 启动）多给一条线索。
    """
    return [
        item
        for item in list_node_processes()
        if WMPFDEBUGGER_CMD_RE.search(item.get("commandLine") or "")
    ]


def _frida_pids_from_tasklist_csv(text: str) -> list[str]:
    """从 `tasklist /m /FO CSV` 的输出里挑出模块列表含 frida 的进程 pid。

    单独抽成纯函数是为了能拿**真机原始输出**做离线断言（见 `verify_start_gate.py`）。
    """
    pids: list[str] = []
    for row in csv.reader((text or "").splitlines()):
        if len(row) < 3:
            continue
        if "frida" in row[2].lower():
            pids.append(row[1])
    return pids


def wechatappex_frida_injected() -> tuple[bool, list[str]]:
    """WeChatAppEx 里是否已有实例加载了 frida agent —— 「注入还活着」最直接的证据。

    为什么用模块列表而不是进程名/命令行：
      * `tasklist /m` 是原生命令，**不需要提权**，也不受「提权进程读不到命令行」影响；
      * 实测（2026-09-23）注入成功时**只有被 hook 的那一个** WeChatAppEx 多出 `frida-agent.dll`，
        且 pid 与 admin 日志里 `[frida] script loaded ... pid: <pid>` **完全对应**；
        另外 11 个 WeChatAppEx、以及 `Weixin.exe` / `node.exe` 全部没有 —— 无假阳性。
      * 注入失效时（微信重启小程序重建进程树）这个模块会随之消失，
        正是我们要检测的「日志看着成功、其实已经失效」的状态。

    取不到结果（命令失败/超时）时返回 `(False, [])` —— **刻意 fail-open 到「去注入」**：
    多弹一次 UAC 的代价，远小于「误判已注入 → 什么都不做 → DevTools 一片空白」。
    """
    try:
        proc = subprocess.run(
            ["tasklist", "/m", "/fi", "imagename eq WeChatAppEx.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="gbk",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return False, []
    pids = _frida_pids_from_tasklist_csv(proc.stdout or "")
    return bool(pids), pids


def launch_hidden_python(script_path: Path, cwd: Path, log_path: Path, pid_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # 注意：不要用 `with open(...)` 包住 Popen。重试时若第一次 CreateProcess 失败，
    # subprocess 会清理它复制的句柄；文件对象必须在所有尝试结束后才关闭。
    log_file = log_path.open("a", encoding="utf-8")
    log_file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] launching {script_path.name}\n")
    log_file.flush()

    # 让引擎 / MCP 真正脱离父 shell：否则 02 所在的后台任务一退出，
    # 同进程组 / 同一 Job Object 的子进程会被一起收掉，表现是
    # 「02 显示全 OK、几十秒后 9421/62000/49999 全部消失」。
    # DETACHED_PROCESS 与 CREATE_NO_WINDOW 组合在某些 Job 下会失败，故逐级回退。
    base_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    detach_flag = getattr(subprocess, "DETACHED_PROCESS", 0)
    breakaway_flag = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)

    def _spawn(flags):
        return subprocess.Popen(
            [sys.executable, str(script_path)],
            cwd=str(cwd),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )

    process = None
    try:
        for flags in (base_flags | detach_flag | breakaway_flag,
                      base_flags | breakaway_flag,
                      base_flags | detach_flag,
                      base_flags):
            try:
                process = _spawn(flags)
                break
            except OSError:
                continue
    finally:
        # 子进程已继承自己的句柄副本，父进程可以安全关闭。
        log_file.close()
    if process is None:
        raise RuntimeError("无法启动后台 python 进程")
    write_pid_file(pid_path, process.pid)
    return int(process.pid)


def wait_for_ports(ports: tuple[int, ...], timeout_seconds: int) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if all(doctor.port_open(port) for port in ports):
            return True
        time.sleep(1)
    return all(doctor.port_open(port) for port in ports)


def ensure_preflight(auto_sync: bool) -> bool:
    print("=== 一键启动前检查 ===")
    results = [
        doctor.check_python(),
        doctor.check_system_node(),
        doctor.check_wmpfdebugger_node(),
        doctor.check_npm_command(),
        doctor.check_wmpfdebugger_deps(),
        doctor.check_python_modules("e0e1-wx Python 依赖", ["frida", "PySide6", "qasync", "websockets", "httpx", "mcp"]),
        doctor.check_wmpf_installation(),
    ]

    for result in results:
        doctor.print_result(result)

    hard_fail = any(item.status == "fail" for item in results)
    no_runtime = any(item.title == "本机 WMPF 运行时" and item.status != "ok" for item in results)
    if hard_fail or no_runtime:
        print()
        doctor.print_next_steps(results)
        return False

    offset_result = doctor.check_offset_sync()
    doctor.print_result(offset_result)
    if offset_result.status == "ok":
        return True

    if offset_result.status == "warn":
        print()
        warn("当前无法自动核对偏移配置，请先确认本机已经安装并打开过微信小程序。")
        return False

    extractor_result = doctor.check_python_modules("偏移提取工具 Python 依赖", ["pefile", "capstone"])
    doctor.print_result(extractor_result)
    if extractor_result.status != "ok":
        print()
        warn("偏移配置缺失，但偏移提取工具依赖还没装好。")
        return False

    if not auto_sync:
        print()
        warn("检测到偏移配置未同步，请先运行 `04-自动更新.bat`。")
        return False

    print()
    info("检测到偏移配置未同步，正在自动执行最新版本同步...")
    code, output = doctor.run_command([sys.executable, str(SYNC_SCRIPT), "--force"], cwd=PROJECT_ROOT)
    if output:
        print(output)
    if code != 0:
        print()
        warn("自动同步偏移失败，请手动运行 `04-自动更新.bat`。")
        return False

    offset_result = doctor.check_offset_sync()
    doctor.print_result(offset_result)
    return offset_result.status == "ok"


def ensure_wmpfdebugger(skip: bool) -> bool:
    print("\n=== Step 1/3: WMPFDebugger 注入 ===")
    if skip:
        warn("已按参数跳过 WMPFDebugger 启动。")
        return True

    existing_pid = read_pid_file(ADMIN_PID)
    if existing_pid is not None:
        if process_alive(existing_pid):
            ok(f"WMPFDebugger 已在运行（PID {existing_pid}）。")
            return True
        remove_stale_pid_file(ADMIN_PID)

    # 第二个判据：**必须能确认「注入现在还活着」**，才允许跳过。
    #
    # ⚠️ 旧实现是 `admin_log_looks_recent() and count_processes("node") > 0`，两个条件都会误命中：
    #   * `admin_log_looks_recent()` 只看「历史上曾经注入成功过」（日志 mtime < 6h），
    #     **不代表现在还有注入** —— 微信重启小程序会重建 WeChatAppEx 进程树、旧注入随之失效；
    #   * `count_processes("node")` 数的是**任意** node 进程 —— 机器上只要还跑着别的 Node 程序就会命中
    #     （实测命中的是 WorkBuddy 自己的两个 MCP 插件服务）。
    # 两者叠加的后果：`02` 打印「先跳过重复启动」然后**什么都不做** —— WMPFDebugger 根本没被拉起，
    # 于是没有 Frida 注入 → 小程序不会回连 9421 → 62000 后面没有会话 → DevTools 一片空白。
    # 2026-09-23 实测踩到并定位：12 个 `WeChatAppEx.exe` 全部未加载 frida 模块、系统里没有 WMPFDebugger 进程，
    # 而 `02` 每次都报「已跳过」。
    injected, frida_pids = wechatappex_frida_injected()
    if injected:
        ok(f"检测到 WeChatAppEx 已加载 frida 注入（PID {', '.join(frida_pids)}），跳过重复启动。")
        return True

    # 只看「命令行可读的 WMPFDebugger 进程」给一条额外提示 —— 它看不见提权实例（见该函数说明），
    # 所以这里只是提示，不参与决策。
    stray = wmpfdebugger_processes()
    if stray:
        warn(
            "检测到 WMPFDebugger 进程仍在运行（PID "
            + ", ".join(str(item.get("pid")) for item in stray)
            + "），但**没有任何 WeChatAppEx 加载 frida** —— 注入很可能已失效。"
            "仍将重新注入；若出现冲突，先跑 `05-一键停止.bat`。"
        )
    info(
        "没有任何 WeChatAppEx 加载 frida → 继续执行注入"
        f"（机器上共 {count_processes('node')} 个 node 进程；"
        f"历史注入日志{'看起来较新但已失效' if admin_log_looks_recent() else '已过期'}）。"
        "说明：这两项**不再**作为跳过依据。"
    )

    before_mtime = ADMIN_LOG.stat().st_mtime if ADMIN_LOG.is_file() else 0.0
    helper = doctor.WMPF_DEBUGGER_DIR / "launch-wmpfdebugger-admin.ps1"
    code, output = doctor.run_command(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(helper)],
        cwd=doctor.WMPF_DEBUGGER_DIR,
    )
    if output:
        print(output)
    if code != 0:
        warn("启动管理员注入助手时返回了非 0 状态，请检查 UAC 弹窗和日志。")

    deadline = time.time() + 90
    saw_fresh_activity = False
    while time.time() < deadline:
        current_pid = read_pid_file(ADMIN_PID)
        if current_pid is not None and process_alive(current_pid):
            saw_fresh_activity = True

        if ADMIN_LOG.is_file() and ADMIN_LOG.stat().st_mtime > before_mtime:
            saw_fresh_activity = True

        if saw_fresh_activity and log_contains_any(ADMIN_LOG, SUCCESS_MARKERS):
            ok(f"WMPFDebugger 注入完成，日志：{ADMIN_LOG}")
            return True

        if saw_fresh_activity and log_contains_any(ADMIN_LOG, FAIL_MARKERS):
            warn("WMPFDebugger 日志中出现失败信号：")
            print(tail_text(ADMIN_LOG))
            return False

        time.sleep(1)

    warn("等待 WMPFDebugger 注入超时。请确认你已经接受 UAC 弹窗。")
    if ADMIN_LOG.is_file():
        print(tail_text(ADMIN_LOG))
    return False


def ensure_engine(skip: bool) -> bool:
    print("\n=== Step 2/3: 启动调试引擎 ===")
    if skip:
        warn("已按参数跳过调试引擎启动。")
        return True

    debug_open = doctor.port_open(9421)
    proxy_open = doctor.port_open(62000)
    if debug_open and proxy_open:
        ok("调试引擎已在运行（9421 / 62000 已监听）。")
        return True
    if debug_open != proxy_open:
        warn("检测到调试引擎端口状态不一致，请先清理旧进程后再试。")
        warn("当前端口状态：9421=%s, 62000=%s" % ("监听" if debug_open else "未监听", "监听" if proxy_open else "未监听"))
        return False

    pid = launch_hidden_python(ENGINE_SCRIPT, doctor.E0E1_WX_DIR, ENGINE_LOG, ENGINE_PID)
    info(f"已在后台启动引擎进程，PID {pid}。")
    if wait_for_ports((9421, 62000), timeout_seconds=30):
        ok(f"调试引擎已就绪，日志：{ENGINE_LOG}")
        return True

    warn("调试引擎未能在预期时间内监听 9421 / 62000。")
    print(tail_text(ENGINE_LOG))
    return False


def ensure_mcp(skip: bool) -> bool:
    print("\n=== Step 3/3: 启动 MCP Server ===")
    if skip:
        warn("已按参数跳过 MCP Server 启动。")
        return True

    if doctor.port_open(49999):
        ok("MCP Server 已在运行（49999 已监听）。")
        return True

    pid = launch_hidden_python(MCP_SCRIPT, doctor.E0E1_WX_DIR, MCP_LOG, MCP_PID)
    info(f"已在后台启动 MCP 进程，PID {pid}。")
    if wait_for_ports((49999,), timeout_seconds=20):
        ok(f"MCP Server 已就绪，日志：{MCP_LOG}")
        return True

    warn("MCP Server 未能在预期时间内监听 49999。")
    print(tail_text(MCP_LOG))
    return False


def describe_log_path(path: Path) -> str:
    if path.is_file():
        return str(path)
    return f"{path}（当前服务不是由一键启动器拉起，暂未生成此日志）"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="One-click start the packaged WMP workflow.")
    parser.add_argument("--skip-wmpf", action="store_true", help="Skip launching WMPFDebugger")
    parser.add_argument("--skip-engine", action="store_true", help="Skip launching the debug engine")
    parser.add_argument("--skip-mcp", action="store_true", help="Skip launching the MCP server")
    parser.add_argument("--no-auto-sync", action="store_true", help="Do not auto-sync offsets when mismatch is detected")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print("=== WMP 一键启动 ===")
    print(f"项目目录: {PROJECT_ROOT}")
    print()

    if not ensure_preflight(auto_sync=not args.no_auto_sync):
        return fail("环境尚未准备好，请先根据提示补齐。")

    if not ensure_wmpfdebugger(skip=args.skip_wmpf):
        return fail("WMPFDebugger 注入未成功。")

    if not ensure_engine(skip=args.skip_engine):
        return fail("调试引擎未成功启动。")

    if not ensure_mcp(skip=args.skip_mcp):
        return fail("MCP Server 未成功启动。")

    config = McpServerConfig()
    commands = config.install_commands()

    print("\n=== 已就绪 ===")
    ok("整条链路已经拉起完成。")
    print("如果小程序是在本脚本运行前就打开的，请现在把它关掉后重新打开一次。")
    print(f"MCP 地址: {config.endpoint_url()}")
    print("")
    print("=== 接入任意 MCP 客户端（把下面这段贴进它的配置文件即可）===")
    print(commands["json"])
    print("=== 或使用 CLI 命令 ===")
    print(f"Codex:  {commands['codex']}")
    print(f"Claude: {commands['claude']}")
    print(f"WMPFDebugger 日志: {describe_log_path(ADMIN_LOG)}")
    print(f"引擎日志: {describe_log_path(ENGINE_LOG)}")
    print(f"MCP 日志: {describe_log_path(MCP_LOG)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

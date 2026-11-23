#!/usr/bin/env python3
"""Project preflight checks for the packaged WMP mini-program workflow."""

from __future__ import annotations

import codecs
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]  # scripts/ 的上一级才是项目根
WMPF_DEBUGGER_DIR = PROJECT_ROOT / "WMPFDebugger"
E0E1_WX_DIR = PROJECT_ROOT / "e0e1-wx"
def _safe_home() -> Path | None:
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return None


def wmpf_root_candidates() -> list[Path]:
    """列出所有可能的 RadiumWMPF 根目录。

    APPDATA 并非总是存在（部分 shell / 服务环境会把它剥掉），所以这里同时用
    LOCALAPPDATA 的兄弟目录、USERPROFILE 与 Path.home() 兜底；WMPF_ROOT 可直接覆盖。
    """
    override = os.environ.get("WMPF_ROOT")
    if override:
        return [Path(override)]

    bases: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        bases.append(Path(appdata))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        # LOCALAPPDATA 是 ...\AppData\Local，Roaming 是它的兄弟目录
        bases.append(Path(local).parent / "Roaming")
    for home in (os.environ.get("USERPROFILE"), _safe_home()):
        if home:
            bases.append(Path(home) / "AppData" / "Roaming")

    subpath = Path("Tencent") / "xwechat" / "xplugin" / "Plugins" / "RadiumWMPF"
    seen: set[str] = set()
    roots: list[Path] = []
    for base in bases:
        root = base / subpath
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            roots.append(root)
    return roots


WMPF_ROOT_CANDIDATES = wmpf_root_candidates()
# 展示用的代表路径：优先取实际存在的那个
WMPF_ROOT = next(
    (root for root in WMPF_ROOT_CANDIDATES if root.is_dir()),
    WMPF_ROOT_CANDIDATES[0],
)
NODE20_ENV_VAR = "WMPF_NODE20_DIR"

# 编码体检时跳过的目录：都不是需要双击的入口脚本，且体积大
SCRIPT_SCAN_SKIP_DIRS = {"node_modules", "__pycache__", ".git", ".venv", "venv", "dist", "logs"}

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

LAST_WMPF_DETECT_ERROR = ""


@dataclass(slots=True)
class CheckResult:
    status: str
    title: str
    details: str


def run_command(args: list[str], cwd: Path | None = None) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError:
        return 127, ""
    output = (completed.stdout or completed.stderr or "").strip()
    return int(completed.returncode), output


def parse_node_major(version_text: str) -> int | None:
    match = re.search(r"v(\d+)", version_text)
    return int(match.group(1)) if match else None


def node_home_from_candidates() -> Path | None:
    """取 WMPFDebugger 要用的 Node 20 目录；取不到返回 None。

    查找顺序：
      1. 环境变量 `WMPF_NODE20_DIR`（由根目录 `01-安装依赖.bat` 写入，指向本项目
         自动下载的 Node 20）；
      2. 本项目内的 `.runtime\\node20`（兜底）。

    为什么要兜底：环境变量是**进程启动时快照**。如果项目目录被改名/移动过，
    registry 里已经是新路径，但**早于改动就已打开的窗口**（资源管理器、终端）
    里仍是旧值 → 只认环境变量就会误判「没有专用 Node」，
    进而回落到系统 Node（常见 v22）→ 报 FAIL。项目内路径不会骗人，所以拿它兜底。
    """
    raw_env = str(os.environ.get(NODE20_ENV_VAR, "")).strip()
    if raw_env:
        candidate = Path(raw_env).expanduser()
        if (candidate / "node.exe").is_file():
            return candidate

    local = PROJECT_ROOT / ".runtime" / "node20"
    if (local / "node.exe").is_file():
        return local
    return None


def node_executable(home: Path | None) -> Path | None:
    if home is None:
        return None
    candidate = home / "node.exe"
    return candidate if candidate.is_file() else None


def npm_executable(home: Path | None) -> Path | None:
    if home is None:
        return None
    candidate = home / "npm.cmd"
    return candidate if candidate.is_file() else None


def check_python() -> CheckResult:
    version = sys.version_info
    text = f"Python {version.major}.{version.minor}.{version.micro}"
    # 顺带报出解释器位置：02~05 现在经 scripts\find-python.bat 显式定位项目 Python，
    # 不再依赖 PATH。这里把「体检实际用的是哪个解释器」写出来，出问题时一眼可辨。
    exe = sys.executable or ""
    if version >= (3, 10):
        return CheckResult("ok", "Python", f"{text}\n       {exe}" if exe else text)
    return CheckResult("fail", "Python", f"{text}，需要 Python 3.10 或更高版本" + (f"\n       {exe}" if exe else ""))


def check_system_node() -> CheckResult:
    code, output = run_command(["node", "-v"])
    if code != 0 or not output:
        return CheckResult("warn", "系统 Node.js", "未检测到系统 node，可忽略；只要 WMPFDebugger 有专用 Node 20 即可")

    major = parse_node_major(output)
    if major == 20:
        return CheckResult("ok", "系统 Node.js", f"检测到 {output}")
    if major is None:
        return CheckResult("warn", "系统 Node.js", f"检测到 {output}，但无法解析主版本号")
    return CheckResult("warn", "系统 Node.js", f"检测到 {output}，当前打包版不建议用它来跑 WMPFDebugger")


def check_wmpfdebugger_node() -> CheckResult:
    home = node_home_from_candidates()
    preferred_node = node_executable(home)
    if preferred_node is not None:
        code, output = run_command([str(preferred_node), "-v"])
        if code == 0 and parse_node_major(output) == 20:
            return CheckResult(
                "ok",
                "WMPFDebugger Node 运行时",
                f"将使用专用 Node 20：{output}（{preferred_node}）",
            )
        return CheckResult(
            "fail",
            "WMPFDebugger Node 运行时",
            f"发现了专用 Node 路径，但版本异常：{preferred_node}",
        )

    code, output = run_command(["node", "-v"])
    if code != 0 or not output:
        return CheckResult(
            "fail",
            "WMPFDebugger Node 运行时",
            "未找到可供 WMPFDebugger 使用的 Node。请安装 Node.js 20.x，或设置 WMPF_NODE20_DIR。",
        )

    major = parse_node_major(output)
    if major == 20:
        return CheckResult("ok", "WMPFDebugger Node 运行时", f"将直接使用系统 Node：{output}")
    return CheckResult(
        "fail",
        "WMPFDebugger Node 运行时",
        f"当前只检测到 {output}。这套打包版固定使用 frida@16.6.6，需要 Node 20.x。",
    )


def check_npm_command() -> CheckResult:
    preferred_npm = npm_executable(node_home_from_candidates())
    if preferred_npm is not None:
        code, output = run_command([str(preferred_npm), "-v"])
        if code == 0 and output:
            return CheckResult("ok", "WMPFDebugger npm", f"检测到专用 npm.cmd：{output}（{preferred_npm}）")

    code, output = run_command(["npm.cmd", "-v"])
    if code == 0 and output:
        return CheckResult("ok", "WMPFDebugger npm", f"检测到系统 npm.cmd：{output}")
    return CheckResult(
        "warn",
        "WMPFDebugger npm",
        "未检测到可用的 npm.cmd。如果你有专用 Node 20，请设置 WMPF_NODE20_DIR。",
    )


def check_wmpfdebugger_deps() -> CheckResult:
    ts_node = WMPF_DEBUGGER_DIR / "node_modules" / "ts-node" / "register" / "index.js"
    frida_dir = WMPF_DEBUGGER_DIR / "node_modules" / "frida"
    missing: list[str] = []
    if not ts_node.exists():
        missing.append("ts-node")
    if not frida_dir.exists():
        missing.append("frida")
    if not missing:
        return CheckResult("ok", "WMPFDebugger 依赖", "本地 node_modules 已准备完成")
    return CheckResult(
        "fail",
        "WMPFDebugger 依赖",
        f"缺少 {', '.join(missing)}。请运行根目录的 `01-安装依赖.bat`。",
    )


def module_exists(module_name: str) -> bool:
    code = (
        "import importlib.util, sys; "
        f"sys.exit(0 if importlib.util.find_spec('{module_name}') else 1)"
    )
    return subprocess.run([sys.executable, "-c", code], check=False).returncode == 0


def check_python_modules(title: str, modules: Iterable[str]) -> CheckResult:
    missing = [name for name in modules if not module_exists(name)]
    if not missing:
        return CheckResult("ok", title, "当前 Python 环境依赖齐全")
    return CheckResult(
        "fail",
        title,
        f"缺少 {', '.join(missing)}。请使用当前 Python 运行对应目录下的 requirements.txt。",
    )


def detect_latest_wmpf() -> tuple[int, Path] | None:
    global LAST_WMPF_DETECT_ERROR
    LAST_WMPF_DETECT_ERROR = ""
    candidates: list[tuple[int, Path]] = []
    denied: list[str] = []
    failed: list[str] = []
    for root in WMPF_ROOT_CANDIDATES:
        try:
            if not root.is_dir():
                continue
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                try:
                    version = int(child.name)
                except ValueError:
                    continue
                dll_path = child / "extracted" / "runtime" / "flue.dll"
                if dll_path.is_file():
                    candidates.append((version, dll_path))
        except PermissionError:
            denied.append(str(root))
        except OSError as exc:
            failed.append(f"{root}: {exc}")

    if candidates:
        return max(candidates, key=lambda item: item[0])
    if denied:
        LAST_WMPF_DETECT_ERROR = (
            f"访问 {', '.join(denied)} 被拒绝。请用普通桌面环境直接运行，"
            "或手动执行 `04-自动更新.bat`。"
        )
    elif failed:
        LAST_WMPF_DETECT_ERROR = "读取 WMPF 目录失败：" + "; ".join(failed)
    return None


def check_wmpf_installation() -> CheckResult:
    detected = detect_latest_wmpf()
    if detected is None:
        if LAST_WMPF_DETECT_ERROR:
            return CheckResult("warn", "本机 WMPF 运行时", LAST_WMPF_DETECT_ERROR)
        tried = "\n".join(f"  - {root}" for root in WMPF_ROOT_CANDIDATES)
        return CheckResult(
            "warn",
            "本机 WMPF 运行时",
            f"未在以下目录找到可用的 flue.dll：\n{tried}",
        )
    version, dll_path = detected
    return CheckResult("ok", "本机 WMPF 运行时", f"检测到版本 {version}，flue.dll 位于 {dll_path}")


def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def check_offset_sync() -> CheckResult:
    detected = detect_latest_wmpf()
    if detected is None:
        if LAST_WMPF_DETECT_ERROR:
            return CheckResult("warn", "偏移配置同步", LAST_WMPF_DETECT_ERROR)
        return CheckResult("warn", "偏移配置同步", "未检测到本机 WMPF 版本，无法核对 addresses.<version>.json")

    version, _dll_path = detected
    debugger_file = WMPF_DEBUGGER_DIR / "frida" / "config" / f"addresses.{version}.json"
    engine_file = E0E1_WX_DIR / "tools" / "config" / "win" / f"addresses.{version}.json"
    debugger_json = load_json(debugger_file)
    engine_json = load_json(engine_file)

    if debugger_json is None or engine_json is None:
        missing: list[str] = []
        if debugger_json is None:
            missing.append(str(debugger_file))
        if engine_json is None:
            missing.append(str(engine_file))
        return CheckResult(
            "fail",
            "偏移配置同步",
            "缺少最新版本配置文件：\n" + "\n".join(missing) + "\n请运行 `04-自动更新.bat`。",
        )

    if debugger_json != engine_json:
        return CheckResult(
            "fail",
            "偏移配置同步",
            f"最新版本 {version} 的两份配置内容不一致，请运行 `04-自动更新.bat --force`。",
        )

    return CheckResult("ok", "偏移配置同步", f"版本 {version} 的两份 addresses 配置已同步")


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def check_runtime_ports() -> CheckResult:
    statuses = {
        9421: port_open(9421),
        62000: port_open(62000),
        49999: port_open(49999),
    }
    details = []
    for port, opened in statuses.items():
        state = "监听中" if opened else "未监听"
        details.append(f"{port}: {state}")

    if all(not opened for opened in statuses.values()):
        return CheckResult("warn", "运行中端口", "当前没有发现调试服务监听\n" + "\n".join(details))
    return CheckResult("ok", "运行中端口", "\n".join(details))


def iter_entry_scripts() -> list[Path]:
    """列出项目内所有需要双击运行的 .bat / .cmd / .ps1。"""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(PROJECT_ROOT):
        dirnames[:] = [name for name in dirnames if name not in SCRIPT_SCAN_SKIP_DIRS]
        for filename in filenames:
            if Path(filename).suffix.lower() in {".bat", ".cmd", ".ps1"}:
                found.append(Path(dirpath) / filename)
    return sorted(found)


def check_requirements_encoding() -> CheckResult:
    """校验 requirements*.txt 是否为 ASCII —— 非 ASCII 会让 pip 直接崩。

    为什么单独查：pip 读 requirements 文件用的是
    `pip._internal.utils.encoding.auto_decode()`，它按 **BOM → PEP263 编码声明
    → 系统首选编码（简体中文 Windows 上是 GBK）** 的顺序猜编码。

    而本项目是 GBK 环境、requirements 又是 UTF-8，两边一撞就是：

        UnicodeDecodeError: 'gbk' codec can't decode byte 0x8a in position 106

    —— pip 连「要装什么」都没读到就退出了，且**官方源/镜像重试都救不了**
    （问题在本地文件，不在网络）。用户看到的是「Python 依赖安装失败」。

    结论：requirements 文件里**不要写中文**（注释也不行），保持纯 ASCII 最稳。
    想写说明就挪到 .bat 或 README 里。
    """
    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(PROJECT_ROOT):
        dirnames[:] = [name for name in dirnames if name not in SCRIPT_SCAN_SKIP_DIRS]
        for filename in filenames:
            low = filename.lower()
            if low.startswith("requirements") and low.endswith(".txt"):
                candidates.append(Path(dirpath) / filename)

    problems: list[str] = []
    for path in sorted(candidates):
        raw = path.read_bytes()
        try:
            label = str(path.relative_to(PROJECT_ROOT))
        except ValueError:
            label = str(path)
        # 只看正文，BOM 本身也算「非 ASCII」但那是另一种问题，先单独识别
        body = raw[3:] if raw.startswith(codecs.BOM_UTF8) else raw
        bad = [(i, b) for i, b in enumerate(body) if b > 127]
        if bad:
            pos, byte = bad[0]
            problems.append(
                f"{label}：含 {len(bad)} 个非 ASCII 字节（首个在 position {pos}：0x{byte:02x}）"
            )

    if not problems:
        if not candidates:
            return CheckResult("warn", "requirements 编码", "未找到 requirements*.txt")
        return CheckResult(
            "ok",
            "requirements 编码",
            f"{len(candidates)} 个 requirements*.txt 均为纯 ASCII（pip 可正常读取）",
        )
    return CheckResult(
        "fail",
        "requirements 编码",
        "以下文件会让 pip 在读取阶段就崩溃（报 UnicodeDecodeError，与网络无关）：\n"
        + "\n".join(f"  - {item}" for item in problems)
        + "\n修法：把这些文件里的中文（含注释）删掉或改写成英文，保持纯 ASCII。",
    )


def check_script_encodings() -> CheckResult:
    """校验入口脚本的编码与换行 —— 这是「双击后乱码 / 报错」的头号原因。

    cmd.exe 是按**字节偏移**边读边解析 .bat 的，所以：

      - `.bat` 里只要有中文，就必须是 GBK：存成 UTF-8 时中文会变乱码；
      - `.bat` 里只要有中文，就必须是 **CRLF**：LF 换行会让 cmd 在多字节
        字符中间断行，表现为报「'xxx' 不是内部或外部命令」、整段输出被
        **静默吞掉**，严重时甚至死循环（同一个脚本反复重跑）。

    这两种故障都不会给出「编码错误」这类明确提示，所以这里主动体检。
    """
    scripts = iter_entry_scripts()
    problems: list[str] = []

    for path in scripts:
        raw = path.read_bytes()
        try:
            label = str(path.relative_to(PROJECT_ROOT))
        except ValueError:
            label = str(path)

        if path.suffix.lower() == ".ps1":
            if not raw.startswith(codecs.BOM_UTF8):
                problems.append(f"{label}：缺少 UTF-8 BOM（PowerShell 5.1 会按 GBK 解析，中文变乱码）")
            continue

        if raw.startswith(codecs.BOM_UTF8):
            problems.append(f"{label}：带了 UTF-8 BOM（.bat 不要加 BOM）")
        if raw.count(b"\n") != raw.count(b"\r\n"):
            problems.append(f"{label}：存在裸 LF 换行（.bat 必须 CRLF，否则含中文时 cmd 解析错乱）")
        try:
            raw.decode("gbk")
        except UnicodeDecodeError:
            problems.append(f"{label}：不是 GBK 编码（.bat 必须存成 GBK / ANSI）")

    if not problems:
        return CheckResult(
            "ok",
            "批处理 / 脚本编码",
            f"{len(scripts)} 个 .bat / .cmd / .ps1 的编码与换行均正确",
        )
    return CheckResult(
        "fail",
        "批处理 / 脚本编码",
        "以下文件会导致双击后乱码或报错：\n"
        + "\n".join(f"  - {item}" for item in problems)
        + "\n修法：.bat 存成 GBK + CRLF（不要加 chcp 65001），.ps1 存成 UTF-8 with BOM。",
    )


def print_result(result: CheckResult) -> None:
    prefix = {
        "ok": "[OK]",
        "warn": "[WARN]",
        "fail": "[FAIL]",
    }.get(result.status, "[INFO]")
    print(f"{prefix} {result.title}")
    print(f"       {result.details}")


def print_next_steps(results: list[CheckResult]) -> None:
    print("\n建议下一步：")
    runtime_failed = any(item.title == "WMPFDebugger Node 运行时" and item.status == "fail" for item in results)
    deps_failed = any(item.title == "WMPFDebugger 依赖" and item.status == "fail" for item in results)
    offsets_failed = any(item.title == "偏移配置同步" and item.status == "fail" for item in results)
    ports_warn = any(item.title == "运行中端口" and item.status == "warn" for item in results)
    encoding_failed = any(item.title == "批处理 / 脚本编码" and item.status == "fail" for item in results)

    step_index = 1
    if encoding_failed:
        print(f"{step_index}. 先把上面列出的 `.bat` 另存为 GBK + CRLF（`.ps1` 存成 UTF-8 with BOM），否则双击后必然乱码或报错。")
        step_index += 1
    if runtime_failed:
        print(f"{step_index}. 先让 WMPFDebugger 使用 Node 20.x。可以设置 `WMPF_NODE20_DIR`，或复用你原来的专用 Node 20 目录。")
        step_index += 1
    if deps_failed:
        print(f"{step_index}. 运行 `01-安装依赖.bat`，给当前打包版目录安装本地 node_modules。")
        step_index += 1
    if offsets_failed:
        print(f"{step_index}. 运行 `04-自动更新.bat`，把最新微信版本的偏移配置同步到两套运行时。")
        step_index += 1
    if ports_warn and not runtime_failed and not deps_failed:
        print(f"{step_index}. 环境已基本齐备，直接运行 `02-一键启动.bat`。")
        step_index += 1
    if step_index == 1:
        print("1. 当前环境检查通过，可以直接重开小程序并连接 MCP，或按需运行 `02-一键启动.bat`。")


def main() -> int:
    print("=== WMP 项目环境体检 ===")
    print(f"项目目录: {PROJECT_ROOT}\n")

    results = [
        check_python(),
        check_system_node(),
        check_wmpfdebugger_node(),
        check_npm_command(),
        check_wmpfdebugger_deps(),
        check_python_modules("e0e1-wx Python 依赖", ["frida", "PySide6", "qasync", "websockets", "httpx", "mcp"]),
        check_python_modules("偏移提取工具 Python 依赖", ["pefile", "capstone"]),
        check_wmpf_installation(),
        check_offset_sync(),
        check_runtime_ports(),
        check_requirements_encoding(),
        check_script_encodings(),
    ]

    for result in results:
        print_result(result)

    print_next_steps(results)
    return 0 if not any(item.status == "fail" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

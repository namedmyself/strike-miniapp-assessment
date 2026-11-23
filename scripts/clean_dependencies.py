#!/usr/bin/env python3
"""一键清理依赖 + 依赖落点核实。

对应根目录按钮 `06-一键清理依赖.bat`。

它先**核实**依赖到底装在哪，再按范围清理：

  [工具目录内]（默认清理，随工具目录一起消失）
    - WMPFDebugger/node_modules        Node 依赖（frida / ts-node 等）
    - **/.venv                         项目内虚拟环境（如果曾经建过）
    - **/__pycache__                   Python 字节码缓存

  [工具目录外]（默认不动，需要显式开关）
    - npm 缓存        %LOCALAPPDATA%\\npm-cache      --npm-cache
    - pip 缓存        %LOCALAPPDATA%\\pip\\Cache     --pip-cache
    - 全局 Python 包  frida / PySide6 / ...          --python-packages

为什么要有这个区分：`01-安装依赖.bat` 用 `python -m pip install -r ...` 装 Python 依赖，
落点是**当前 Python 环境的 site-packages**（通常是系统 Python），而不是工具目录。
所以「删掉工具目录 = 依赖自动没了」只对 Node 依赖成立，Python 依赖会留在系统里。
"""

from __future__ import annotations

import argparse
import json
import locale
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WMPF_DEBUGGER_DIR = PROJECT_ROOT / "WMPFDebugger"
E0E1_WX_DIR = PROJECT_ROOT / "e0e1-wx"
OFFSET_TOOL_DIR = PROJECT_ROOT / "偏移提取工具"

# 工具目录内、可以直接删掉并由 01-安装依赖.bat 重建的东西
NODE_DEPS = WMPF_DEBUGGER_DIR / "node_modules"
VENV_DIRS = (E0E1_WX_DIR / ".venv", OFFSET_TOOL_DIR / ".venv", PROJECT_ROOT / ".venv")
LOG_DIRS = (PROJECT_ROOT / "logs", WMPF_DEBUGGER_DIR / "logs")

# e0e1-wx / 偏移提取工具 requirements.txt 里的关键包
PYTHON_REQUIRED_PACKAGES = (
    "frida",
    "PySide6",
    "qasync",
    "websockets",
    "httpx",
    "mcp",
    "pefile",
    "capstone",
)

SKIP_DIR_NAMES = {"node_modules", ".git", ".venv", "venv"}

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

    npm / pip 在中文 Windows 上按控制台代码页（cp936）输出，按 UTF-8 解会乱码。
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
    return int(completed.returncode), decode_console((completed.stdout or b"") + (completed.stderr or b"")).strip()


def human_size(num_bytes: int) -> str:
    """把字节数格式化成可读大小。"""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"


def dir_size(path: Path) -> int:
    """递归统计目录大小，忽略无法访问的条目。"""
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def find_pycache_dirs() -> list[Path]:
    """在工具目录内查找所有 __pycache__ 目录（不进入 node_modules）。"""
    found: list[Path] = []
    stack = [PROJECT_ROOT]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    name = entry.name
                    if name == "__pycache__":
                        found.append(Path(entry.path))
                        continue
                    if name in SKIP_DIR_NAMES:
                        continue
                    stack.append(Path(entry.path))
        except OSError:
            continue
    return sorted(found)


def npm_cache_dir() -> Path | None:
    """读取 npm 缓存目录。"""
    code, output = run_command(["npm.cmd", "config", "get", "cache"])
    if code == 0 and output and not output.startswith("npm"):
        candidate = Path(output.splitlines()[-1].strip())
        if candidate.is_dir():
            return candidate
    fallback = Path(os.environ.get("LOCALAPPDATA", "")) / "npm-cache"
    return fallback if fallback.is_dir() else None


def pip_cache_dir() -> Path | None:
    """读取 pip 缓存目录。"""
    code, output = run_command([sys.executable, "-m", "pip", "cache", "dir"])
    if code == 0 and output:
        candidate = Path(output.splitlines()[-1].strip())
        if candidate.is_dir():
            return candidate
    fallback = Path(os.environ.get("LOCALAPPDATA", "")) / "pip" / "Cache"
    return fallback if fallback.is_dir() else None


def python_site_packages() -> list[Path]:
    """列出当前 Python 的 site-packages 目录。"""
    code = (
        "import json,sys,site;"
        "paths=[];"
        "paths.extend(site.getsitepackages());"
        "u=site.getusersitepackages();"
        "paths.append(u) if u else None;"
        "print(json.dumps([p for p in paths]))"
    )
    run_code, output = run_command([sys.executable, "-c", code])
    if run_code != 0 or not output:
        return []
    try:
        return [Path(item) for item in json.loads(output.splitlines()[-1])]
    except Exception:
        return []


def installed_python_packages() -> list[dict]:
    """检查关键 Python 包是否已安装以及落在哪个目录。"""
    site_dirs = python_site_packages()
    results: list[dict] = []
    for name in PYTHON_REQUIRED_PACKAGES:
        probe = f"import importlib.util as u; s=u.find_spec({name!r}); print(s.origin if s else '')"
        code, output = run_command([sys.executable, "-c", probe])
        origin = output.splitlines()[-1].strip() if code == 0 and output else ""
        results.append({"package": name, "installed": bool(origin), "origin": origin})
    return results


def collect_tool_local_targets(include_logs: bool) -> list[dict]:
    """汇总工具目录内可清理的目标。"""
    targets: list[dict] = []
    if NODE_DEPS.is_dir():
        targets.append({"label": "Node 依赖 (WMPFDebugger/node_modules)", "path": NODE_DEPS, "size": dir_size(NODE_DEPS)})
    for venv in VENV_DIRS:
        if venv.is_dir():
            targets.append({"label": f"虚拟环境 ({venv.relative_to(PROJECT_ROOT)})", "path": venv, "size": dir_size(venv)})
    for pycache in find_pycache_dirs():
        targets.append({"label": f"字节码缓存 ({pycache.relative_to(PROJECT_ROOT)})", "path": pycache, "size": dir_size(pycache)})
    if include_logs:
        for log_dir in LOG_DIRS:
            if not log_dir.is_dir():
                continue
            artifacts = [item for item in log_dir.iterdir() if item.is_file() and item.suffix in {".log", ".pid"}]
            if artifacts:
                targets.append({"label": f"运行日志 ({log_dir.relative_to(PROJECT_ROOT)})", "path": log_dir, "size": sum(item.stat().st_size for item in artifacts), "files_only": True})
    return targets


def remove_target(target: dict) -> tuple[bool, str]:
    """删除一个清理目标。"""
    path: Path = target["path"]
    try:
        if target.get("files_only"):
            removed = 0
            for item in path.iterdir():
                if item.is_file() and item.suffix in {".log", ".pid"}:
                    item.unlink()
                    removed += 1
            return True, f"已删除 {removed} 个日志/pid 文件"
        shutil.rmtree(path)
        return True, "已删除"
    except OSError as exc:
        return False, str(exc)


def purge_npm_cache(cache: Path) -> tuple[bool, str]:
    """清理 npm 缓存（优先用 npm cache clean --force）。"""
    code, output = run_command(["npm.cmd", "cache", "clean", "--force"])
    if code == 0:
        return True, output or "npm cache clean --force 完成"
    try:
        shutil.rmtree(cache)
        return True, f"已直接删除 {cache}"
    except OSError as exc:
        return False, f"{output} / {exc}"


def purge_pip_cache() -> tuple[bool, str]:
    """清理 pip 缓存。"""
    code, output = run_command([sys.executable, "-m", "pip", "cache", "purge"])
    return code == 0, output or "pip cache purge 完成"


def uninstall_python_packages(packages: list[str]) -> tuple[bool, str]:
    """从当前 Python 环境卸载指定的包。"""
    if not packages:
        return True, "没有需要卸载的包"
    code, output = run_command([sys.executable, "-m", "pip", "uninstall", "-y", *packages])
    return code == 0, output


def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="Clean tool-local dependencies and report where dependencies live.")
    parser.add_argument("--report-only", action="store_true", help="只核实依赖落点，不删除任何东西")
    parser.add_argument("--dry-run", action="store_true", help="列出将要删除的内容，不实际删除")
    parser.add_argument("--yes", "-y", action="store_true", help="跳过交互确认")
    parser.add_argument("--logs", action="store_true", help="同时清理 logs/ 下的日志与 pid 文件")
    parser.add_argument("--npm-cache", action="store_true", help="同时清理 npm 缓存（工具目录之外）")
    parser.add_argument("--pip-cache", action="store_true", help="同时清理 pip 缓存（工具目录之外）")
    parser.add_argument("--python-packages", action="store_true", help="同时卸载全局 Python 依赖（影响当前 Python 环境）")
    parser.add_argument("--all", action="store_true", help="等于同时开启 --logs --npm-cache --pip-cache --python-packages")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    return parser.parse_args()


def confirm(question: str) -> bool:
    """在终端询问是/否。"""
    try:
        answer = input(f"{question} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def print_dependency_map(packages: list[dict]) -> None:
    """打印依赖落点核实结果。"""
    print("=== 依赖落点核实 ===")
    print()
    print("[工具目录内] 随工具目录一起删除")
    if NODE_DEPS.is_dir():
        print(f"  [OK]   Node 依赖     {NODE_DEPS}")
        print(f"                       {human_size(dir_size(NODE_DEPS))}  -> 删掉工具目录就没了")
    else:
        print("  [--]   Node 依赖     未安装（WMPFDebugger/node_modules 不存在）")

    venvs = [venv for venv in VENV_DIRS if venv.is_dir()]
    if venvs:
        for venv in venvs:
            print(f"  [OK]   虚拟环境     {venv}  {human_size(dir_size(venv))}")
    else:
        print("  [--]   虚拟环境     未使用（01-安装依赖.bat 不建 venv，直接装进当前 Python）")
    print()

    print("[工具目录外] 删掉工具目录**不会**清掉这些")
    for item in packages:
        if item["installed"]:
            print(f"  [OK]   {item['package']:<12} {item['origin']}")
        else:
            print(f"  [--]   {item['package']:<12} 未安装")
    print(f"  Python 解释器      {sys.executable}")
    for site_dir in python_site_packages():
        print(f"  site-packages      {site_dir}{'  (不存在)' if not site_dir.is_dir() else ''}")

    cache = npm_cache_dir()
    if cache:
        print(f"  npm 缓存           {cache}  {human_size(dir_size(cache))}")
    pip_cache = pip_cache_dir()
    if pip_cache:
        print(f"  pip 缓存           {pip_cache}  {human_size(dir_size(pip_cache))}")
    print()
    print("结论：Node 依赖装在工具目录内，删目录即消失；Python 依赖装在当前 Python 的")
    print("      site-packages（上面那几行），删工具目录**不会**清掉，需要 --python-packages。")
    print()


def main() -> int:
    """入口：核实依赖落点并按范围清理。"""
    args = parse_args()
    if args.all:
        args.logs = args.npm_cache = args.pip_cache = args.python_packages = True

    packages = installed_python_packages()
    report: dict = {
        "projectRoot": str(PROJECT_ROOT),
        "pythonExecutable": sys.executable,
        "pythonSitePackages": [str(path) for path in python_site_packages()],
        "pythonPackages": packages,
        "removed": [],
        "failed": [],
    }

    if not args.json:
        print("=== WMP 一键清理依赖 ===")
        print(f"工具目录: {PROJECT_ROOT}")
        print()

    if args.report_only:
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print_dependency_map(packages)
        return 0

    targets = collect_tool_local_targets(include_logs=args.logs)
    report["toolLocalTargets"] = [
        {"label": item["label"], "path": str(item["path"]), "size": item["size"]} for item in targets
    ]

    if not args.json:
        if targets:
            print("[工具目录内] 计划清理：")
            for item in targets:
                print(f"  - {item['label']}  ({human_size(item['size'])})")
        else:
            info("工具目录内没有可清理的依赖（可能已经清理过了）。")
        print()

        if args.npm_cache:
            cache = npm_cache_dir()
            print(f"[工具目录外] npm 缓存：{cache if cache else '未找到'}")
        if args.pip_cache:
            print(f"[工具目录外] pip 缓存：{pip_cache_dir() or '未找到'}")
        if args.python_packages:
            installed = [item["package"] for item in packages if item["installed"]]
            print(f"[工具目录外] 将卸载全局 Python 包：{', '.join(installed) if installed else '无'}")
        print()

    if args.dry_run:
        if not args.json:
            info("--dry-run：未执行任何删除。")
            print()
            print_dependency_map(packages)
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    total = sum(int(item["size"]) for item in targets)
    if not args.json and (targets or args.npm_cache or args.pip_cache or args.python_packages):
        question = f"确认执行以上清理？工具目录内将删除 {human_size(total)}"
        if not args.yes and sys.stdin.isatty() and not confirm(question):
            warn("已取消，未做任何改动。")
            return 1

    for item in targets:
        success, detail = remove_target(item)
        entry = {"label": item["label"], "path": str(item["path"]), "ok": success, "detail": detail}
        (report["removed"] if success else report["failed"]).append(entry)
        if args.json:
            continue
        if success:
            ok(f"{item['label']}：{detail}")
        else:
            warn(f"{item['label']} 删除失败：{detail}")

    if args.npm_cache:
        cache = npm_cache_dir()
        success, detail = purge_npm_cache(cache) if cache else (True, "未找到 npm 缓存，跳过")
        entry = {"label": "npm 缓存", "ok": success, "detail": detail}
        (report["removed"] if success else report["failed"]).append(entry)
        if not args.json:
            (ok if success else warn)(f"npm 缓存：{detail}")

    if args.pip_cache:
        success, detail = purge_pip_cache()
        entry = {"label": "pip 缓存", "ok": success, "detail": detail}
        (report["removed"] if success else report["failed"]).append(entry)
        if not args.json:
            (ok if success else warn)(f"pip 缓存：{detail}")

    if args.python_packages:
        installed = [item["package"] for item in packages if item["installed"]]
        success, detail = uninstall_python_packages(installed)
        entry = {"label": "全局 Python 包", "packages": installed, "ok": success, "detail": detail}
        (report["removed"] if success else report["failed"]).append(entry)
        if not args.json:
            (ok if success else warn)(f"全局 Python 包卸载：{'成功' if success else detail}")

    if not args.json:
        print()
        print_dependency_map(installed_python_packages())
        print("下一步：需要重新使用时，双击 `01-安装依赖.bat` 重新安装。")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not report["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

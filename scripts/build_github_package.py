#!/usr/bin/env python3
"""Export a clean GitHub-ready package from the current project directory."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile

PROJECT_ROOT = Path(__file__).resolve().parents[1]  # scripts/ 的上一级才是项目根
# 导出目录与 zip 都用仓库名，这样解压出来是 WMP-pentest-automation/ 而不是本地目录名
REPO_NAME = "WMP-pentest-automation"
DIST_DIR = PROJECT_ROOT / "dist"

IGNORED_DIR_NAMES = {
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    # 01-安装依赖.bat 在本目录内下载的 Node 20（约 80 MB）。
    # 这是「本机运行环境」不是源码：每个使用者跑 01 时会自己下，
    # 打进发布包既臃肿又违规（Node 的二进制有自己的分发许可）。
    ".runtime",
    ".idea",
    ".vscode",
    ".pytest_cache",
    "dist",
    "logs",
    # 运行时会话产物（抓包记录 / 报告），可能含 cookie、token 等敏感数据，
    # 绝对不能进发布包。与 .gitignore 的 output/ 保持一致。
    "output",
    "发布材料",
}
IGNORED_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
    "*.log",
    "*.pid",
    "Thumbs.db",
    ".DS_Store",
    "*.bak",
}
# 备份类目录/文件的通用前缀。实测这类临时备份**两次**混进过发布包
# （`.bak_enc/`、`README.md.bak`），里面可能是旧版本代码或含明文的数据，
# 所以除精确名单外再按前缀兜一道。
IGNORED_NAME_PREFIXES = (".bak", "_bak", "backup", "_backup", ".backup", ".old", "_old")

IGNORED_RELATIVE_FILES = {
    Path("e0e1-wx") / "wxid.db",
}
# 单个文件体积上限（见 verify_export 的说明）：源码最大约 0.5 MB
MAX_INCLUDED_FILE_BYTES = 5 * 1024 * 1024
REQUIRED_RELATIVE_FILES = [
    Path("README.md"),
    Path("问题解决.md"),
    Path("LICENSE"),
    Path(".gitignore"),
    # 根目录只保留这 6 个入口按钮
    Path("01-安装依赖.bat"),
    Path("02-一键启动.bat"),
    Path("03-检测依赖.bat"),
    Path("04-自动更新.bat"),
    Path("05-一键停止.bat"),
    Path("06-一键清理依赖.bat"),
    # 按钮背后的实现
    Path("scripts") / "project_doctor.py",
    Path("scripts") / "start_full_chain.py",
    Path("scripts") / "stop_full_chain.py",
    Path("scripts") / "clean_dependencies.py",
    Path("scripts") / "restart-elevated.ps1",
    Path("scripts") / "wxmcp.py",
    Path("scripts") / "mcp_smoke_test.py",
    Path("scripts") / "analysis_regression.py",
    Path("scripts") / "build_github_package.py",
    # 引用的项目
    Path("WMPFDebugger") / "package.json",
    Path("WMPFDebugger") / "launch-wmpfdebugger-admin.ps1",
    Path("WMPFDebugger") / "frida" / "hook.js",
    Path("e0e1-wx") / "start_engine.py",
    Path("e0e1-wx") / "start_mcp_server.py",
    Path("e0e1-wx") / "SKILL.md",
    Path("e0e1-wx") / "tools.md",
    Path("e0e1-wx") / "requirements.txt",
    Path("偏移提取工具") / "extract_wmpf_offsets.py",
    Path("偏移提取工具") / "extract_wmpf_offsets_modern.py",
    Path("偏移提取工具") / "sync_latest_wmpf_offsets.py",
    Path("偏移提取工具") / "SKILL.md",
]

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def info(message: str) -> None:
    print(f"[INFO] {message}")


def ok(message: str) -> None:
    print(f"[OK] {message}")


def fail(message: str) -> int:
    print(f"[FAIL] {message}")
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a clean GitHub upload package.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DIST_DIR,
        help="Directory where the exported folder and zip will be created.",
    )
    parser.add_argument(
        "--keep-export-dir",
        action="store_true",
        help="Keep the extracted export directory after creating the zip.",
    )
    return parser.parse_args()


def looks_like_backup(name: str) -> bool:
    """名字像临时备份就跳过（`.bak_enc` / `_backup_before_trim` / `x.old` …）。"""
    lowered = name.lower()
    # ".bak" 任意位置命中：覆盖 .bak / .bak_<时间戳> / .bak_enc（2026-09-23 实测 .bak_131310 漏网）
    return (lowered.startswith(IGNORED_NAME_PREFIXES)
            or ".bak" in lowered
            or lowered.endswith((".old", ".orig")))


def should_skip_dir(relative_dir: Path) -> tuple[bool, str]:
    for part in relative_dir.parts:
        if part in IGNORED_DIR_NAMES:
            return True, f"ignored directory name: {part}"
        if looks_like_backup(part):
            return True, f"looks like a backup: {part}"
    return False, ""


def should_skip_file(relative_file: Path) -> tuple[bool, str]:
    if relative_file in IGNORED_RELATIVE_FILES:
        return True, "ignored runtime data file"
    for part in relative_file.parts[:-1]:
        if part in IGNORED_DIR_NAMES:
            return True, f"inside ignored directory: {part}"
    for pattern in IGNORED_FILE_PATTERNS:
        if fnmatch.fnmatch(relative_file.name, pattern):
            return True, f"ignored file pattern: {pattern}"
    if looks_like_backup(relative_file.name):
        return True, f"looks like a backup: {relative_file.name}"
    return False, ""


def export_project(source_root: Path, export_root: Path) -> dict:
    included_files = 0
    skipped_files = 0
    skipped_dirs = 0
    skip_examples: list[dict[str, str]] = []

    for current_root, dir_names, file_names in os.walk(source_root):
        current_root_path = Path(current_root)
        relative_root = current_root_path.relative_to(source_root)

        kept_dirs: list[str] = []
        for dir_name in sorted(dir_names):
            relative_dir = relative_root / dir_name if relative_root != Path(".") else Path(dir_name)
            skip, reason = should_skip_dir(relative_dir)
            if skip:
                skipped_dirs += 1
                if len(skip_examples) < 25:
                    skip_examples.append({"path": str(relative_dir), "reason": reason})
                continue
            kept_dirs.append(dir_name)
        dir_names[:] = kept_dirs

        for file_name in sorted(file_names):
            relative_file = relative_root / file_name if relative_root != Path(".") else Path(file_name)
            skip, reason = should_skip_file(relative_file)
            if skip:
                skipped_files += 1
                if len(skip_examples) < 25:
                    skip_examples.append({"path": str(relative_file), "reason": reason})
                continue

            source_path = current_root_path / file_name
            destination = export_root / relative_file
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)
            included_files += 1

    return {
        "included_files": included_files,
        "skipped_files": skipped_files,
        "skipped_dirs": skipped_dirs,
        "skip_examples": skip_examples,
    }


def build_zip(folder_to_zip: Path, zip_path: Path) -> int:
    entry_count = 0
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        for path in sorted(folder_to_zip.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=path.relative_to(folder_to_zip.parent))
                entry_count += 1
    return entry_count


def verify_export(export_root: Path, zip_path: Path) -> None:
    export_project_root = export_root / REPO_NAME
    missing = [str(relative_path) for relative_path in REQUIRED_RELATIVE_FILES if not (export_project_root / relative_path).is_file()]
    if missing:
        raise RuntimeError("export is missing required files:\n" + "\n".join(missing))

    with ZipFile(zip_path, "r") as archive:
        infos = archive.infolist()

    def has_forbidden_runtime_content(name: str) -> bool:
        parts = PurePosixPath(name).parts
        if any(part in IGNORED_DIR_NAMES for part in parts):
            return True
        if PurePosixPath(name).name == "wxid.db" and "e0e1-wx" in parts:
            return True
        if PurePosixPath(name).suffix.lower() in {".log", ".pid", ".pyc", ".pyo"}:
            return True
        return False

    matched = [info.filename for info in infos if has_forbidden_runtime_content(info.filename)]
    if matched:
        preview = "\n".join(matched[:20])
        raise RuntimeError("zip still contains ignored runtime content:\n" + preview)

    # 第二道防线：体积异常的大文件几乎一定是运行时会话产物
    # （例如 e0e1-wx/output/reports/*.json 抓包记录，可能含 cookie / token）。
    # 源码里最大的文件约 0.5 MB，所以 5 MB 阈值不会误报。
    oversized = [
        (info.filename, info.file_size)
        for info in infos
        if info.file_size > MAX_INCLUDED_FILE_BYTES
    ]
    if oversized:
        preview = "\n".join(f"{name}  ({size / 1048576:.1f} MB)" for name, size in oversized[:10])
        raise RuntimeError(
            "zip contains unexpectedly large files — 很可能是运行时会话产物（抓包记录/报告），"
            "请确认不要把它发布出去：\n" + preview
        )


def main() -> int:
    args = parse_args()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir.resolve()
    export_root = output_dir / f"{REPO_NAME}-github-{timestamp}"
    export_project_root = export_root / REPO_NAME
    zip_path = output_dir / f"{REPO_NAME}-github-{timestamp}.zip"
    summary_path = output_dir / f"{REPO_NAME}-github-{timestamp}-summary.json"

    output_dir.mkdir(parents=True, exist_ok=True)
    if export_root.exists():
        shutil.rmtree(export_root)

    info(f"source: {PROJECT_ROOT}")
    info(f"export folder: {export_root}")
    info(f"zip file: {zip_path}")

    try:
        metrics = export_project(PROJECT_ROOT, export_project_root)
        # 以 export_project_root 为根打包，zip 内顶层就是 WMP-pentest-automation/
        # （而不是带时间戳的中间目录，避免解压出双层嵌套）
        zip_entries = build_zip(export_project_root, zip_path)
        verify_export(export_root, zip_path)
    except Exception as exc:
        if zip_path.exists():
            zip_path.unlink()
        # 失败时也要清掉临时导出目录，否则会残留一份（可能含敏感内容的）副本
        if export_root.exists():
            shutil.rmtree(export_root, ignore_errors=True)
        return fail(str(exc))

    summary = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "source_root": str(PROJECT_ROOT),
        "export_root": str(export_root),
        "zip_path": str(zip_path),
        "included_files": metrics["included_files"],
        "skipped_files": metrics["skipped_files"],
        "skipped_dirs": metrics["skipped_dirs"],
        "zip_entries": zip_entries,
        "required_files_verified": [str(item) for item in REQUIRED_RELATIVE_FILES],
        "skip_examples": metrics["skip_examples"],
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    ok(f"clean export built: {export_root}")
    ok(f"zip built: {zip_path}")
    ok(f"summary written: {summary_path}")
    print(f"included files: {metrics['included_files']}")
    print(f"skipped files: {metrics['skipped_files']}")
    print(f"skipped directories: {metrics['skipped_dirs']}")

    if not args.keep_export_dir:
        shutil.rmtree(export_root)
        info("removed temporary export folder after zip verification")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

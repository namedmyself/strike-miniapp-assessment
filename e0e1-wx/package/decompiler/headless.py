"""无头模式下的小程序反编译编排：定位包 → 解密解包 → 美化 → 检索。

本模块供 MCP 工具层调用，**不依赖 PySide6，也不依赖 CDP 连接** ——
在没有 GUI、没有调试链路的情况下也能单独工作。

设计取舍：

* **复用既有实现**：解密与解包用 `decompiler.core`，美化用
  `code_optimizer.formatter`，包目录发现用 `monitor.paths` / `monitor.windows`
  —— 不重复造轮子。
* **同步执行**：由 MCP 层用 `asyncio.to_thread` 包装。不复用
  `DecompileTaskRunner` 的多进程 + 事件队列 —— 那套是给 GUI 用的，
  无头场景下只会多出两个故障点。
* **幂等**：产物与源包签名一致时直接复用，避免每次调用重跑。
* **不猜测覆盖范围**：分包缺失必须显式报告，否则上层会静默漏测。
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Iterable

from package.code_optimizer.formatter import CodeFormatter
from package.content_scanner import RegexContentScanner
from package.decompiler.core import (
    WxapkgError,
    decrypt_wxapkg,
    find_wxapkg_files,
    safe_output_folder_name,
    unpack_wxapkg,
)
from package.monitor.paths import (
    build_monitor_scan_roots,
    default_applet_packages_root,
    resolve_packages_roots,
)
from package.regex_rules.presets import copy_default_regex_rules


DECOMPILE_ACTIONS = (
    "list_opened_applets",
    "decompile",
    "list_files",
    "read_source",
    "search_source",
    "scan_source",
)

MANIFEST_NAME = ".e0e1_decompile_manifest.json"
SKIP_DIR_NAMES = {".e0e1_cache", "__pycache__"}
# 工具自身写的状态文件，不算产出内容，列清单/列源码时都要排除。
SKIP_FILE_NAMES = {MANIFEST_NAME}

# 单次读取/检索的上限，避免把几 MB 的文件整个灌进 Agent 上下文。
DEFAULT_READ_MAX_LINES = 400
MAX_READ_MAX_LINES = 2000
DEFAULT_SEARCH_MAX_RESULTS = 200
MAX_SEARCH_MAX_RESULTS = 2000
SEARCH_MAX_FILE_BYTES = 8 * 1024 * 1024
LINE_COUNT_MAX_BYTES = 4 * 1024 * 1024

# scan_source：按预设规则全量扫描产物的输出上限。
# 规则在整棵源码树上的命中数动辄上千（「路径接口」「域名」尤其密集），
# 逐条回传必然撑爆返回体 —— 所以只回**每条规则的计数 + 有限样本**，并显式给出 top 文件。
DEFAULT_SCAN_SAMPLES_PER_RULE = 20
MAX_SCAN_SAMPLES_PER_RULE = 200
DEFAULT_SCAN_TOP_FILES = 20
MAX_SCAN_TOP_FILES = 100

TEXT_EXTENSIONS = {
    ".js",
    ".json",
    ".html",
    ".wxml",
    ".wxss",
    ".css",
    ".wxs",
    ".ts",
    ".txt",
    ".md",
}
SOURCE_EXTENSIONS = {".js", ".json", ".wxml", ".wxss", ".css", ".wxs", ".html"}


def default_output_root() -> Path:
    """反编译产物的默认根目录：WMP 根目录下的 output/。

    `headless.py` 位于 `<WMP>/e0e1-wx/package/decompiler/`，
    `parents[3]` 即 WMP 根目录（与既有的 `logs/` 同级）。
    """
    return Path(__file__).resolve().parents[3] / "output"


def _human_size(size: int) -> str:
    """把字节数渲染成便于阅读的文本。"""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.2f} GB"


def _iso_time(timestamp: float) -> str:
    """把时间戳渲染成本地时间文本。"""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(timestamp)))
    except (OSError, ValueError, TypeError):
        return ""


def discover_packages_roots(
    packages_root: str | os.PathLike[str] | None = None,
    home_dir: str | os.PathLike[str] | None = None,
) -> list[Path]:
    """解析出所有可能存在小程序包缓存的 packages 根目录。

    覆盖两种微信 4.x 布局：
      * `radium/Applet/packages`
      * `radium/users/<md5>/applet/packages`
    """
    configured = (
        Path(packages_root).expanduser()
        if packages_root
        else default_applet_packages_root(home_dir=home_dir)
    )
    home = Path(home_dir) if home_dir is not None else None
    resolved_roots: list[Path] = []
    for scan_root in build_monitor_scan_roots(configured, home_dir=home):
        for resolved in resolve_packages_roots(scan_root):
            key = str(resolved).casefold()
            if all(str(item).casefold() != key for item in resolved_roots) and resolved.is_dir():
                resolved_roots.append(resolved)
    return resolved_roots


def list_wechat_mini_program_windows() -> list[dict]:
    """枚举当前打开的微信小程序窗口（纯 Win32 API，失败时返回空列表）。"""
    try:
        from package.monitor.windows import list_wechat_app_windows

        windows = list_wechat_app_windows()
    except Exception:  # noqa: BLE001 - 非 Windows 或 API 不可用时不该拖垮工具
        return []
    result: list[dict] = []
    for window in windows or []:
        result.append(
            {
                "title": str(window.get("title") or ""),
                "pid": int(window.get("pid") or 0),
                "hwnd": int(window.get("hwnd") or 0),
                "start_time": _iso_time(float(window.get("start_time") or 0.0)),
            }
        )
    return result


def list_opened_applets(
    packages_root: str | os.PathLike[str] | None = None,
    home_dir: str | os.PathLike[str] | None = None,
    limit: int = 50,
) -> dict:
    """列出本地有包缓存的小程序，供上层确定「要分析哪一个」。

    返回里同时给出微信小程序窗口列表 —— 窗口标题无法直接映射到 appid，
    但「包目录最近写入时间」与「窗口启动时间」对照通常足以定位目标。
    """
    roots = discover_packages_roots(packages_root, home_dir=home_dir)
    applets: list[dict] = []
    unreadable: list[str] = []

    for root in roots:
        try:
            children = sorted(root.iterdir(), key=lambda item: item.name.lower())
        except OSError as exc:
            unreadable.append(f"{root} ({exc})")
            continue
        for child in children:
            try:
                if not child.is_dir() or not child.name.lower().startswith("wx"):
                    continue
            except OSError:
                continue
            packages = find_wxapkg_files(child)
            if not packages:
                continue
            sizes = []
            mtimes = []
            for item in packages:
                try:
                    mtimes.append(os.path.getmtime(item["path"]))
                    sizes.append(int(item["size"]))
                except OSError:
                    continue
            if not mtimes:
                continue
            latest = max(mtimes)
            total = sum(sizes)
            applets.append(
                {
                    "appid": child.name,
                    "packages_root": str(root),
                    "package_dir": str(child),
                    "versions": sorted({Path(item["path"]).parent.name for item in packages}),
                    "wxapkg_count": len(packages),
                    "wxapkg_names": sorted({item["name"] for item in packages}),
                    "total_size": total,
                    "total_size_text": _human_size(total),
                    "latest_mtime": latest,
                    "latest_mtime_text": _iso_time(latest),
                }
            )

    applets.sort(key=lambda item: item["latest_mtime"], reverse=True)
    windows = list_wechat_mini_program_windows()

    return {
        "ok": True,
        "packages_roots": [str(root) for root in roots],
        "unreadable_roots": unreadable,
        "total_applets": len(applets),
        "applets": applets[: max(int(limit or 50), 1)],
        "wechat_windows": windows,
        "recommended_appid": applets[0]["appid"] if applets else "",
        "hint": (
            "窗口标题无法直接映射到 appid。若只有一个候选或只有一个小程序窗口，"
            "它通常就是目标；不确定时把 applets 列表与 wechat_windows 的时间对照，"
            "或先连上 CDP 用 runtime_eval('__wxConfig.appId') 取准确 appid。"
        ),
    }


def _locate_applet_dir(
    appid: str,
    roots: Iterable[Path],
    version: str | None = None,
) -> tuple[Path | None, Path | None]:
    """在候选 packages 根目录里定位某个 appid 的包目录。

    返回 `(appid 目录, packages 根目录)`；找不到返回 `(None, None)`。
    """
    target = str(appid or "").strip()
    if not target:
        return None, None
    for root in roots:
        candidate = root / target
        if not candidate.is_dir():
            continue
        if version:
            versioned = candidate / str(version)
            if versioned.is_dir():
                return versioned, root
            continue
        return candidate, root
    return None, None


def _manifest_path(appid_output_dir: Path) -> Path:
    return appid_output_dir / MANIFEST_NAME


def _load_manifest(appid_output_dir: Path) -> dict:
    path = _manifest_path(appid_output_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _package_signature(wxapkg_path: Path) -> dict:
    """源包签名：路径 + 大小 + mtime，用于判断产物是否可复用。"""
    try:
        stat = wxapkg_path.stat()
    except OSError:
        return {}
    return {
        "path": str(wxapkg_path),
        "size": int(stat.st_size),
        "mtime": round(float(stat.st_mtime), 3),
    }


def _extract_package(wxapkg_path: Path, dest_dir: Path, appid: str) -> dict:
    """解密 + 解包单个 wxapkg 到目标目录，返回统计。"""
    raw = wxapkg_path.read_bytes()
    decrypted = decrypt_wxapkg(raw, appid)
    entries = unpack_wxapkg(decrypted)

    written = 0
    skipped_unsafe = 0
    root = dest_dir.resolve()
    for name, content in entries:
        relative = str(name or "").lstrip("/").replace("\\", "/")
        parts = [part for part in relative.split("/") if part not in ("", ".")]
        if not parts or ".." in parts:
            skipped_unsafe += 1
            continue
        target = (dest_dir / Path(*parts)).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            skipped_unsafe += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        written += 1

    return {
        "raw_size": len(raw),
        "decrypted_size": len(decrypted),
        "index_entries": len(entries),
        "files_written": written,
        "skipped_unsafe": skipped_unsafe,
    }


def _read_app_config(package_output_dir: Path) -> dict:
    """从产物里读 app-config.json（含分包声明）。"""
    for candidate in ("app-config.json", "app.json"):
        path = package_output_dir / candidate
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def _collect_subpackages(config: dict) -> list[str]:
    """从 app-config.json 里提取分包 root 列表。"""
    raw = config.get("subPackages") or config.get("subpackages") or []
    roots: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                value = str(item.get("root") or item.get("name") or "").strip()
            else:
                value = str(item or "").strip()
            if value:
                roots.append(value.rstrip("/") + "/")
    return roots


def decompile_applet(
    appid: str,
    *,
    packages_root: str | os.PathLike[str] | None = None,
    home_dir: str | os.PathLike[str] | None = None,
    version: str | None = None,
    output_root: str | os.PathLike[str] | None = None,
    do_format: bool = True,
    force: bool = False,
) -> dict:
    """把某个小程序的所有本地包解密解包并美化，返回产物清单与覆盖边界。

    幂等：源包签名与上次一致（且产物存在）时直接复用，除非 `force=True`。
    """
    started = time.time()
    roots = discover_packages_roots(packages_root, home_dir=home_dir)
    if not roots:
        return {
            "ok": False,
            "error": "没有找到任何微信小程序 packages 目录。",
            "searched": [str(default_applet_packages_root(home_dir=home_dir))],
            "hint": "确认本机装有微信 4.x，并至少打开过一次目标小程序。",
        }

    applet_dir, matched_root = _locate_applet_dir(appid, roots, version=version)
    if applet_dir is None:
        return {
            "ok": False,
            "error": f"未在包缓存里找到 appid={appid} 的目录。",
            "searched_roots": [str(root) for root in roots],
            "hint": "先在微信里打开一次该小程序，让包缓存落盘；或用 list_opened_applets 看现有候选。",
        }

    packages = find_wxapkg_files(applet_dir)
    if not packages:
        return {
            "ok": False,
            "error": f"目录存在但没有 .wxapkg 文件：{applet_dir}",
            "hint": "小程序可能只缓存了索引而未下载包体，重新打开小程序页面触发下载。",
        }

    out_root = Path(output_root).expanduser() if output_root else default_output_root()
    appid_output = out_root / safe_output_folder_name(appid)
    appid_output.mkdir(parents=True, exist_ok=True)

    manifest = _load_manifest(appid_output)
    previous_packages = manifest.get("packages") if isinstance(manifest.get("packages"), dict) else {}

    packages_report: list[dict] = []
    format_stats = {"success": 0, "skipped": 0, "error": 0}
    reused = False
    formatter = CodeFormatter() if do_format else None

    for item in packages:
        wxapkg_path = Path(item["path"])
        package_name = wxapkg_path.stem or "package"
        package_output = appid_output / safe_output_folder_name(package_name)
        signature = _package_signature(wxapkg_path)
        record: dict[str, Any] = {
            "name": wxapkg_path.name,
            "package": package_name,
            "wxapkg_path": str(wxapkg_path),
            "size": int(item.get("size") or 0),
            "size_text": _human_size(int(item.get("size") or 0)),
            "version": wxapkg_path.parent.name,
            "output_dir": str(package_output),
        }

        previous = previous_packages.get(str(wxapkg_path))
        signature_matches = (
            isinstance(previous, dict)
            and previous.get("size") == signature.get("size")
            and previous.get("mtime") == signature.get("mtime")
            and package_output.is_dir()
        )

        try:
            if signature_matches and not force:
                record["status"] = "reused"
                reused = True
                record["files_written"] = int(previous.get("files_written") or 0)
                record["formatted"] = previous.get("formatted")
            else:
                record.update(_extract_package(wxapkg_path, package_output, appid))
                record["status"] = "decompiled"
                if formatter is not None:
                    file_format_stats = _format_tree(package_output, formatter)
                    record["formatted"] = file_format_stats
                    format_stats["success"] += file_format_stats["success"]
                    format_stats["skipped"] += file_format_stats["skipped"]
                    format_stats["error"] += file_format_stats["error"]
        except WxapkgError as exc:
            record["status"] = "error"
            record["error"] = str(exc)
        except OSError as exc:
            record["status"] = "error"
            record["error"] = f"读写失败：{exc}"

        packages_report.append(record)

    main_record = next(
        (item for item in packages_report if str(item.get("package", "")).upper() == "__APP__"),
        packages_report[0],
    )
    main_output = Path(str(main_record.get("output_dir") or appid_output))

    config = _read_app_config(main_output)
    declared = _collect_subpackages(config)
    main_pages = config.get("pages") if isinstance(config.get("pages"), list) else []

    local_package_names = {str(item.get("package") or "") for item in packages_report}
    missing = [root for root in declared if root.rstrip("/").split("/")[-1] not in local_package_names]

    source_files = _iter_source_files(appid_output)

    new_manifest = {
        "appid": appid,
        "packages_root": str(matched_root) if matched_root else "",
        "applet_dir": str(applet_dir),
        "output_dir": str(appid_output),
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "packages": {},
    }
    for item in packages:
        wxapkg_path = Path(item["path"])
        signature = _package_signature(wxapkg_path)
        record = next((r for r in packages_report if r.get("wxapkg_path") == str(wxapkg_path)), {})
        if signature:
            new_manifest["packages"][str(wxapkg_path)] = {
                **signature,
                "files_written": record.get("files_written"),
                "formatted": record.get("formatted"),
            }
    try:
        with open(_manifest_path(appid_output), "w", encoding="utf-8") as handle:
            json.dump(new_manifest, handle, ensure_ascii=False, indent=2)
    except OSError:
        pass

    warnings: list[str] = []
    if missing:
        warnings.append(
            f"有 {len(missing)} 个声明分包在本地不存在：{'、'.join(missing)}。"
            "分包按需下载，未被访问过的页面代码不在本地 —— 静态分析覆盖不到这部分。"
        )
    if not main_pages:
        warnings.append("未能从 app-config.json 读到主包 pages 清单，产物可能不完整。")

    return {
        "ok": True,
        "appid": appid,
        "version": Path(str(main_record.get("wxapkg_path") or "")).parent.name,
        "packages_root": str(matched_root) if matched_root else "",
        "applet_dir": str(applet_dir),
        "output_dir": str(appid_output),
        "reused_existing_output": reused,
        "packages_found": len(packages_report),
        "packages": packages_report,
        "formatted_total": format_stats if formatter is not None else None,
        "subpackages_declared": declared,
        "subpackages_missing": missing,
        "main_pages_count": len(main_pages),
        "source_files": source_files,
        "coverage": {
            "packages_local": len(packages_report),
            "subpackages_declared": len(declared),
            "subpackages_missing": len(missing),
            "complete": not missing,
        },
        "warnings": warnings,
        "elapsed_seconds": round(time.time() - started, 2),
        "next_steps": [
            "所有产物路径都以 output_dir 为基准（如 '__APP__/app-service.js'）。",
            "decompile_ops(action='list_files') 拿产物文件清单",
            "decompile_ops(action='search_source', pattern='...') 定向检索接口/凭据线索",
            "decompile_ops(action='read_source', path='__APP__/app-service.js', start_line=..., end_line=...) 按行读",
            "需要动态验证时再走 connection_ops 建立 CDP 链路",
        ],
    }


def _format_tree(root: Path, formatter: CodeFormatter) -> dict:
    """对产物目录里可格式化的文件统一美化。"""
    stats = {"success": 0, "skipped": 0, "error": 0}
    try:
        candidates = [
            path
            for path in root.rglob("*")
            if path.is_file()
            and formatter.is_supported_file(path)
            and not any(part in SKIP_DIR_NAMES for part in path.parts)
        ]
    except OSError:
        return stats
    for path in candidates:
        result = formatter.format_file(path)
        status = str(result.get("status") or "")
        if status in stats:
            stats[status] += 1
    return stats


def _iter_source_files(root: Path, extensions: Iterable[str] | None = None) -> list[dict]:
    """列出产物里的可读源码文件（默认只看源码类扩展名）。"""
    allowed = {ext.lower() for ext in (extensions or SOURCE_EXTENSIONS)}
    files: list[dict] = []
    if not root.is_dir():
        return files
    for current, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIR_NAMES]
        for name in names:
            if name in SKIP_FILE_NAMES:
                continue
            path = Path(current) / name
            suffix = path.suffix.lower()
            if suffix not in allowed:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            item = {
                "path": path.relative_to(root).as_posix(),
                "size": int(stat.st_size),
                "size_text": _human_size(int(stat.st_size)),
            }
            if stat.st_size <= LINE_COUNT_MAX_BYTES:
                item["lines"] = _count_lines(path)
            files.append(item)
    files.sort(key=lambda item: item["size"], reverse=True)
    return files


def _count_lines(path: Path) -> int:
    """统计文本文件行数（大文件由调用方跳过）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def list_output_files(
    output_dir: str | os.PathLike[str],
    *,
    extensions: Iterable[str] | None = None,
    limit: int = 500,
) -> dict:
    """列出反编译产物里的文件，按大小倒序（最大的通常最值得先看）。"""
    root = Path(output_dir).expanduser()
    if not root.is_dir():
        return {
            "ok": False,
            "error": f"产物目录不存在：{root}",
            "hint": "先调用 decompile_ops(action='decompile') 生成产物。",
        }

    allowed = {ext.lower() for ext in extensions} if extensions else None
    files: list[dict] = []
    total_bytes = 0
    for current, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIR_NAMES]
        for name in names:
            if name in SKIP_FILE_NAMES:
                continue
            path = Path(current) / name
            if allowed is not None and path.suffix.lower() not in allowed:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            total_bytes += int(stat.st_size)
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": int(stat.st_size),
                    "size_text": _human_size(int(stat.st_size)),
                }
            )

    files.sort(key=lambda item: item["size"], reverse=True)
    limited = files[: max(int(limit or 500), 1)]
    for item in limited:
        if item["path"].lower().endswith(tuple(TEXT_EXTENSIONS)) and item["size"] <= LINE_COUNT_MAX_BYTES:
            item["lines"] = _count_lines(root / item["path"])

    return {
        "ok": True,
        "output_dir": str(root),
        "total_files": len(files),
        "total_size": total_bytes,
        "total_size_text": _human_size(total_bytes),
        "returned": len(limited),
        "files": limited,
        "hint": (
            "用 read_source(path=..., start_line=..., end_line=...) 按行区间读，"
            "不要把大文件整读；定位内容优先用 search_source。"
        ),
    }


def read_source(
    path: str | os.PathLike[str],
    *,
    base_dir: str | os.PathLike[str] | None = None,
    start_line: int = 1,
    end_line: int | None = None,
    max_lines: int = DEFAULT_READ_MAX_LINES,
) -> dict:
    """按行区间读取产物里的一个文本文件。

    `path` 给相对路径时必须以 `base_dir` 为基准（通常是 decompile 返回的 output_dir）。
    """
    raw_path = Path(str(path))
    if not raw_path.is_absolute():
        if not base_dir:
            return {
                "ok": False,
                "error": "相对路径必须同时提供 base_dir。",
                "hint": "base_dir 用 decompile_ops(action='decompile') 返回的 output_dir。",
            }
        raw_path = Path(base_dir).expanduser() / raw_path
    target = raw_path.expanduser()

    if not target.is_file():
        return {"ok": False, "error": f"文件不存在：{target}"}

    suffix = target.suffix.lower()
    if suffix not in TEXT_EXTENSIONS:
        return {
            "ok": False,
            "error": f"拒绝读取非文本文件：{suffix or '(无扩展名)'}",
            "allowed": sorted(TEXT_EXTENSIONS),
        }

    try:
        size = target.stat().st_size
    except OSError as exc:
        return {"ok": False, "error": f"无法读取文件属性：{exc}"}

    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError as exc:
        return {"ok": False, "error": f"读取失败：{exc}"}

    total_lines = len(lines)
    begin = max(int(start_line or 1), 1)
    cap = min(max(int(max_lines or DEFAULT_READ_MAX_LINES), 1), MAX_READ_MAX_LINES)
    stop = int(end_line) if end_line else begin + cap - 1
    stop = min(max(stop, begin), begin + cap - 1)
    stop = min(stop, total_lines)

    if begin > total_lines:
        return {
            "ok": False,
            "error": f"start_line={begin} 超出文件总行数 {total_lines}。",
            "total_lines": total_lines,
        }

    chunk = [line.rstrip("\n") for line in lines[begin - 1 : stop]]
    return {
        "ok": True,
        "path": str(target),
        "size": size,
        "size_text": _human_size(size),
        "total_lines": total_lines,
        "start_line": begin,
        "end_line": stop,
        "returned_lines": len(chunk),
        "truncated": stop < total_lines,
        "content": "\n".join(f"{begin + index}: {text}" for index, text in enumerate(chunk)),
    }


def search_in_output(
    output_dir: str | os.PathLike[str],
    pattern: str,
    *,
    is_regex: bool = False,
    case_sensitive: bool = False,
    context_lines: int = 2,
    max_results: int = DEFAULT_SEARCH_MAX_RESULTS,
    extensions: Iterable[str] | None = None,
) -> dict:
    """在产物目录里做内容检索，返回「文件 + 行号 + 上下文」。

    这是 Agent 定位代码的主路径 —— 产物里最大的文件有 5 万行，
    整读不现实，靠关键词命中再局部展开才可行。
    """
    root = Path(output_dir).expanduser()
    if not root.is_dir():
        return {"ok": False, "error": f"产物目录不存在：{root}"}
    if not str(pattern or "").strip():
        return {"ok": False, "error": "pattern 不能为空。"}

    flags = 0 if case_sensitive else re.IGNORECASE
    if is_regex:
        try:
            matcher = re.compile(str(pattern), flags)
        except re.error as exc:
            return {"ok": False, "error": f"正则表达式无效：{exc}", "pattern": pattern}
        check = matcher.search
    else:
        needle = str(pattern) if case_sensitive else str(pattern).lower()
        def check(text: str) -> Any:  # type: ignore[misc]
            haystack = text if case_sensitive else text.lower()
            return needle in haystack

    ctx = max(int(context_lines or 0), 0)
    cap = min(max(int(max_results or DEFAULT_SEARCH_MAX_RESULTS), 1), MAX_SEARCH_MAX_RESULTS)
    allowed = {ext.lower() for ext in extensions} if extensions else TEXT_EXTENSIONS

    hits: list[dict] = []
    scanned_files = 0
    skipped_large = 0
    truncated = False

    for current, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIR_NAMES]
        for name in sorted(names):
            path = Path(current) / name
            if path.suffix.lower() not in allowed:
                continue
            try:
                if path.stat().st_size > SEARCH_MAX_FILE_BYTES:
                    skipped_large += 1
                    continue
            except OSError:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    lines = handle.readlines()
            except OSError:
                continue
            scanned_files += 1
            relative = path.relative_to(root).as_posix()
            for index, line in enumerate(lines):
                if not check(line):
                    continue
                start = max(index - ctx, 0)
                stop = min(index + ctx + 1, len(lines))
                hits.append(
                    {
                        "path": relative,
                        "line": index + 1,
                        "match": line.strip()[:400],
                        "context": "\n".join(
                            f"{start + offset + 1}: {text.rstrip()}"
                            for offset, text in enumerate(lines[start:stop])
                        ),
                    }
                )
                if len(hits) >= cap:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break

    return {
        "ok": True,
        "output_dir": str(root),
        "pattern": pattern,
        "is_regex": bool(is_regex),
        "case_sensitive": bool(case_sensitive),
        "scanned_files": scanned_files,
        "skipped_large_files": skipped_large,
        "hit_count": len(hits),
        "truncated": truncated,
        "hits": hits,
        "hint": (
            "命中多了就收窄 pattern，或配合 read_source 读命中行附近的内容；"
            "接口类线索可试 pattern='/api/|/sys/|request\\(|http'，"
            "凭据类可试 'token|secret|sign|key'。"
        ),
    }


def scan_output(
    output_dir: str | os.PathLike[str],
    *,
    rules: Iterable[dict] | None = None,
    max_samples_per_rule: int = DEFAULT_SCAN_SAMPLES_PER_RULE,
    top_files: int = DEFAULT_SCAN_TOP_FILES,
    extensions: Iterable[str] | None = None,
) -> dict:
    """按预设规则**全量扫描**产物目录，返回「每条规则的命中计数 + 有限样本」。

    与 `search_in_output` 的分工（两者互补，不能互相替代）：

    * `search_source` —— **定向**：你已经有一个假设（比如「找 sign 的实现」），去验证它在哪。
    * `scan_source`   —— **全量**：你**还没有**假设，要先一次拿到「这个包里有什么」。

    规则集默认取 `regex_rules.presets.DEFAULT_REGEX_RULES`（27 条：身份证 / 手机号 /
    邮箱 / IPv4 / 域名 / URL 接口 / 路径接口 / 静态资源 / JWT / Bearer / Basic /
    敏感字段赋值 / 硬编码账号密码 / 私钥块 / 云厂商 AK / Google / GitHub / GitLab /
    Stripe / Twilio / Mailgun / 微信标识 / Webhook / OSS / 地图 Key / 加密算法调用），
    与 GUI 侧详情页用的是同一套 —— 避免「MCP 侧要自己写脚本」这种双轨。

    **返回体量受控**：规则在整棵源码树上的命中动辄上千条，逐条回传必然撑爆返回体，
    所以只回**计数 + 每条规则前 `max_samples_per_rule` 条样本**，
    并另给 `top_files`（命中最密集的文件）作为下一步 `read_source` 的入口。
    命中总量由 `total_match_count` 如实给出，**不会被样本上限掩盖**；
    `rules_without_match` 显式列出「跑过但没命中」的规则 ——
    这样调用方能分清「没扫」和「扫了没有」。
    """
    root = Path(output_dir).expanduser()
    if not root.is_dir():
        return {"ok": False, "error": f"产物目录不存在：{root}"}

    rule_list = [item for item in (rules or []) if isinstance(item, dict)] or copy_default_regex_rules()
    scanner = RegexContentScanner(rule_list)
    if not scanner.rules:
        return {
            "ok": False,
            "error": "规则集为空或全部正则无效。",
            "hint": "不传 rules 时用内置预设（copy_default_regex_rules）。",
        }

    sample_cap = min(
        max(int(max_samples_per_rule or DEFAULT_SCAN_SAMPLES_PER_RULE), 1),
        MAX_SCAN_SAMPLES_PER_RULE,
    )
    file_cap = min(max(int(top_files or DEFAULT_SCAN_TOP_FILES), 1), MAX_SCAN_TOP_FILES)
    allowed = {ext.lower() for ext in extensions} if extensions else TEXT_EXTENSIONS

    counts: dict[str, int] = {str(rule["name"]): 0 for rule in scanner.rules}
    samples: dict[str, list[dict]] = {str(rule["name"]): [] for rule in scanner.rules}
    matched_files: dict[str, set[str]] = {str(rule["name"]): set() for rule in scanner.rules}
    file_counts: dict[str, int] = {}

    scanned_files = 0
    skipped_large = 0
    skipped_binary = 0
    for path in scanner.discover_files([root]):
        if path.suffix.lower() not in allowed or path.name in SKIP_FILE_NAMES:
            continue
        try:
            if path.stat().st_size > SEARCH_MAX_FILE_BYTES:
                skipped_large += 1
                continue
        except OSError:
            continue
        # 用扫描器自己的二进制判定，避免两处实现漂移；
        # 单独计数是为了让 `scanned_files` 只反映「真正参与匹配的文本文件」，
        # 否则被跳过的二进制会把覆盖率报大（覆盖率报大 = 让人以为扫过）。
        try:
            with open(path, "rb") as probe_handle:
                probe_bytes = probe_handle.read(4096)
        except OSError:
            continue
        if scanner.looks_binary(probe_bytes):
            skipped_binary += 1
            continue
        try:
            matches = scanner.scan_file(path)
        except OSError:
            continue
        scanned_files += 1
        if not matches:
            continue
        relative = path.relative_to(root).as_posix()
        for match in matches:
            name = str(match.get("rule_name") or "")
            if name not in counts:
                continue
            counts[name] += 1
            matched_files[name].add(relative)
            file_counts[relative] = file_counts.get(relative, 0) + 1
            bucket = samples[name]
            if len(bucket) < sample_cap:
                bucket.append(
                    {
                        "path": relative,
                        "line": int(match.get("line_number") or 0),
                        "match": str(match.get("match_text") or "")[:300],
                    }
                )

    notes = {str(rule["name"]): str(rule.get("note") or "") for rule in scanner.rules}
    matched = [
        {
            "name": name,
            "match_count": counts[name],
            "matched_files": len(matched_files[name]),
            "note": notes.get(name, ""),
            "samples": samples[name],
            "samples_truncated": counts[name] > len(samples[name]),
        }
        for name in counts
        if counts[name] > 0
    ]
    matched.sort(key=lambda item: (-item["match_count"], item["name"]))
    empty_rules = sorted(name for name, value in counts.items() if value == 0)
    top = sorted(file_counts.items(), key=lambda item: (-item[1], item[0]))[:file_cap]

    return {
        "ok": True,
        "output_dir": str(root),
        "rule_count": len(scanner.rules),
        "scanned_files": scanned_files,
        "skipped_large_files": skipped_large,
        "skipped_binary_files": skipped_binary,
        "total_match_count": sum(counts.values()),
        "matched_rule_count": len(matched),
        "max_samples_per_rule": sample_cap,
        "rules": matched,
        "rules_without_match": empty_rules,
        "top_files": [{"path": name, "match_count": value} for name, value in top],
        "hint": (
            "本结果只是**线索清单**，命中需人工核对："
            "① `路径`/`URL 接口`/`域名` 这类规则命中量大且含大量静态资源噪声，优先看 `top_files`；"
            "② 样本被 `samples_truncated=true` 截断时，用 "
            "search_source(pattern=...) 或 read_source 在具体文件里展开；"
            "③ 想只看某几类，可传 rules=[{name, pattern}] 覆盖预设。"
        ),
    }

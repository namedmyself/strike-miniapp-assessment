#!/usr/bin/env python3
"""
Sync WMPF offset configs for the latest installed runtime version.

Reads the locally installed RadiumWMPF runtime, extracts offsets from flue.dll,
and writes the resulting addresses.<version>.json into both config directories
used by this project:

1. WMPFDebugger/frida/config
2. e0e1-wx/tools/config/win

布局说明（重要）
----------------
flue.dll 有两套结构，JSON 字段不同，写错会让 hook 崩溃：

* legacy —— LoadStart / CDP / SceneOffsets(6)
* modern —— LoadStart / CDP / CastToJson + MiniAppConfigStructOffsets
  （25xxx 中后期起，例如 25707 / 25715）

本脚本优先调用 extract_wmpf_offsets_modern.py（上游 WMPFDebugger
frida/autodetect/win32.js 的离线移植），它会自行判定布局并带内部一致性断言；
只有当该文件缺失时才回落到只认 legacy 的 extract_wmpf_offsets.py。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent

# RadiumWMPF 根目录候选（APPDATA 在部分环境里不存在，必须有兜底）
RADIUM_SUBPATH = ("Tencent", "xwechat", "xplugin", "Plugins", "RadiumWMPF")
DEFAULT_TARGET_DIRS = (
    PROJECT_ROOT / "WMPFDebugger" / "frida" / "config",
    PROJECT_ROOT / "e0e1-wx" / "tools" / "config" / "win",
)


def _safe_home() -> Path | None:
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return None


def wmpf_root_candidates() -> list[Path]:
    roots: list[Path] = []

    override = os.environ.get("WMPF_ROOT")
    if override:
        roots.append(Path(override))

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

    for base in bases:
        roots.append(base.joinpath(*RADIUM_SUBPATH))

    xwechat = os.environ.get("XWECHAT_HOME")
    if xwechat:
        roots.append(Path(xwechat) / "xplugin" / "Plugins" / "RadiumWMPF")

    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def default_wmpf_root() -> Path:
    """优先返回实际存在的候选，避免默认值指向不存在的路径。"""
    candidates = wmpf_root_candidates()
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def load_extractor():
    """返回 (extract 函数, 描述)。优先 modern 检测器。"""
    modern_path = HERE / "extract_wmpf_offsets_modern.py"
    if modern_path.is_file():
        spec = importlib.util.spec_from_file_location("wmpf_extract_modern", modern_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module.extract, "modern+legacy 自动判定"
    from extract_wmpf_offsets import extract as legacy_extract  # type: ignore

    return legacy_extract, "legacy only（未找到 modern 检测器）"


def iter_installed(root: Path) -> list[tuple[int, Path]]:
    """列出 root 下所有可用运行时（版本号 + flue.dll 路径）。"""
    found: list[tuple[int, Path]] = []
    if not root.is_dir():
        return found
    for child in root.iterdir():
        if not child.is_dir():
            continue
        try:
            version = int(child.name)
        except ValueError:
            continue
        dll_path = child / "extracted" / "runtime" / "flue.dll"
        if dll_path.is_file():
            found.append((version, dll_path))
    return found


def detect_latest_version(root: Path) -> tuple[int, Path]:
    candidates = iter_installed(root)
    if not candidates:
        raise FileNotFoundError(
            f"No usable flue.dll found under: {root}\n"
            f"可用 --wmpf-root 指定 RadiumWMPF 根目录，或 --dll 直接给出 flue.dll"
        )
    return max(candidates, key=lambda item: item[0])


def resolve_version_and_dll(
    version: int | None,
    dll_path: Path | None,
    wmpf_root: Path,
) -> tuple[int, Path]:
    if dll_path is not None:
        if version is not None:
            return version, dll_path
        for parent in dll_path.parents:
            try:
                return int(parent.name), dll_path
            except ValueError:
                continue
        raise ValueError(
            "--version is required when --dll does not contain a numeric version directory"
        )

    if version is not None:
        return version, wmpf_root / str(version) / "extracted" / "runtime" / "flue.dll"

    return detect_latest_version(wmpf_root)


def describe(result: dict) -> str:
    if "SceneOffsets" in result:
        return (f"legacy  SceneOffsets={result['SceneOffsets']}  "
                f"LoadStart={result['LoadStartHookOffset']}  "
                f"CDP={result['CDPFilterHookOffset']}")
    struct_offsets = result["MiniAppConfigStructOffsets"]
    return (f"modern  LoadStart={result['LoadStartHookOffset']}  "
            f"CDP={result['CDPFilterHookOffset']}  "
            f"CastToJson={result['CastToJsonHookOffset']}\n"
            f"        LaunchConfig={struct_offsets['LaunchConfigOffsets']}  "
            f"RemoteDebug={struct_offsets['RemoteDebugConfigOffsets']}  "
            f"Scene={struct_offsets['SceneOffset']}  "
            f"WS={struct_offsets['WebSocketURLStringOffset']}  "
            f"Mode={struct_offsets['RemoteDebugModeOffset']}")


def format_config(config: dict) -> str:
    """短数字数组保持单行，与仓库既有 JSON 风格一致。"""
    def arr(values) -> str:
        return "[" + ", ".join(str(v) for v in values) + "]"

    lines = [
        "{",
        f'    "Version": {config["Version"]},',
        f'    "LoadStartHookOffset": "{config["LoadStartHookOffset"]}",',
        f'    "CDPFilterHookOffset": "{config["CDPFilterHookOffset"]}",',
    ]
    if "CastToJsonHookOffset" in config:
        lines.append(f'    "CastToJsonHookOffset": "{config["CastToJsonHookOffset"]}",')
    if "SceneOffsets" in config:
        lines.append(f'    "SceneOffsets": {arr(config["SceneOffsets"])}')
    else:
        struct_offsets = config["MiniAppConfigStructOffsets"]
        lines.append('    "MiniAppConfigStructOffsets": {')
        lines.append(f'        "LaunchConfigOffsets": '
                     f'{arr(struct_offsets["LaunchConfigOffsets"])},')
        lines.append(f'        "RemoteDebugConfigOffsets": '
                     f'{arr(struct_offsets["RemoteDebugConfigOffsets"])},')
        lines.append(f'        "SceneOffset": {struct_offsets["SceneOffset"]},')
        lines.append(f'        "WebSocketURLStringOffset": '
                     f'{struct_offsets["WebSocketURLStringOffset"]},')
        lines.append(f'        "RemoteDebugModeOffset": '
                     f'{struct_offsets["RemoteDebugModeOffset"]}')
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_targets(result: dict, target_dirs: list[Path], force: bool) -> int:
    version = result["Version"]
    payload = format_config(result)

    wrote_any = False
    failures = 0
    for target_dir in target_dirs:
        output_path = target_dir / f"addresses.{version}.json"
        if output_path.exists() and not force:
            print(f"[skip] {output_path}")
            continue
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            print(f"[error] cannot write {output_path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        wrote_any = True
        print(f"[write] {output_path}")

    if not wrote_any and failures == 0:
        print("[done] all target files already existed (use --force to overwrite)")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract offsets from the latest installed WMPF runtime and sync project configs."
    )
    parser.add_argument("--version", type=int, help="Specific WMPF version to extract")
    parser.add_argument("--dll", type=Path, help="Explicit flue.dll path")
    parser.add_argument(
        "--wmpf-root",
        type=Path,
        default=default_wmpf_root(),
        help="Root directory of the locally installed RadiumWMPF versions",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        action="append",
        help="Config directory to write to. Repeat to override the default targets.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing addresses.<version>.json files",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Sync every installed runtime version, not just the newest one",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print detection internals (string anchors, pointer chains)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target_dirs = args.target_dir or list(DEFAULT_TARGET_DIRS)

    try:
        extract, engine = load_extractor()
    except ImportError as exc:
        print(f"[error] missing dependency: {exc}", file=sys.stderr)
        print("        pip install pefile capstone", file=sys.stderr)
        return 1

    print(f"[info] extraction engine: {engine}")

    try:
        if args.all and args.dll is None:
            installed = iter_installed(args.wmpf_root)
            if not installed:
                raise FileNotFoundError(f"No usable flue.dll found under: {args.wmpf_root}")
            targets = sorted(installed, key=lambda item: item[0])
        else:
            targets = [resolve_version_and_dll(args.version, args.dll, args.wmpf_root)]
    except (FileNotFoundError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    failures = 0
    for version, dll_path in targets:
        if not dll_path.is_file():
            print(f"[error] flue.dll not found: {dll_path}", file=sys.stderr)
            failures += 1
            continue

        print(f"[info] version={version}")
        print(f"[info] dll={dll_path}")
        try:
            result = extract(version, dll_path, args.verbose)
        except Exception as exc:  # noqa: BLE001 - 需要把失败原因完整透出
            print(f"[error] extraction failed for {version}: {exc}", file=sys.stderr)
            print("        flue.dll 结构可能又变了：用 -v 看中间量，"
                  "并参考 SKILL.md 的布局判定章节人工核对。", file=sys.stderr)
            failures += 1
            continue

        print(f"[info] layout: {describe(result)}")
        failures += write_targets(result, target_dirs, args.force)

    if failures:
        return 1
    print("[done] offset sync completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

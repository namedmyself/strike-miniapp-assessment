#!/usr/bin/env python3
"""
macOS WeChatAppEx Framework offset helper for addresses.<version>.json

Modes:
  1) prepare (default, no IDA): detect version, lipo ARM64 slice, write draft JSON
  2) idalib: open ARM64 binary in IDAPython/idalib and extract 5 offsets

Usage:
  python extract_macos_offsets.py
  python extract_macos_offsets.py --prepare-only
  python extract_macos_offsets.py --idalib --binary ./WeChatAppEx_Framework_arm64
  python extract_macos_offsets.py --idalib --write --config-dir path/to/frida/config/macos
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


APP_CANDIDATES = [
    Path("/Applications/微信.app"),
    Path("/Applications/WeChat.app"),
]


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def find_wechat_app() -> Path:
    for p in APP_CANDIDATES:
        if p.is_dir():
            return p
    die("WeChat.app not found under /Applications (微信.app / WeChat.app)")


def read_bundle_version(app: Path) -> str:
    info = app / "Contents" / "Info.plist"
    for key in ("WeChatBundleVersion", "CFBundleShortVersionString"):
        r = subprocess.run(
            ["/usr/bin/plutil", "-extract", key, "raw", "-o", "-", str(info)],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    die(f"cannot read version from {info}")


def framework_path(app: Path) -> Path:
    fw = (
        app
        / "Contents/MacOS/WeChatAppEx.app/Contents/Frameworks"
        / "WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework"
    )
    if not fw.is_file():
        die(f"Framework missing: {fw}")
    return fw


def thin_arm64(src: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    info = subprocess.run(["/usr/bin/file", str(src)], capture_output=True, text=True)
    out = info.stdout
    if "arm64" in out and "x86_64" in out:
        subprocess.run(
            ["/usr/bin/lipo", "-thin", "arm64", str(src), "-output", str(dest)],
            check=True,
        )
        print(f"[prepare] lipo arm64 → {dest}")
    else:
        shutil.copy2(src, dest)
        print(f"[prepare] copied → {dest}")
    return dest


def draft_json(version: str) -> dict:
    return {
        "Version": version,
        "ModuleName": "WeChatAppEx Framework",
        "CDPFilterHookOffset": "0x0",
        "SceneHookOffset": "0x0",
        "SceneOffsets": [8, 0, 16, 456],
        "LoadStartHookOffset": "0x0",
        "ResourceCachePolicyHookOffset": "0x0",
    }


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"[write] {path}")


def prepare(work: Path) -> tuple[str, Path]:
    app = find_wechat_app()
    version = read_bundle_version(app)
    fw = framework_path(app)
    print(f"[prepare] app={app}")
    print(f"[prepare] version={version}")
    print(f"[prepare] framework={fw}")
    arm = thin_arm64(fw, work / f"WeChatAppEx_Framework_arm64_{version}")
    draft = work / f"addresses.{version}.draft.json"
    write_json(draft, draft_json(version))
    print(
        """
[prepare] Next:
  1) Open the ARM64 binary in IDA (Hex-Rays), OR
  2) python extract_macos_offsets.py --idalib --binary <arm64-path> --write \\
       --config-dir <nebula-tauri/frida/config/macos>

Locate offsets (see SKILL.md §B / reference-macos.md):
  LoadStart  ← OnLoadStart / applet_index_container.cc
  SceneHook  ← OnLoadStart tail: if ((_DWORD)a2) return unk_...
  SceneOffsets ← chain ending with == 1101
  CDP        ← SendToClientFilter parent → filter callee (v[2]!=6)
  Resource   ← WAPCAdapterAppIndex.js first xref
"""
    )
    return version, arm


# ── idalib extraction ─────────────────────────────────────────────────


def _ida_find_string_ea(needle: bytes) -> list[int]:
    import ida_bytes
    import ida_ida
    import idautils

    text = needle.decode("utf-8", "ignore")
    hits: list[int] = []
    for s in idautils.Strings():
        try:
            t = str(s)
        except Exception:
            continue
        if text in t:
            hits.append(int(s.ea))
    if hits:
        return hits

    # Fallback: raw byte search (IDA 9+)
    try:
        start = ida_ida.inf_get_min_ea()
        end = ida_ida.inf_get_max_ea()
    except Exception:
        return hits

    ea = start
    while True:
        ea = ida_bytes.find_bytes(needle, ea, end)
        if ea is None or ea == ida_bytes.BADADDR or ea == -1:
            break
        hits.append(int(ea))
        ea = int(ea) + 1
    return hits


def _ida_xrefs_to(ea: int) -> list[int]:
    import idautils

    return [int(x.frm) for x in idautils.XrefsTo(ea)]


def _ida_func_start(ea: int) -> int | None:
    import ida_funcs

    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None


def _ida_decompile(ea: int) -> str:
    try:
        import ida_hexrays

        if not ida_hexrays.init_hexrays_plugin():
            return ""
        c = ida_hexrays.decompile(ea)
        return str(c) if c else ""
    except Exception as e:
        print(f"[idalib] decompile 0x{ea:x} failed: {e}", file=sys.stderr)
        return ""


def extract_with_idalib(binary: Path) -> dict:
    try:
        import idapro
    except ImportError:
        die("idalib not available. Activate IDA idalib / pip install into IDA Python, then retry.")

    print(f"[idalib] opening {binary} ...")
    idapro.open_database(str(binary), True)

    try:
        import ida_auto
        import ida_idaapi
        import ida_nalt

        ida_auto.auto_wait()
        imagebase = int(ida_nalt.get_imagebase())
        print(f"[idalib] imagebase=0x{imagebase:x}")

        def off(ea: int) -> str:
            return hex(ea - imagebase)

        # LoadStart
        load_eas = _ida_find_string_ea(b"AppletIndexContainer::OnLoadStart")
        if not load_eas:
            load_eas = _ida_find_string_ea(b"applet_index_container.cc")
        load_start = None
        for sea in load_eas:
            for xref in _ida_xrefs_to(sea):
                fs = _ida_func_start(xref)
                if not fs:
                    continue
                src = _ida_decompile(fs)
                if "applet_index_container" in src or "OnLoadStart" in src or not src:
                    # Prefer larger OnLoadStart (not tiny log stubs)
                    if load_start is None or fs < load_start:
                        # keep first reasonable; refine by size later
                        load_start = fs
                    # Prefer function that also references applet path
                    if "applet_index_container.cc" in src:
                        load_start = fs
                        break
            if load_start and "applet_index_container" in (_ida_decompile(load_start) or ""):
                break
        if load_start is None and load_eas:
            # last resort: first xref function
            for sea in load_eas:
                xrefs = _ida_xrefs_to(sea)
                if xrefs:
                    load_start = _ida_func_start(xrefs[0])
                    if load_start:
                        break
        if load_start is None:
            die("[idalib] LoadStart not found")

        print(f"[idalib] LoadStart=0x{load_start:x} ({off(load_start)})")
        load_src = _ida_decompile(load_start)

        # SceneHook: unk_ in `if ((_DWORD)a2) return unk_...`
        scene_hook = None
        m = re.search(
            r"if\s*\(\s*\(_DWORD\)\s*a2\s*\)\s*(?:return\s+)?((?:sub_|unk_|loc_)?[A-Fa-f0-9]+)\s*\(",
            load_src,
        )
        if not m:
            m = re.search(
                r"if\s*\(\s*\(int\)\s*a2\s*\)\s*(?:return\s+)?((?:sub_|unk_)?[A-Fa-f0-9]+)\s*\(",
                load_src,
            )
        if m:
            token = m.group(1)
            # HexRays may print as unk_8444BD0 or just address in call
            hm = re.search(r"([A-Fa-f0-9]{5,})$", token)
            if hm:
                scene_hook = int(hm.group(1), 16)
        if scene_hook is None:
            # Fallback: last call target mentioned near end of function text
            calls = re.findall(r"\b(?:sub_|unk_)([0-9A-Fa-f]+)\s*\(", load_src)
            if calls:
                scene_hook = int(calls[-1], 16)
        if scene_hook is None:
            die("[idalib] SceneHook not found — fill manually from OnLoadStart decompile")

        print(f"[idalib] SceneHook=0x{scene_hook:x} ({off(scene_hook)})")
        scene_src = _ida_decompile(scene_hook)

        # SceneOffsets: pointer chain ending with == 1101 / 0x44D
        scene_offsets = [8, 0, 16, 456]
        # Heuristic: collect +N offsets before 1101 / 0x44D compare
        if "1101" in scene_src or "0x44D" in scene_src or "0x44d" in scene_src:
            # Match patterns like v = *(a1 + 8); *(v + 1440); *(v + 16); == 1101 at +456
            nums = [
                int(x, 0)
                for x in re.findall(
                    r"\+\s*(0x[0-9A-Fa-f]+|\d+)",
                    scene_src.split("1101")[0]
                    if "1101" in scene_src
                    else scene_src.split("0x44D")[0]
                    if "0x44D" in scene_src
                    else scene_src,
                )
            ]
            # Keep last 4 plausible member offsets
            cand = [n for n in nums if 0 < n < 0x2000]
            if len(cand) >= 4:
                scene_offsets = cand[-4:]
            print(f"[idalib] SceneOffsets candidates={cand} → {scene_offsets}")

        # Resource: WAPCAdapterAppIndex.js
        res_eas = _ida_find_string_ea(b"WAPCAdapterAppIndex.js")
        resource = None
        for sea in res_eas:
            for xref in _ida_xrefs_to(sea):
                fs = _ida_func_start(xref)
                if fs:
                    resource = fs
                    break
            if resource:
                break
        if resource is None:
            die("[idalib] ResourceCache not found")
        print(f"[idalib] Resource=0x{resource:x} ({off(resource)})")

        # CDP: SendToClientFilter → parent → callee used with [2] != 6
        cdp_eas = _ida_find_string_ea(b"SendToClientFilter")
        cdp = None
        parent = None
        for sea in cdp_eas:
            for xref in _ida_xrefs_to(sea):
                parent = _ida_func_start(xref)
                if parent:
                    break
            if parent:
                break
        if parent is None:
            die("[idalib] CDP parent (SendToClientFilter xref) not found")
        parent_src = _ida_decompile(parent)
        # Look for call assigned then [2] != 6
        m = re.search(
            r"=\s*\([^\)]*\)\s*((?:sub_|unk_)?[0-9A-Fa-f]+)\s*\([^\)]*\).*?\[\s*2\s*\]\s*!=\s*6",
            parent_src,
            re.S,
        )
        if not m:
            m = re.search(
                r"((?:sub_|unk_)[0-9A-Fa-f]+)\s*\([^\)]*\).*?\[\s*2\s*\]\s*!=\s*6",
                parent_src,
                re.S,
            )
        if m:
            hm = re.search(r"([0-9A-Fa-f]{5,})$", m.group(1))
            if hm:
                cdp = int(hm.group(1), 16)
        if cdp is None:
            # Fallback: first large callee in parent (not tiny)
            callees = re.findall(r"\b(?:sub_|unk_)([0-9A-Fa-f]+)\s*\(", parent_src)
            for c in callees:
                ea = int(c, 16)
                if ea != parent and ea > 0x100000:
                    cdp = ea
                    break
        if cdp is None:
            die("[idalib] CDP filter callee not found — fill manually (v[2]!=6)")
        print(f"[idalib] CDP=0x{cdp:x} ({off(cdp)}) parent=0x{parent:x}")

        # Version from CLI later
        result = {
            "Version": "UNKNOWN",
            "ModuleName": "WeChatAppEx Framework",
            "CDPFilterHookOffset": off(cdp),
            "SceneHookOffset": off(scene_hook),
            "SceneOffsets": scene_offsets,
            "LoadStartHookOffset": off(load_start),
            "ResourceCachePolicyHookOffset": off(resource),
        }
        return result
    finally:
        try:
            import idapro

            idapro.close_database()
        except Exception:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description="macOS WeChatAppEx Framework offset helper")
    ap.add_argument("--work", type=Path, default=Path(".ida-work-macos"), help="work directory")
    ap.add_argument("--prepare-only", action="store_true", help="only lipo + draft JSON")
    ap.add_argument("--idalib", action="store_true", help="run IDA/idalib extraction")
    ap.add_argument("--binary", type=Path, help="ARM64 Framework path for --idalib")
    ap.add_argument("--version", type=str, help="override WeChatBundleVersion")
    ap.add_argument("--output", type=Path, help="write JSON path")
    ap.add_argument("--write", action="store_true", help="write into --config-dir")
    ap.add_argument(
        "--config-dir",
        type=Path,
        help="e.g. nebula-tauri/frida/config/macos",
    )
    args = ap.parse_args()

    if sys.platform != "darwin" and not args.idalib:
        print("warning: prepare paths assume macOS host", file=sys.stderr)

    args.work.mkdir(parents=True, exist_ok=True)
    version = args.version
    binary = args.binary

    if not args.idalib or binary is None:
        ver, arm = prepare(args.work)
        version = version or ver
        binary = binary or arm
        if args.prepare_only or not args.idalib:
            return

    assert binary is not None
    result = extract_with_idalib(binary)
    if not version:
        # try detect again
        try:
            version = read_bundle_version(find_wechat_app())
        except SystemExit:
            version = "UNKNOWN"
    result["Version"] = version

    print(json.dumps(result, indent=2))

    out = args.output
    if args.write:
        if not args.config_dir:
            die("--write requires --config-dir")
        out = args.config_dir / f"addresses.{version}.json"
    if out:
        for k in (
            "CDPFilterHookOffset",
            "SceneHookOffset",
            "LoadStartHookOffset",
            "ResourceCachePolicyHookOffset",
        ):
            result[k] = "0x" + format(int(str(result[k]), 16), "X")
        write_json(out, result)
        print(
            "\n[note] Always manually verify SceneOffsets / CDP in Hex-Rays before shipping.\n"
            "Inject also needs: csrutil disable + scripts/macos/resign-wechatappex.sh"
        )


if __name__ == "__main__":
    main()

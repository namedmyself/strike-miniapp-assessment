#!/usr/bin/env python3
"""
Extract WMPF flue.dll Frida offsets for addresses.{version}.json — MODERN builds.

This is an offline (static) port of WMPFDebugger's own runtime detector,
`frida/autodetect/win32.js`. It runs the exact same algorithm — the same string
anchors, the same backward register-slice data-flow recovery, and the same
internal consistency assertions — against a flue.dll sitting on disk, so you do
not need a running WeChat, a live Frida session, or IDA.

Why this exists
---------------
`extract_wmpf_offsets.py` (the legacy script) only knows the *legacy* layout and
emits `SceneOffsets: [..6 numbers..]`. WMPF builds from roughly the 25xxx series
onwards use the *modern* layout instead: the scene / remote-debug-mode guard is
inlined into `AppletIndexContainer::OnLoadStart`, and hook.js expects
`MiniAppConfigStructOffsets` + `CastToJsonHookOffset`. Feeding a legacy JSON to a
modern build makes hook.js take the legacy branch and crash.

How the layout is chosen (identical to upstream)
------------------------------------------------
If all of `devtools_message_filter_applet_webview.cc`, `CastToJson`,
`devtools_message_filter.cc`, ` request.url=` and `create webview devtools
failed.` are present, the modern detector runs; otherwise the legacy one.

Usage
-----
  python extract_wmpf_offsets_modern.py --version 25707
  python extract_wmpf_offsets_modern.py --version 25707 --dll path/to/flue.dll
  python extract_wmpf_offsets_modern.py --version 25707 --write \
      --config-dir path/to/WMPFDebugger/frida/config/win32

Dependencies: pip install pefile capstone
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

try:
    import pefile
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except ImportError:
    print("Missing deps: pip install pefile capstone", file=sys.stderr)
    sys.exit(1)

DEFAULT_DLL = (
    Path.home()
    / "AppData/Roaming/Tencent/xwechat/xplugin/Plugins/RadiumWMPF/{version}"
    / "extracted/runtime/flue.dll"
)

# String anchors used by frida/autodetect/win32.js
ANCHOR_LOAD_FILE = b"applet_index_container.cc"
ANCHOR_LOAD_NAME = b"AppletIndexContainer::OnLoadStart(bool"
ANCHOR_FILTER_NAME = b"SendToClientFilter"
ANCHOR_FILTER_FILE = b"devtools_message_filter_applet_webview.cc"
ANCHOR_CAST_NAME = b"CastToJson"
ANCHOR_CAST_FILE = b"devtools_message_filter.cc"
ANCHOR_START_URL = b" request.url="
ANCHOR_START_FAILURE = b"create webview devtools failed."

WRITES_DST0 = {
    "mov", "movabs", "movzx", "movsx", "movsxd", "lea", "add", "sub", "xor",
    "or", "and", "imul", "shl", "shr", "sar", "sal", "inc", "dec", "neg",
    "not", "pop", "bswap", "xchg", "adc", "sbb", "mul", "div", "idiv",
}

REG_ALIASES: dict[str, str] = {}
for _full, _names in {
    "rax": ["rax", "eax", "ax", "al", "ah"],
    "rbx": ["rbx", "ebx", "bx", "bl", "bh"],
    "rcx": ["rcx", "ecx", "cx", "cl", "ch"],
    "rdx": ["rdx", "edx", "dx", "dl", "dh"],
    "rsi": ["rsi", "esi", "si", "sil"],
    "rdi": ["rdi", "edi", "di", "dil"],
    "rbp": ["rbp", "ebp", "bp", "bpl"],
    "rsp": ["rsp", "esp", "sp", "spl"],
}.items():
    for _n in _names:
        REG_ALIASES[_n] = _full
for _i in range(8, 16):
    for _s in ("", "d", "w", "b"):
        REG_ALIASES[f"r{_i}{_s}"] = f"r{_i}"

ARGUMENT_REGISTERS = {"rcx": 0, "rdx": 1, "r8": 2, "r9": 3}
VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}

LEA_RE = re.compile(rb"[\x48\x4c]\x8d")
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


class Insn:
    __slots__ = ("rva", "mnemonic", "op_str", "operands", "size")

    def __init__(self, rva, mnemonic, op_str, operands, size):
        self.rva = rva
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.operands = operands
        self.size = size


def canonical_register(name):
    if not isinstance(name, str):
        return None
    return REG_ALIASES.get(name.lower())


def to_hex(value: int) -> str:
    return "0x" + format(value, "x")


class FlueImage:
    """A PE mapped into a flat virtual image, mirroring Frida's module view."""

    def __init__(self, path: Path):
        self.path = path
        self.pe = pefile.PE(str(path), fast_load=True)
        self.pe.parse_data_directories()
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.image = bytearray(self.size)
        self.sections = []
        for sec in self.pe.sections:
            name = sec.Name.rstrip(b"\x00").decode(errors="replace")
            va = sec.VirtualAddress
            vsize = sec.Misc_VirtualSize
            raw = sec.SizeOfRawData
            ptr = sec.PointerToRawData
            count = min(raw, vsize) if vsize else raw
            if count and ptr:
                self.image[va:va + count] = self.pe.__data__[ptr:ptr + count]
            self.sections.append({
                "name": name, "va": va, "vsize": vsize,
                "exec": bool(sec.Characteristics & 0x20000000),
            })
        self.functions = self._load_functions()

    # ---- .pdata ----
    def _load_functions(self):
        sec = next((s for s in self.sections if s["name"] == ".pdata"), None)
        if sec is None:
            raise RuntimeError(".pdata section not found")
        blob = bytes(self.image[sec["va"]:sec["va"] + sec["vsize"]])
        by_start: dict[int, int] = {}
        for off in range(0, len(blob) - 11, 12):
            begin, end, _unwind = struct.unpack_from("<III", blob, off)
            if begin == 0 or begin >= end or end > self.size:
                continue
            prev = by_start.get(begin)
            if prev is None or end > prev:
                by_start[begin] = end
        fns = sorted(by_start.items())
        if not fns:
            raise RuntimeError("no functions found in .pdata")
        return fns

    def find_function(self, address):
        lo, hi = 0, len(self.functions) - 1
        while lo <= hi:
            mid = (lo + hi) >> 1
            begin, end = self.functions[mid]
            if address < begin:
                hi = mid - 1
            elif address >= end:
                lo = mid + 1
            else:
                return (begin, end)
        return None

    def require_function(self, address, name):
        entry = self.find_function(address)
        if entry is None:
            raise RuntimeError(f"{name}: function boundary not found for {to_hex(address)}")
        return entry

    # ---- strings ----
    def _string_matches(self, value: bytes):
        out = []
        for sec in self.sections:
            if sec["name"] in (".text", ".pdata") or sec["vsize"] <= 0:
                continue
            base = sec["va"]
            blob = bytes(self.image[base:base + sec["vsize"]])
            start = 0
            while True:
                idx = blob.find(value, start)
                if idx < 0:
                    break
                out.append({"rva": base + idx, "section": sec})
                start = idx + 1
        return out

    def exact_ranges(self, value: bytes, required=True):
        matches = self._string_matches(value)
        if required and not matches:
            raise RuntimeError(f"string not found: {value!r}")
        return [{"start": m["rva"], "end": m["rva"]} for m in matches]

    def containing_ranges(self, value: bytes, required=True):
        matches = self._string_matches(value)
        if required and not matches:
            raise RuntimeError(f"string not found: {value!r}")
        out = []
        for m in matches:
            sec = m["section"]
            start = m["rva"]
            for _ in range(4096):
                if start <= sec["va"] or self.image[start - 1] == 0:
                    break
                start -= 1
            out.append({"start": start, "end": m["rva"] + len(value) - 1})
        return out

    def build_string_targets(self):
        return {
            "loadFile": self.containing_ranges(ANCHOR_LOAD_FILE),
            "loadName": self.containing_ranges(ANCHOR_LOAD_NAME),
            "filterName": self.exact_ranges(ANCHOR_FILTER_NAME),
            "filterFile": self.containing_ranges(ANCHOR_FILTER_FILE, False),
            "castName": self.exact_ranges(ANCHOR_CAST_NAME, False),
            "castFile": self.containing_ranges(ANCHOR_CAST_FILE, False),
            "startUrl": self.exact_ranges(ANCHOR_START_URL, False),
            "startFailure": self.exact_ranges(ANCHOR_START_FAILURE, False),
        }

    def find_xref_functions(self, targets):
        results = {k: set() for k in targets}
        for sec in self.sections:
            if not sec["exec"]:
                continue
            base = sec["va"]
            blob = bytes(self.image[base:base + sec["vsize"]])
            for m in LEA_RE.finditer(blob):
                i = m.start()
                if i + 7 > len(blob) or (blob[i + 2] & 0xC7) != 0x05:
                    continue
                instr_off = base + i
                target = instr_off + 7 + struct.unpack_from("<i", blob, i + 3)[0]
                owner = self.find_function(instr_off)
                if owner is None:
                    continue
                for name, ranges in targets.items():
                    if any(r["start"] <= target <= r["end"] for r in ranges):
                        results[name].add(owner[0])
        return results

    # ---- disassembly ----
    def disassemble(self, entry, maximum_size=None):
        begin, end = entry
        limit = begin + min(end - begin, end - begin if maximum_size is None else maximum_size)
        out = []
        off = begin
        while off < limit:
            decoded = None
            for ins in MD.disasm(bytes(self.image[off:off + 16]), self.base + off):
                decoded = ins
                break
            if decoded is None or decoded.size <= 0 or off + decoded.size > limit:
                break
            operands = []
            for op in decoded.operands:
                if op.type == X86_OP_REG:
                    operands.append({"type": "reg", "value": decoded.reg_name(op.reg),
                                     "size": op.size})
                elif op.type == X86_OP_MEM:
                    operands.append({
                        "type": "mem",
                        "value": {
                            "base": decoded.reg_name(op.mem.base) if op.mem.base else None,
                            "index": decoded.reg_name(op.mem.index) if op.mem.index else None,
                            "disp": op.mem.disp,
                        },
                        "size": op.size,
                    })
                elif op.type == X86_OP_IMM:
                    operands.append({"type": "imm", "value": op.imm, "size": op.size})
                else:
                    operands.append({"type": "other", "value": None, "size": 0})
            out.append(Insn(off, decoded.mnemonic, decoded.op_str, operands, decoded.size))
            off += decoded.size
        return out


# ---------------- operand helpers ----------------
def reg_operand(insn, index):
    if index < len(insn.operands) and insn.operands[index]["type"] == "reg":
        return insn.operands[index]
    return None


def mem_operand(insn, index):
    if index < len(insn.operands) and insn.operands[index]["type"] == "mem":
        return insn.operands[index]
    return None


def imm_operand(insn, index):
    if index < len(insn.operands) and insn.operands[index]["type"] == "imm":
        return insn.operands[index]
    return None


def has_index(memory):
    if not memory or not memory.get("value"):
        return False
    return memory["value"].get("index") is not None


def memory_displacement(memory):
    if memory is None or memory.get("value") is None:
        return None
    return int(memory["value"]["disp"])


def arg_expr(index):
    return {"kind": "arg", "index": index}


def const_expr(value):
    return {"kind": "constant", "value": value}


def load_expr(base, offset):
    return {"kind": "load", "base": base, "offset": offset}


def add_expr(base, offset):
    if offset == 0:
        return base
    if base["kind"] == "add":
        return {"kind": "add", "base": base["base"], "offset": base["offset"] + offset}
    return {"kind": "add", "base": base, "offset": offset}


def expr_key(expr):
    if expr is None:
        return "unknown"
    if expr["kind"] == "arg":
        return f"arg{expr['index']}"
    if expr["kind"] == "constant":
        return f"constant:{expr['value']}"
    return f"{expr['kind']}({expr_key(expr['base'])},{expr['offset']})"


def resolve_register(instructions, before_index, requested, depth=0):
    register = canonical_register(requested)
    if register is None or depth > 48:
        return None
    for index in range(before_index - 1, -1, -1):
        insn = instructions[index]
        if insn.mnemonic == "call" and register in VOLATILE:
            return None
        dest = reg_operand(insn, 0)
        if (dest is None or canonical_register(dest["value"]) != register
                or insn.mnemonic not in WRITES_DST0):
            continue
        src_reg = reg_operand(insn, 1)
        src_mem = mem_operand(insn, 1)
        src_imm = imm_operand(insn, 1)

        if insn.mnemonic in ("mov", "movabs"):
            if src_reg is not None:
                return resolve_register(instructions, index, src_reg["value"], depth + 1)
            if src_mem is not None and src_mem["size"] == 8 and not has_index(src_mem):
                base_reg = canonical_register(src_mem["value"]["base"])
                disp = memory_displacement(src_mem)
                if base_reg is None or disp is None:
                    return None
                base = resolve_register(instructions, index, base_reg, depth + 1)
                return None if base is None else load_expr(base, disp)
            if src_imm is not None:
                return const_expr(int(src_imm["value"]))
            return None

        if insn.mnemonic == "lea" and src_mem is not None:
            if has_index(src_mem):
                return None
            base_reg = canonical_register(src_mem["value"]["base"])
            disp = memory_displacement(src_mem)
            if base_reg is None or disp is None:
                return None
            base = resolve_register(instructions, index, base_reg, depth + 1)
            return None if base is None else add_expr(base, disp)

        if insn.mnemonic in ("add", "sub") and src_imm is not None:
            value = int(src_imm["value"])
            base = resolve_register(instructions, index, register, depth + 1)
            if base is None:
                return None
            return add_expr(base, -value if insn.mnemonic == "sub" else value)

        return None

    arg_index = ARGUMENT_REGISTERS.get(register)
    return None if arg_index is None else arg_expr(arg_index)


def unwrap_load_chain(expr):
    if expr is None:
        return None
    if expr["kind"] == "arg":
        return {"argumentIndex": expr["index"], "offsets": []}
    if expr["kind"] != "load":
        return None
    parent = unwrap_load_chain(expr["base"])
    if parent is None:
        return None
    parent["offsets"].append(expr["offset"])
    return parent


def direct_call_target(image, insn):
    if insn.mnemonic != "call":
        return None
    immediate = imm_operand(insn, 0)
    target = int(immediate["value"]) if immediate is not None else None
    if target is None:
        m = re.match(r"^(0x[0-9a-f]+)$", insn.op_str, re.I)
        if m:
            target = int(m.group(1), 16)
    if target is None or target < image.base or target >= image.base + image.size:
        return None
    return target - image.base


def comparison_memory_and_immediate(insn):
    if insn.mnemonic != "cmp":
        return None
    left_mem, right_mem = mem_operand(insn, 0), mem_operand(insn, 1)
    left_imm, right_imm = imm_operand(insn, 0), imm_operand(insn, 1)
    memory = left_mem if left_mem is not None else right_mem
    immediate = right_imm if right_imm is not None else left_imm
    if memory is None or immediate is None or has_index(memory):
        return None
    displacement = memory_displacement(memory)
    base_register = canonical_register(memory["value"]["base"])
    if displacement is None or base_register is None:
        return None
    return {"memory": memory, "immediate": int(immediate["value"]),
            "displacement": displacement, "baseRegister": base_register}


def recover_remote_guard(instructions, name):
    comparisons = []
    for index, insn in enumerate(instructions):
        cmp_ = comparison_memory_and_immediate(insn)
        if cmp_ is None or cmp_["immediate"] not in (1101, 1):
            continue
        base = resolve_register(instructions, index, cmp_["baseRegister"])
        chain = unwrap_load_chain(base)
        if base is None or chain is None or chain["argumentIndex"] != 0:
            continue
        comparisons.append({
            "immediate": cmp_["immediate"], "fieldOffset": cmp_["displacement"],
            "baseKey": expr_key(base), "rootOffsets": chain["offsets"],
        })
    candidates = []
    for scene in [c for c in comparisons if c["immediate"] == 1101]:
        for mode in [c for c in comparisons
                     if c["immediate"] == 1 and c["baseKey"] == scene["baseKey"]]:
            candidates.append({"rootOffsets": scene["rootOffsets"],
                               "sceneOffset": scene["fieldOffset"],
                               "modeOffset": mode["fieldOffset"]})
    unique = {}
    for c in candidates:
        key = f"{':'.join(map(str, c['rootOffsets']))}:{c['sceneOffset']}:{c['modeOffset']}"
        unique[key] = c
    if len(unique) != 1:
        raise RuntimeError(f"{name}: expected one scene/mode guard, found {len(unique)}")
    return list(unique.values())[0]


def recover_call_argument_chain(image, instructions, target, name):
    candidates = []
    for index, insn in enumerate(instructions):
        if direct_call_target(image, insn) != target:
            continue
        chain = unwrap_load_chain(resolve_register(instructions, index, "rcx"))
        if chain is not None and chain["argumentIndex"] == 0:
            candidates.append(chain["offsets"])
    unique = {':'.join(map(str, o)): o for o in candidates}
    if len(unique) != 1:
        raise RuntimeError(f"{name}: expected one call argument chain, found {len(unique)}")
    return list(unique.values())[0]


def memory_accesses(instructions):
    accesses = []
    for index, insn in enumerate(instructions):
        for operand in insn.operands:
            if operand["type"] != "mem" or has_index(operand):
                continue
            base_register = canonical_register(operand["value"]["base"])
            displacement = memory_displacement(operand)
            if base_register is None or displacement is None:
                continue
            base = resolve_register(instructions, index, base_register)
            if base is not None:
                accesses.append({"index": index, "operand": operand, "base": base,
                                 "baseKey": expr_key(base), "displacement": displacement})
    return accesses


def recover_websocket_url_offset(instructions, launch_expression):
    launch_key = expr_key(launch_expression)
    accesses = [a for a in memory_accesses(instructions) if a["baseKey"] == launch_key]
    launch_displacements = {a["displacement"] for a in accesses}
    candidates = []
    for insn in instructions:
        cmp_ = comparison_memory_and_immediate(insn)
        if cmp_ is None or cmp_["immediate"] != 0 or cmp_["memory"]["size"] != 1:
            continue
        string_offset = cmp_["displacement"] - 23
        if string_offset < 0:
            continue
        same_base = any(
            a["displacement"] in (string_offset, string_offset + 8)
            and canonical_register(a["operand"]["value"]["base"]) == cmp_["baseRegister"]
            for a in accesses
        )
        if (same_base and string_offset in launch_displacements
                and (string_offset + 8) in launch_displacements):
            candidates.append(string_offset)
    unique = set(candidates)
    if len(unique) != 1:
        raise RuntimeError(f"websocket URL string: expected one offset, found {len(unique)}")
    return list(unique)[0]


def assert_pointer_offsets(name, offsets):
    if not offsets or any(not isinstance(o, int) or o < 0 or o > 0x10000 or o % 8
                          for o in offsets):
        raise RuntimeError(f"{name}: implausible pointer chain {offsets}")


def assert_field_offset(name, offset, alignment):
    if not isinstance(offset, int) or offset < 0 or offset > 0x10000 or offset % alignment:
        raise RuntimeError(f"{name}: implausible field offset {offset}")


def contains_direct_call(image, instructions, target):
    return any(direct_call_target(image, i) == target for i in instructions)


def validate_cast_to_json_abi(instructions):
    input_offsets = {a["displacement"] for a in memory_accesses(instructions)
                     if a["baseKey"] == expr_key(arg_expr(1))}
    if 0 not in input_offsets or 8 not in input_offsets:
        raise RuntimeError("CastToJson candidate does not read the input pointer/length pair")


def intersect(*sets):
    if not sets:
        return set()
    return {v for v in sets[0] if all(v in s for s in sets)}


def require_unique(name, values):
    candidates = sorted(values)
    if len(candidates) != 1:
        raise RuntimeError(
            f"{name}: expected one function, found {len(candidates)}"
            + (f" ({', '.join(to_hex(c) for c in candidates)})" if candidates else "")
        )
    return candidates[0]


# ---------------- detection ----------------
def detect_modern(image, xrefs, load_start, verbose=False):
    start_offset = require_unique(
        "DevToolsWebSocketServer::Start",
        intersect(xrefs["startUrl"], xrefs["startFailure"]))
    filter_offset = require_unique(
        "applet-webview SendToClientFilter",
        intersect(xrefs["filterName"], xrefs["filterFile"]))
    cast_offset = require_unique(
        "CastToJson", intersect(xrefs["castName"], xrefs["castFile"]))

    start = image.require_function(start_offset, "DevToolsWebSocketServer::Start")
    filt = image.require_function(filter_offset, "SendToClientFilter")
    cast = image.require_function(cast_offset, "CastToJson")

    load_insns = image.disassemble(load_start)
    start_insns = image.disassemble(start, 0x1200)
    filter_insns = image.disassemble(filt)
    cast_prefix = image.disassemble(cast, 0x100)

    server_chain = recover_call_argument_chain(
        image, load_insns, start[0], "OnLoadStart -> DevToolsWebSocketServer::Start")
    load_guard = recover_remote_guard(load_insns, "OnLoadStart")
    start_guard = recover_remote_guard(start_insns, "DevToolsWebSocketServer::Start")

    if verbose:
        print(f"# start={to_hex(start[0])} filter={to_hex(filt[0])} cast={to_hex(cast[0])}")
        print(f"# serverChain={server_chain}")
        print(f"# loadGuard={load_guard}")
        print(f"# startGuard={start_guard}")

    assert_pointer_offsets("server pointer chain", server_chain)
    assert_pointer_offsets("OnLoadStart remote config chain", load_guard["rootOffsets"])
    assert_pointer_offsets("Start remote config chain", start_guard["rootOffsets"])
    if (len(server_chain) != 2 or len(load_guard["rootOffsets"]) != 3
            or len(start_guard["rootOffsets"]) != 3):
        raise RuntimeError("unexpected modern WMPF pointer-chain depth")
    if server_chain[0] != load_guard["rootOffsets"][0]:
        raise RuntimeError("OnLoadStart server and remote-config roots disagree")
    if load_guard["rootOffsets"][1:] != start_guard["rootOffsets"][1:]:
        raise RuntimeError("OnLoadStart and Start remote-config chains disagree")
    if (load_guard["sceneOffset"] != start_guard["sceneOffset"]
            or load_guard["modeOffset"] != start_guard["modeOffset"]):
        raise RuntimeError("OnLoadStart and Start remote-debug fields disagree")

    launch_expression = load_expr(arg_expr(0), start_guard["rootOffsets"][0])
    ws_offset = recover_websocket_url_offset(start_insns, launch_expression)
    assert_field_offset("scene", start_guard["sceneOffset"], 4)
    assert_field_offset("remote debug mode", start_guard["modeOffset"], 4)
    assert_field_offset("websocket URL string", ws_offset, 8)

    if not contains_direct_call(image, filter_insns, cast[0]):
        raise RuntimeError("SendToClientFilter does not call the detected CastToJson")
    validate_cast_to_json_abi(cast_prefix)

    return {
        "LoadStartHookOffset": to_hex(load_start[0]),
        "CDPFilterHookOffset": to_hex(filt[0]),
        "CastToJsonHookOffset": to_hex(cast[0]),
        "MiniAppConfigStructOffsets": {
            "LaunchConfigOffsets": list(server_chain) + [start_guard["rootOffsets"][0]],
            "RemoteDebugConfigOffsets": start_guard["rootOffsets"][1:],
            "SceneOffset": start_guard["sceneOffset"],
            "WebSocketURLStringOffset": ws_offset,
            "RemoteDebugModeOffset": start_guard["modeOffset"],
        },
    }


def find_legacy_scene_path(image, load_start):
    instructions = image.disassemble(load_start)
    candidates = []
    for index, insn in enumerate(instructions):
        target = direct_call_target(image, insn)
        if target is None:
            continue
        call_chain = unwrap_load_chain(resolve_register(instructions, index, "rcx"))
        if (call_chain is None or call_chain["argumentIndex"] != 0
                or len(call_chain["offsets"]) != 2):
            continue
        callee = image.find_function(target)
        if callee is None:
            continue
        try:
            guard = recover_remote_guard(image.disassemble(callee, 0x500),
                                         f"legacy scene helper {to_hex(callee[0])}")
            if len(guard["rootOffsets"]) == 3:
                candidates.append({"callChain": call_chain["offsets"], "guard": guard})
        except RuntimeError:
            pass
    unique = {}
    for c in candidates:
        key = (f"{':'.join(map(str, c['callChain']))}:"
               f"{':'.join(map(str, c['guard']['rootOffsets']))}:{c['guard']['sceneOffset']}")
        unique[key] = c
    if len(unique) != 1:
        raise RuntimeError(f"legacy scene path: expected one candidate, found {len(unique)}")
    return list(unique.values())[0]


def detect_legacy(image, xrefs, load_start):
    filter_owner = image.require_function(
        require_unique("SendToClientFilter", xrefs["filterName"]),
        "SendToClientFilter owner")
    scene_path = find_legacy_scene_path(image, load_start)
    scene_offsets = (list(scene_path["callChain"])
                     + list(scene_path["guard"]["rootOffsets"])
                     + [scene_path["guard"]["sceneOffset"]])
    assert_pointer_offsets("legacy launch pointer chain", scene_path["callChain"])
    assert_pointer_offsets("legacy remote config chain", scene_path["guard"]["rootOffsets"])
    assert_field_offset("legacy scene", scene_path["guard"]["sceneOffset"], 4)
    first_call = None
    for insn in image.disassemble(filter_owner, 0x600):
        first_call = direct_call_target(image, insn)
        if first_call is not None:
            break
    if first_call is None:
        raise RuntimeError(f"no direct call found in function {to_hex(filter_owner[0])}")
    return {
        "LoadStartHookOffset": to_hex(load_start[0]),
        "CDPFilterHookOffset": to_hex(first_call),
        "SceneOffsets": scene_offsets,
    }


def extract(version: int, dll_path: Path, verbose=False) -> dict:
    if not dll_path.is_file():
        raise FileNotFoundError(f"flue.dll not found: {dll_path}")
    image = FlueImage(dll_path)
    xrefs = image.find_xref_functions(image.build_string_targets())

    load_start = image.require_function(
        require_unique("AppletIndexContainer::OnLoadStart",
                       intersect(xrefs["loadFile"], xrefs["loadName"])),
        "AppletIndexContainer::OnLoadStart")
    if verbose:
        print(f"# imagebase={to_hex(image.base)} size={to_hex(image.size)} "
              f"functions={len(image.functions)}")
        print(f"# OnLoadStart={to_hex(load_start[0])}..{to_hex(load_start[1])}")
        for name in sorted(xrefs):
            print(f"# xref[{name}]={{{', '.join(to_hex(x) for x in sorted(xrefs[name]))}}}")

    modern_anchors = all(len(xrefs[k]) != 0 for k in
                         ("filterFile", "castName", "castFile", "startUrl", "startFailure"))
    if verbose:
        print(f"# modernAnchorsPresent={modern_anchors}")

    if modern_anchors:
        try:
            return {"Version": version, **detect_modern(image, xrefs, load_start, verbose)}
        except RuntimeError as exc:
            if verbose:
                print(f"# detectModern failed: {exc}", file=sys.stderr)
            if len(xrefs["filterName"]) != 1:
                raise RuntimeError(f"modern WMPF layout validation failed: {exc}") from exc
    return {"Version": version, **detect_legacy(image, xrefs, load_start)}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract WMPF flue.dll Frida offsets (modern + legacy layouts)")
    parser.add_argument("--version", type=int, required=True, help="WMPF version number")
    parser.add_argument("--dll", type=Path, help="Path to flue.dll")
    parser.add_argument("--output", "-o", type=Path, help="Write JSON to this file")
    parser.add_argument("--write", action="store_true",
                        help="Write addresses.{version}.json (use with --config-dir)")
    parser.add_argument("--config-dir", type=Path, action="append",
                        help="Config directory for --write (repeatable)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print intermediate detection details")
    args = parser.parse_args()

    dll = args.dll or Path(str(DEFAULT_DLL).format(version=args.version))
    result = extract(args.version, dll, args.verbose)

    text = json.dumps(result, indent=4) + "\n"
    print(text)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)

    if args.write:
        for directory in (args.config_dir or [Path("frida/config/win32")]):
            out = directory / f"addresses.{args.version}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"Wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()

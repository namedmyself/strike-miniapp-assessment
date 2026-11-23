#!/usr/bin/env python3
"""离线验证：`02-一键启动.bat` 的「WMPFDebugger 要不要跳过」判据（2026-09-23 事故回归）。

只读、不连 CDP、不启动任何进程：`wechatappex_frida_injected` / `list_node_processes` /
`doctor.run_command` / `ADMIN_LOG` / `ADMIN_PID` 全部换成桩与临时路径。
**不会碰真实的 WMPFDebugger 日志和 pid 文件。**

要钉住的回归点（第 [3] 组）—— 旧判据是：

    if admin_log_looks_recent() and count_processes("node") > 0: return True   # 跳过

这两个条件在真机上都极易误命中，于是 `02` 报「先跳过重复启动」然后**什么都不做**：
WMPFDebugger 从未被拉起 → 无 Frida 注入 → 小程序不回连 9421 → DevTools 一片空白。
所以最关键的一条断言是：**「有个新日志 + 机器上有别的 node 进程」绝不能再导致跳过。**
"""

from __future__ import annotations

import csv
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import project_doctor as doctor  # noqa: E402
import start_full_chain as sfc  # noqa: E402

PASSED = 0
FAILED = 0

# 真机实测的两条「无关 node」命令行（WorkBuddy 自己的 MCP 插件服务）
UNRELATED_CMDS = [
    r"node C:\Users\testuser\.workbuddy\plugins\cache\workbuddy-builtin\sheetagent\5.6.2\mcp\start.mjs",
    '"C:\\Users\\testuser\\.workbuddy\\binaries\\node\\versions\\22.22.2-3\\node.exe" '
    '"C:\\Users\\testuser\\.workbuddy\\plugins\\cache\\workbuddy-builtin\\weixinpay\\1.6.110\\dist'
    '\\mcp-server.mjs"',
]
WMPF_CMD = r"node  -r ts-node/register src/index.ts"

SUCCESS_LOG = (
    "[2026-09-23 00:02:04] Starting elevated WMPFDebugger\n"
    "[frida] found 12 WeChatAppEx.exe processes\n"
    "[frida] Detected WMPF version: 25707\n"
    "[frida] script loaded, WMPF version: 25707, pid: 27744\n"
    "[frida] you can now open any miniapps\n"
)
FAIL_LOG = "[frida] Unable to access process with pid 1234\n"

# 真机 `tasklist /m /fi "imagename eq WeChatAppEx.exe" /FO CSV /NH` 的**原始形态**：
# ⚠️ 加了 `/m` 且 `/FO CSV /NH` 时只有 **3 列** —— `ImageName,PID,Modules`（不是常见的 6 列！
# 这一点实测校正过：第一版夹具按 6 列编写，结果**测的是一个不存在的输出格式**）。
# 注入成功时只有被 hook 的那一个进程多出 `frida-agent.dll`（12 个实例里只有 1 个）。
REAL_TASKLIST_OK = "\n".join([
    '"WeChatAppEx.exe","27744","ntdll.dll,KERNEL32.DLL,KERNELBASE.dll,USER32.dll,frida-agent.dll,WS2_32.dll"',
    '"WeChatAppEx.exe","27612","ntdll.dll,KERNEL32.DLL,KERNELBASE.dll,USER32.dll,xweb_elf.dll"',
    '"WeChatAppEx.exe","11112","ntdll.dll,KERNEL32.DLL,KERNELBASE.dll,USER32.dll"',
])
REAL_TASKLIST_NONE = "\n".join([
    '"WeChatAppEx.exe","27612","ntdll.dll,KERNEL32.DLL,USER32.dll,xweb_elf.dll"',
    '"WeChatAppEx.exe","11112","ntdll.dll,KERNEL32.DLL,USER32.dll"',
])
REAL_TASKLIST_INFO = "INFO: No tasks are running which match the specified criteria."


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  [PASS] {label}")
    else:
        FAILED += 1
        print(f"  [FAIL] {label}")
    if detail:
        print(f"         {detail}")


def setup(tmp: Path, *, node_procs: list[tuple[int, str]], alive: set[int],
          admin_log_text: str | None, admin_pid: int | None, launch_log_text: str | None,
          frida_pids: list[str]):
    """把模块全局换成临时路径 + 桩，返回记录调用次数的 state。"""
    tmp.mkdir(parents=True, exist_ok=True)
    log = tmp / "wmpfdebugger-admin.log"
    pidf = tmp / "wmpfdebugger-admin.pid"
    if admin_log_text is not None:
        log.write_text(admin_log_text, encoding="utf-8")
    if admin_pid is not None:
        pidf.write_text(str(admin_pid), encoding="ascii")

    sfc.ADMIN_LOG = log
    sfc.ADMIN_PID = pidf
    state = {"launch_calls": 0, "node_count_calls": 0}

    def fake_list_node_processes():
        return [{"pid": str(p), "exe": "", "commandLine": cmd} for p, cmd in node_procs]

    def fake_run_command(cmd, cwd=None):
        joined = " ".join(str(c) for c in cmd)
        if "Get-Process -Id" in joined:
            m = re.search(r"Get-Process -Id (\d+)", joined)
            pid = int(m.group(1)) if m else -1
            return (0, "alive") if pid in alive else (1, "")
        if "Get-Process -Name 'node'" in joined:
            state["node_count_calls"] += 1
            return (0, str(len(node_procs)))
        if "launch-wmpfdebugger-admin.ps1" in joined:
            state["launch_calls"] += 1
            if launch_log_text is not None:
                log.write_text(launch_log_text, encoding="utf-8")
            return (0, "Started elevated WMPFDebugger helper.")
        return (0, "")

    sfc.list_node_processes = fake_list_node_processes
    sfc.wechatappex_frida_injected = lambda: (bool(frida_pids), list(frida_pids))
    doctor.run_command = fake_run_command
    return state


def test_parsers() -> None:
    print("\n[1] 两个识别器的纯函数层（用真机原始输出）")
    check("tasklist 解析：注入成功时只挑出 1 个 pid",
          sfc._frida_pids_from_tasklist_csv(REAL_TASKLIST_OK) == ["27744"],
          f"{sfc._frida_pids_from_tasklist_csv(REAL_TASKLIST_OK)}")
    check("tasklist 解析：无 frida 时返回空",
          sfc._frida_pids_from_tasklist_csv(REAL_TASKLIST_NONE) == [])
    check("tasklist 解析：无匹配任务（INFO 行）不炸且返回空",
          sfc._frida_pids_from_tasklist_csv(REAL_TASKLIST_INFO) == [])
    check("夹具列数与真机一致（ImageName,PID,Modules 共 3 列）",
          all(len(row) == 3 for row in csv.reader(REAL_TASKLIST_OK.splitlines())),
          "拉错列=测了个不存在的输出格式（第一版就这么错过）")

    for cmd, expect in (
        (WMPF_CMD, True),
        (r"node -r ts-node\register src\index.ts", True),
        (r"node C:\x\WMPFDebugger\src\index.ts", True),
        (UNRELATED_CMDS[0], False),
        (UNRELATED_CMDS[1], False),
        ("node -v", False),
        ("", False),
    ):
        got = bool(sfc.WMPFDEBUGGER_CMD_RE.search(cmd))
        check(f"命令行特征 {'命中' if expect else '不命中'}: {cmd[:48] or '(空)'}", got is expect)


def test_gate(tmp: Path) -> None:
    print("\n[2] pid 文件还活着 → 跳过（不重复注入）")
    state = setup(tmp / "a", node_procs=[(100, WMPF_CMD)], alive={4242},
                  admin_log_text=None, admin_pid=4242, launch_log_text=None, frida_pids=[])
    result = sfc.ensure_wmpfdebugger(skip=False)
    check("返回 True", result is True)
    check("没有调用注入助手", state["launch_calls"] == 0, f"{state}")

    print("\n[3] ★ 回归：新日志 + 有无关 node 进程 + 无 frida 注入 —— 绝不能再跳过（本次事故）")
    state = setup(tmp / "b", node_procs=[(1, UNRELATED_CMDS[0]), (2, UNRELATED_CMDS[1])],
                  alive=set(), admin_log_text=SUCCESS_LOG, admin_pid=None,
                  launch_log_text=SUCCESS_LOG, frida_pids=[])
    check("前置条件：admin_log_looks_recent() == True（旧判据的两个条件都成立）",
          sfc.admin_log_looks_recent() is True)
    result = sfc.ensure_wmpfdebugger(skip=False)
    check("仍然真的去注入了（旧逻辑在这里会 return True 什么都不做）",
          state["launch_calls"] == 1, f"launch_calls={state['launch_calls']}")
    check("返回 True（注入助手报成功）", result is True)

    print("\n[4] ★ 已有 WeChatAppEx 加载 frida → 跳过（这才是「注入还活着」的判据）")
    state = setup(tmp / "g", node_procs=[], alive=set(), admin_log_text=None, admin_pid=None,
                  launch_log_text=None, frida_pids=["27744"])
    result = sfc.ensure_wmpfdebugger(skip=False)
    check("返回 True", result is True)
    check("没有重复注入", state["launch_calls"] == 0, f"{state}")

    print("\n[5] pid 文件已死（陈旧）→ 清掉并重新注入")
    state = setup(tmp / "c", node_procs=[], alive=set(), admin_log_text=None, admin_pid=999999,
                  launch_log_text=SUCCESS_LOG, frida_pids=[])
    result = sfc.ensure_wmpfdebugger(skip=False)
    check("调用了一次注入助手", state["launch_calls"] == 1, f"{state}")
    check("陈旧 pid 文件已被删除", not (tmp / "c" / "wmpfdebugger-admin.pid").exists())
    check("返回 True", result is True)

    print("\n[6] 有 WMPFDebugger 进程残留、但无 frida → 仍然注入（并给 WARN）")
    state = setup(tmp / "d", node_procs=[(777, WMPF_CMD)], alive=set(), admin_log_text=None,
                  admin_pid=None, launch_log_text=SUCCESS_LOG, frida_pids=[])
    result = sfc.ensure_wmpfdebugger(skip=False)
    check("返回 True", result is True)
    check("仍然注入了（注入失效时不能靠进程残留跳过）", state["launch_calls"] == 1, f"{state}")

    print("\n[7] 注入助手报失败信号 → 返回 False（不能假绿）")
    state = setup(tmp / "e", node_procs=[], alive=set(), admin_log_text=None, admin_pid=None,
                  launch_log_text=FAIL_LOG, frida_pids=[])
    result = sfc.ensure_wmpfdebugger(skip=False)
    check("返回 False", result is False)
    check("确实调用了注入助手", state["launch_calls"] == 1)

    print("\n[8] --skip-wmpf 显式跳过仍然有效")
    state = setup(tmp / "f", node_procs=[], alive=set(), admin_log_text=None, admin_pid=None,
                  launch_log_text=None, frida_pids=[])
    check("skip=True → True 且不注入",
          sfc.ensure_wmpfdebugger(skip=True) is True and state["launch_calls"] == 0)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="verify_start_gate_"))
    original = (sfc.ADMIN_LOG, sfc.ADMIN_PID, doctor.run_command,
                sfc.list_node_processes, sfc.wechatappex_frida_injected)
    try:
        test_parsers()
        test_gate(tmp)
    finally:
        (sfc.ADMIN_LOG, sfc.ADMIN_PID, doctor.run_command,
         sfc.list_node_processes, sfc.wechatappex_frida_injected) = original
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("=" * 78)
    print(f"结果：{PASSED} passed / {FAILED} failed")
    print("=" * 78)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

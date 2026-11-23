# -*- coding: utf-8 -*-
"""无窗启动 WMPFDebugger Frida 注入器（尝试非提权，当前用户若已是管理员则可注入）。"""
import subprocess
from pathlib import Path
# 自动定位项目根（tools/web-console/injector.py -> parents[2] = 项目根）
ROOT = Path(__file__).resolve().parents[2]
WMPF = ROOT / "WMPFDebugger"
NODE = ROOT / ".runtime" / "node20" / "node.exe"
LOG = WMPF / "logs" / "inject-console.log"
LOG.parent.mkdir(parents=True, exist_ok=True)
BASE = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
BREAKAWAY = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0)
FLAGS = [BASE | BREAKAWAY | DETACHED, BASE | BREAKAWAY, BASE | DETACHED, BASE]
lf = open(str(LOG), "a", encoding="utf-8")
cmd = [str(NODE), "-r", "ts-node/register", "src/index.ts", "--debug-frida"]
for fl in FLAGS:
    try:
        p = subprocess.Popen(cmd, cwd=str(WMPF), creationflags=fl,
                             stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT,
                             close_fds=True)
        print("launched node injector pid=", p.pid)
        break
    except OSError:
        continue

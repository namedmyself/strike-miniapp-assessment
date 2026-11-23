# -*- coding: utf-8 -*-
"""CDP 控制面板后端（标准库 http.server，零依赖）。
- 精确 PID 文件管理：启动只记录自己起的 PID，停止只杀这些 PID，绝不误伤。
- 所有子进程 pythonw + CREATE_NO_WINDOW，物理上不弹窗。
- 提供 /api/start /api/stop /api/status /api/exit，供前端控制。
- Web 服务自身可点"退出服务"干净关闭。
"""
import json, socket, subprocess, os, sys, time, threading
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# 自动定位项目根（tools/web-console/server.py -> parents[2] = 项目根）
PANEL_DIR = Path(__file__).resolve().parent
ROOT = PANEL_DIR.parents[1]
PYW = ROOT / ".venv" / "Scripts" / "pythonw.exe"
ENGINE = ROOT / "e0e1-wx" / "start_engine.py"
MCP = ROOT / "e0e1-wx" / "start_mcp_server.py"
PID_ENGINE = PANEL_DIR / ".pid_engine"
PID_MCP = PANEL_DIR / ".pid_mcp"
PID_WEB = PANEL_DIR / ".pid_web"
LOG = PANEL_DIR / "panel.log"
WEB_PORT = int(os.environ.get("PANEL_PORT", "47821"))  # 冷门端口，避开代理/安全软件常见劫持段

BASE = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
BREAKAWAY = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0)
FLAGS = [BASE | BREAKAWAY | DETACHED, BASE | BREAKAWAY, BASE | DETACHED, BASE]

def log(m):
    try:
        with LOG.open("a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {m}\n")
    except Exception: pass

def port_open(p):
    s = socket.socket(); s.settimeout(.3)
    try: s.connect(("127.0.0.1", int(p))); return True
    except Exception: return False
    finally: s.close()

def pid_alive(pid):
    try:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True,
                             creationflags=BASE, timeout=5).stdout
        return str(pid) in out
    except Exception: return False

def save_pid(path, pid):
    try: path.write_text(str(pid))
    except Exception: pass

def read_pid(path):
    try: return int(path.read_text().strip())
    except Exception: return None

def spawn(script, pidfile):
    """启动一个子进程，记录其真实 PID。"""
    for fl in FLAGS:
        try:
            p = subprocess.Popen([str(PYW), str(script)], cwd=str(ROOT), creationflags=fl,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
            save_pid(pidfile, p.pid)
            log(f"spawned {script.name} pid={p.pid}")
            return p.pid
        except OSError: continue
    log(f"FAILED spawn {script.name}"); return None

def stop_pid(pidfile, port):
    """按 PID 精确停止；若 PID 文件丢失则按端口找 PID 兜底。"""
    pid = read_pid(pidfile)
    stopped = []
    if pid and pid_alive(pid):
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True,
                           creationflags=BASE, timeout=10)
            stopped.append(pid); log(f"killed pid={pid}")
        except Exception as e: log(f"kill fail {pid}: {str(e)[:60]}")
    # 兜底：端口仍占用且 PID 文件无效时，按端口定位（仅针对我们管的端口）
    if port_open(port):
        try:
            out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                                 creationflags=BASE, timeout=10).stdout
            for line in out.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    cand = int(line.strip().split()[-1])
                    if cand and cand != os.getpid() and cand not in stopped:
                        # 只处理我们管的关键端口：端口在 9421/62000/49999 上监听的，
                        # 且进程名是 python/pythonw 的，一定是我们的 CDP 脚本（这些端口无别人用）。
                        # 用 tasklist 取进程名，不依赖 wmic（新系统已移除）或 PowerShell。
                        tl = subprocess.run(["tasklist", "/FI", f"PID eq {cand}"], capture_output=True,
                                            text=True, creationflags=BASE, timeout=8).stdout
                        if "python.exe" in tl.lower() or "pythonw.exe" in tl.lower():
                            subprocess.run(["taskkill", "/PID", str(cand), "/F"],
                                           capture_output=True, creationflags=BASE, timeout=10)
                            stopped.append(cand); log(f"killed by-port pid={cand}")
        except Exception as e: log(f"by-port fail: {str(e)[:60]}")
    try: pidfile.unlink()
    except Exception: pass
    return stopped

def status():
    e_pid, m_pid = read_pid(PID_ENGINE), read_pid(PID_MCP)
    e_ports = port_open(9421) and port_open(62000)
    m_port = port_open(49999)
    # alive 以端口为准（pythonw 会 fork/exec，记录的 PID 可能是壳进程，pid_alive 会误判）
    # 真正"活着"的定义 = 端口在监听，这才是 CDP 可用的判据
    return {
        "engine": {"port_9421": port_open(9421), "port_62000": port_open(62000),
                   "pid": e_pid, "alive": e_ports},
        "mcp": {"port_49999": m_port, "pid": m_pid, "alive": m_port},
        "cdp_ready": e_ports and m_port,
        "web_pid": os.getpid(),
        "ts": time.strftime("%H:%M:%S"),
    }

def _wait_port(port, timeout=8):
    """等端口就绪，避免启动后立刻又被判 down 重复起。"""
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port): return True
        time.sleep(.3)
    return False

_START_LOCK = threading.Lock()

def do_start():
    res = {"engine": None, "mcp": None}
    with _START_LOCK:  # 进程内串行，杜绝并发双起
        # 引擎：两个端口都监听才算在跑；否则先清掉半死进程再起，避免 10048 端口冲突
        if port_open(9421) and port_open(62000):
            res["engine"] = "already running"
        else:
            # 若只有一个端口通(半死状态)，先按端口清掉残留，再干净启动
            if port_open(9421) or port_open(62000):
                log("engine half-alive -> cleanup before restart")
                stop_pid(PID_ENGINE, 9421)
                time.sleep(1)
            res["engine"] = spawn(ENGINE, PID_ENGINE)
            if res["engine"]: _wait_port(9421)
        # MCP 同理
        if port_open(49999):
            res["mcp"] = "already running"
        else:
            res["mcp"] = spawn(MCP, PID_MCP)
            if res["mcp"]: _wait_port(49999)
    return res

def do_stop():
    return {"engine": stop_pid(PID_ENGINE, 9421), "mcp": stop_pid(PID_MCP, 49999)}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # 不打访问日志，避免刷屏

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path, ctype):
        try:
            data = Path(path).read_bytes()
        except Exception:
            self._json({"error": "not found"}, 404); return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            self._file(PANEL_DIR / "index.html", "text/html; charset=utf-8")
        elif p == "/api/status":
            self._json(status())
        elif p == "/api/log":
            try: lines = LOG.read_text(encoding="utf-8").splitlines()[-50:]
            except Exception: lines = []
            self._json({"lines": lines})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        p = self.path.split("?")[0]
        if p == "/api/start":
            self._json({"ok": True, "result": do_start()})
        elif p == "/api/stop":
            self._json({"ok": True, "result": do_stop()})
        elif p == "/api/exit":
            self._json({"ok": True, "msg": "exiting"})
            def _exit():
                time.sleep(0.5)
                do_stop()
                os._exit(0)
            threading.Thread(target=_exit, daemon=True).start()
        else:
            self._json({"error": "not found"}, 404)

if __name__ == "__main__":
    # 单实例：靠 bind 原子抢占，谁先绑上端口谁就是主实例，失败方立即退出。
    # 不用 port_open 预检查（检查与 bind 之间有时间窗，会制造"双实例"竞态）。
    ThreadingHTTPServer.allow_reuse_address = False
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", WEB_PORT), Handler)
    except OSError:
        sys.exit(0)  # 端口已被占，安静退出，不写日志、不残留
    save_pid(PID_WEB, os.getpid())
    log(f"web panel started pid={os.getpid()} port={WEB_PORT}")
    try:
        srv.serve_forever()
    finally:
        try: PID_WEB.unlink()
        except Exception: pass

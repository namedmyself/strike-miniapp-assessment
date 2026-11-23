# -*- coding: utf-8 -*-
"""端口守护 v3: 规则1进程不退出。
保护: 端口持续down>=30s才重启; 若CDP上已有小程序target则不重启引擎(避免冲掉用户连接)。
"""
import socket,time,subprocess,sys,json,urllib.request
ROOT=r'.'
ARTEX=r'%USERPROFILE%\.workbuddy\skills\artex\scripts\artex_wsl.py'
PORTS=[9421,62000,49999,8787]
def up(p):
    s=socket.socket();s.settimeout(.4)
    try:s.connect(('127.0.0.1',p));return True
    except:return False
    finally:s.close()
def cdp_has_target():
    # 快速探测62000上是否有page target(轻量)
    try:
        import urllib.request
        req=urllib.request.Request('http://127.0.0.1:49999/mcp?token=CHANGE_ME_SET_STRIKE_MCP_TOKEN')
        # 只看端口活不活; target检测交给ai_probe_agent
        return up(49999)
    except:return False
down_since={}
print('keepalive v3 started',PORTS,flush=True)
for i in range(2880):  # 4h
    for p in PORTS:
        if not up(p):
            down_since.setdefault(p,time.time())
            elapsed=time.time()-down_since[p]
            if elapsed>=30:
                # artex单独处理
                if p==8787:
                    print('restart artex',flush=True)
                    subprocess.run([sys.executable,ARTEX,'start'],capture_output=True,timeout=90)
                else:
                    # wxcdp链路: 若49999活着但9421/62000掉了且CDP有target, 不重启(避免冲掉)
                    if p in (9421,62000) and up(49999):
                        print('skip restart',p,'mcp alive, avoid dropping CDP',flush=True)
                        down_since[p]=time.time()  # 推迟判断
                        continue
                    print('restart full chain (down',p,')',flush=True)
                    subprocess.run([sys.executable,ROOT+r'\scripts\start_full_chain.py','--no-auto-sync'],capture_output=True,timeout=180)
                down_since.pop(p,None)
        else:
            down_since.pop(p,None)
    time.sleep(5)

"""启动 e0e1-wx 的 DebugEngine（debug server 9421 + proxy server 62000，跳过 Frida）。"""
import asyncio
import sys
sys.path.insert(0, '.')

from package.devtools.engine import DebugEngine
from package.devtools.constants import DEBUG_PORT, CDP_PORT_START


class SimpleLogger:
    def info(self, msg): print(f"[INFO] {msg}")
    def error(self, msg): print(f"[ERROR] {msg}")
    def main_debug(self, msg): pass
    def frida_debug(self, msg): pass


class SimpleOptions:
    debug_port = DEBUG_PORT
    cdp_port = CDP_PORT_START
    miniapp_connection_timeout = 10


async def main():
    options = SimpleOptions()
    engine = DebugEngine(options, SimpleLogger())
    await engine.start()
    print(f"[OK] debug server (9421) + proxy server (62000) started")
    print("[OK] Frida injection skipped (delegated to WMPFDebugger)")
    # 保持运行
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        await engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
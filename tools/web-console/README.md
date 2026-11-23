# Web 控制台（可控可停的 CDP 调试链路）

一个零依赖的本地 Web 面板，用来**可控地启动/停止小程序 CDP 调试链路**，替代"只启动不会停、反复弹窗、后台守护拉起多份"的旧做法。

## 解决什么问题

- 旧方案用守护进程每2分钟拉起，导致同一秒起多份 → 端口冲突（Errno 10048）→ 进程崩溃但 UI 显示正常
- 旧方案弹一堆 conhost / wsl 窗口
- 本方案：**一个面板管全生命周期**，启动/停止/退出都点按钮，全程无窗

## 文件

| 文件 | 作用 |
|---|---|
| `server.py` | 标准库 http.server 后端，零依赖。API：`/api/start` `/api/stop` `/api/status` `/api/exit` |
| `index.html` | 单页面板：状态灯、启动/停止/退出按钮、运行日志 |
| `injector.py` | 无窗启动 WMPFDebugger Frida 注入器（当前用户已是管理员时无需提权、不弹 UAC） |
| `run-injector-hidden.bat` | 计划任务用的无窗常驻注入器包装（崩溃自动重注入） |

## 用法

1. 先按主仓库说明安装依赖、启动注入器（`injector.py`）和引擎
2. 启动面板：
   ```
   python tools/web-console/server.py
   ```
   （默认端口 47821，可用环境变量 `PANEL_PORT` 覆盖）
3. 浏览器打开 `http://127.0.0.1:47821/`
4. 点「启动 CDP」→ 打开小程序 → 回对话说"开了"开始评估
5. 测完点「停止 CDP」；彻底不用点「退出服务」

## 设计要点

- 所有子进程 `pythonw` + `CREATE_NO_WINDOW`，物理上不弹窗
- 启动加锁 + 半死状态清理 + 端口就绪等待，杜绝重复起/端口冲突
- 面板单实例：靠 `bind` 原子抢占，重复触发的实例直接退出
- 状态以端口为准，不用 pythonw 壳 PID 误判
- 精确 PID 文件管理：停止只杀自己起的 PID，不误伤其他程序

## 常驻建议

面板/注入器若需跨命令会话存活（不被终端回收），用 Windows 计划任务 `ONLOGON` 触发
`run-injector-hidden.bat`（注入器）；面板本身可用同样方式或 `pythonw server.py` 无窗启动。

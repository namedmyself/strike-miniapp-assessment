@echo off
rem 无窗常驻启动 WMPFDebugger Frida 注入器（由计划任务调用，脱离会话不掉落）
rem 会在 WMPFDebugger 目录执行，src/index.ts 为相对路径
set "ROOT=%~dp0..\.."
set "NODE=%ROOT%\.runtime\node20\node.exe"
if not exist "%NODE%" set "NODE=node"
set "PATH=%ROOT%\.runtime\node20;%PATH%"
cd /d "%ROOT%\WMPFDebugger"
if not exist logs mkdir logs
:loop
"%NODE%" -r ts-node/register src/index.ts --debug-frida >> logs\inject-console.log 2>&1
timeout /t 5 >nul
goto loop

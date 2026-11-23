@echo off
setlocal
title 一键启动

set "ROOT=%~dp0"

rem 定位本项目的 Python（不依赖 PATH —— 见 scripts\find-python.bat 的说明）
call "%ROOT%scripts\find-python.bat"
if not defined PY_RUN_OK goto :no_python

echo ============================================
echo   一键启动
echo   依赖检测 + 版本检测 + 自动更新 + 全部启动
echo ============================================
echo.

rem 全部逻辑在 scripts\start_full_chain.py：
rem   1) 依赖/环境体检（Node、依赖、本机 WMPF 运行时）
rem   2) 偏移配置缺失时自动更新
rem   3) 启动 WMPFDebugger 注入（会弹 UAC，请点“是”）
rem   4) 启动调试引擎（9421 / 62000）
rem   5) 启动 MCP Server（49999）
rem 可选参数：--skip-wmpf / --skip-engine / --skip-mcp / --no-auto-sync
"%PY_EXE%" "%ROOT%scripts\start_full_chain.py" %*
if errorlevel 1 (
    echo.
    echo [提示] 启动未完成。常见原因与处理见 `问题解决.md`。
    echo.
    pause
    exit /b 1
)

echo.
echo 提示：如果小程序是在启动前就打开的，请关掉再重新打开一次。
echo.
pause
exit /b 0

rem ---------------------------------------------------------------------------
rem  未找到可用 Python 的出口（由 scripts\find-python.bat 判定）
rem  只能由上面的 goto 进入，正常流程不会走到这里
rem ---------------------------------------------------------------------------
:no_python
echo [错误] 没有找到可用的 Python 3.10+。
echo        请先双击 `01-安装依赖.bat` —— 它会自动装好项目专用的 Python 环境。
echo.
pause
exit /b 1

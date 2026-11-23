@echo off
setlocal
title 一键停止

set "ROOT=%~dp0"

rem 定位本项目的 Python（不依赖 PATH —— 见 scripts\find-python.bat 的说明）
rem 注意：提权重跑那一轮也会重新定位，所以这里放在参数解析之前。
call "%ROOT%scripts\find-python.bat"
if not defined PY_RUN_OK goto :no_python

rem 参数解析：逐个 shift 精确匹配。
rem 不用 for %%A in (%*) —— 参数里带 ( ) ^& 等字符时 for 会直接解析失败。
rem   --no-elevate  不提权，只关端口
rem   --elevated    内部标记：本次已经是提权后的那一轮，禁止再次提权（防 UAC 死循环）
set "NOELEV="
set "ELEVATED="
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--no-elevate" set "NOELEV=1"
if /i "%~1"=="--elevated" set "ELEVATED=1"
shift
goto :parse_args
:args_done

echo ============================================
echo   一键停止
echo   关闭 9421 / 62000 / 49999 并结束调试链路
echo ============================================
echo.

rem 注入器（WMPFDebugger）是提权启动的，普通权限杀不掉；先判断当前是不是管理员。
rem 想跳过提权、只关端口：05-一键停止.bat --no-elevate
if not defined NOELEV if not defined ELEVATED (
    rem net session 依赖 Server 服务，服务被停时即使提权也会误判，所以再用 fsutil 兜底。
    set "IS_ADMIN="
    net session >nul 2>&1
    if not errorlevel 1 set "IS_ADMIN=1"
    if not defined IS_ADMIN (
        fsutil dirty query %SystemDrive% >nul 2>&1
        if not errorlevel 1 set "IS_ADMIN=1"
    )
    if not defined IS_ADMIN (
        echo [提示] 注入器是提权运行的，普通权限结束不掉。
        echo        现在请求管理员权限，以便一次清干净（关端口 + 结束注入器）。
        echo        只想关端口不提权：05-一键停止.bat --no-elevate
        echo.
        if not exist "%ROOT%scripts\restart-elevated.ps1" (
            echo [错误] 缺少 scripts\restart-elevated.ps1，无法自动提权重启。
            echo        请右键本按钮，选择以管理员身份运行。
            echo.
            pause
            exit /b 1
        )
        rem 带上 --elevated，提权后的那一轮不会再尝试提权，避免反复弹 UAC。
        powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\restart-elevated.ps1" -Target "%~f0" -ExtraArgs "--elevated %*"
        exit /b 0
    )
)

rem 全部逻辑在 scripts\stop_full_chain.py：
rem   1) 按 logs\*.pid 与 WMPFDebugger\logs\*.pid 定位本工具启动的进程
rem   2) 兜底扫描 9421 / 62000 / 49999 的实际监听进程
rem   3) 结束进程树 - 校验端口释放 - 清理过期 pid 文件
rem 可选参数：
rem   --dry-run       只列出将要结束的进程，不动手
rem   --kill-wechat   连微信小程序进程一起结束（清除内存里的 Frida hook）
rem   --no-elevate    不提权，只做普通权限能做的事
rem   --json          以 JSON 输出
rem 默认直接执行，不再二次确认（只会结束白名单内的 python / node 进程）。
"%PY_EXE%" "%ROOT%scripts\stop_full_chain.py" --yes %*
if errorlevel 1 (
    echo.
    echo [提示] 停止过程未完全成功。常见原因与处理见 `问题解决.md` 第四节。
    echo.
    pause
    exit /b 1
)

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

@echo off
setlocal
title 自动更新偏移配置

set "ROOT=%~dp0"

rem 定位本项目的 Python（不依赖 PATH —— 见 scripts\find-python.bat 的说明）
call "%ROOT%scripts\find-python.bat"
if not defined PY_RUN_OK goto :no_python

echo ============================================
echo   自动更新偏移配置
echo   按本机微信的 WMPF 运行时版本重新生成
echo ============================================
echo   微信不需要关闭。
echo   同一版本已存在配置时会跳过；要强制重算：
echo       04-自动更新.bat --force
echo ============================================
echo.

"%PY_EXE%" "%ROOT%偏移提取工具\sync_latest_wmpf_offsets.py" %*
if errorlevel 1 (
    echo.
    echo [提示] 更新失败。常见原因与处理见 `问题解决.md`。
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

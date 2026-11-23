@echo off
setlocal
title 检测依赖

set "ROOT=%~dp0"

rem 定位本项目的 Python（不依赖 PATH —— 见 scripts\find-python.bat 的说明）
call "%ROOT%scripts\find-python.bat"
if not defined PY_RUN_OK goto :no_python

echo ============================================
echo   检测依赖 / 环境体检
echo ============================================
echo.

"%PY_EXE%" "%ROOT%scripts\project_doctor.py" %*
if errorlevel 1 (
    echo.
    echo [提示] 体检发现问题，请按上面的“建议下一步”处理。
    echo        常见原因与处理见 `问题解决.md`。
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

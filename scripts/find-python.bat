@echo off
rem ==========================================================================
rem  scripts\find-python.bat —— 【内部用】定位本项目的 Python 解释器
rem
rem  被 02 / 03 / 04 / 05 以 `call` 方式引用，不单独双击。
rem
rem  为什么要它：以前 02~05 用的是裸 `python`，完全依赖 PATH。而 PATH 是全局的，
rem  一旦被写乱的条目（比如指向一个残缺的 .venv）挡在前面，裸 `python` 就会解析到
rem  错的解释器上，报出看不懂的错。改成「显式定位 + 绝对路径调用」以后：
rem    * 不依赖 PATH —— 不往系统里写任何东西；
rem    * 谁先谁后是确定的 —— 优先本项目自己的环境。
rem
rem  成功后设置两个变量供调用方使用：
rem    PY_EXE        项目 Python 的可执行文件完整路径
rem    PY_RUN_OK     置为 1 表示找到可用解释器
rem
rem  查找顺序（第一个可用的胜出）：
rem    1) .venv\Scripts\python.exe            项目专用环境（01 创建，首选）
rem    2) .runtime\python\python.exe          项目可嵌入版（机器无 Python 时 01 下载）
rem    3) WMPF_NODE20_DIR 同级无关 —— 不找 Node
rem    4) 系统 Python（py -3 / where python），需 3.10+
rem
rem  与 01 的判定口径保持一致：候选必须
rem    a) 能起（python -c "import sys" 返回 0）
rem    b) 版本 >= 3.10
rem  否则视为不可用，继续找下一个 —— 这样「残缺的 .venv」会被自动跳过，
rem  不会再把整个链路带崩。
rem ==========================================================================

set "FPY_ROOT=%~dp0.."
pushd "%FPY_ROOT%" >nul
set "FPY_ROOT=%CD%"
popd >nul

set "PY_EXE="
set "PY_RUN_OK="

rem --------------------------------------------------------------------------
rem  1) 项目专用环境 .venv（01 创建的首选）
rem --------------------------------------------------------------------------
if defined PY_EXE goto :fpy_done
if not exist "%FPY_ROOT%\.venv\Scripts\python.exe" goto :fpy_local_embed
call :fpy_probe "%FPY_ROOT%\.venv\Scripts\python.exe"
if not defined PY_EXE goto :fpy_local_embed
goto :fpy_done

rem --------------------------------------------------------------------------
rem  2) 项目可嵌入版 .runtime\python（机器上没有 Python 时 01 下载的）
rem --------------------------------------------------------------------------
:fpy_local_embed
if defined PY_EXE goto :fpy_done
if not exist "%FPY_ROOT%\.runtime\python\python.exe" goto :fpy_sys_py
call :fpy_probe "%FPY_ROOT%\.runtime\python\python.exe"
if not defined PY_EXE goto :fpy_sys_py
goto :fpy_done

rem --------------------------------------------------------------------------
rem  3) 系统 Python：先 py -3 launcher，再 where python
rem --------------------------------------------------------------------------
:fpy_sys_py
if defined PY_EXE goto :fpy_done
for /f "delims=" %%p in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do if not defined PY_EXE call :fpy_probe "%%p"
if defined PY_EXE goto :fpy_done

for /f "delims=" %%p in ('where python 2^>nul') do if not defined PY_EXE call :fpy_probe "%%p"

:fpy_done
if not defined PY_EXE exit /b 0
set "PY_RUN_OK=1"
exit /b 0

rem --------------------------------------------------------------------------
rem  校验一个候选：%1=路径
rem  能用则设置 PY_EXE。判定：能起 + 版本 >= 3.10
rem --------------------------------------------------------------------------
:fpy_probe
if defined PY_EXE exit /b 0
if not exist "%~1" exit /b 0
rem 能起
"%~1" -c "import sys" >nul 2>&1
if errorlevel 1 exit /b 0
rem 版本 >= 3.10
"%~1" -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
set "PY_EXE=%~1"
exit /b 0

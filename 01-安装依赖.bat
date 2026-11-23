@echo off
setlocal DisableDelayedExpansion
title 安装依赖（首次使用 · 一键全自动）

rem ==========================================================================
rem  01-安装依赖.bat —— 一次性装齐所有依赖（零前置）
rem
rem  目标：完全没用过本项目的人，双击一次就能把全部依赖装完。
rem
rem  两个原则
rem    1) 依赖尽量落在【本项目目录】内，删掉项目目录就一起消失：
rem         .runtime\node20\        Node 20（官方便携 zip 解压）
rem         .venv\                  项目专用 Python 环境
rem         .runtime\python\        机器上没有 Python 时自动下载的可嵌入版
rem         WMPFDebugger\node_modules\
rem    2) 不写死任何机器路径：全部按本文件所在目录 %~dp0 与运行时探测自动适配。
rem
rem  需要写环境变量时本脚本会一并设置好，否则 WMPFDebugger 的启动脚本找不到 Node 20：
rem         WMPF_NODE20_DIR     -> 本项目的 Node 20 目录（用户级）
rem  这一处改动可以用 `06-一键清理依赖.bat` 一键撤销。
rem
rem  【为什么不再写 PATH】02~05 以前用裸 `python`，本脚本就得把项目 Python 写进
rem  PATH（管理员下还会写系统级）。后果是：一旦这个 PATH 条目失效（例如 .venv
rem  后来损坏），裸 `python` 会被解析到坏掉的解释器上，02/03/05 全线报错，且症状
rem  与本工具无关、极难排查。现在 02~05 改为经 `scripts\find-python.bat` 显式定位
rem  本项目 Python，本脚本因此**完全不改写 PATH**，对机器零侵入。
rem
rem  建议以管理员身份运行（右键 → 以管理员身份运行）。
rem
rem  可选参数
rem         --no-pip        只装 Node 依赖
rem         --no-npm        只装 Python 依赖
rem         --force-node    忽略已有的 Node 20，重新下载
rem         --local-python  不用系统 Python，强制用项目内的可嵌入版
rem
rem  【维护注意】本项目路径里带 ASCII 括号（如 "WMP-pentest-automation-v3.0 (1)"），
rem  而 cmd 会在解析时先配对括号。所以本文件里遵守三条硬规则：
rem    a) 不写多行的 ( ... ) 命令块，一律用单行 if + goto 标签；
rem    b) 路径变量一律加引号，绝不裸写进命令行；
rem    c) 不在 for /f '...' 里用 -c "..." 这种嵌套引号，改用直接命令 + errorlevel。
rem  破坏任意一条都会在含括号的目录下直接解析失败。
rem ==========================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "NODE_DIR=%ROOT%\.runtime\node20"
set "DL_DIR=%ROOT%\.runtime\downloads"
set "VENV_DIR=%ROOT%\.venv"
set "PY_LOCAL_DIR=%ROOT%\.runtime\python"
set "WMPF_DIR=%ROOT%\WMPFDebugger"
set "PY_MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple"

rem 候选版本：python.org 对某分支的最后一个补丁版有时只发源码包，故按列表逐个试
set "NODE_VERSIONS=v20.20.2 v20.18.0"
set "PY_VERSIONS=3.12.10 3.11.9"

set "DO_PIP=1"
set "DO_NPM=1"
set "FORCE_NODE="
set "FORCE_LOCAL_PY="

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--no-pip" set "DO_PIP="
if /i "%~1"=="--no-npm" set "DO_NPM="
if /i "%~1"=="--force-node" set "FORCE_NODE=1"
if /i "%~1"=="--local-python" set "FORCE_LOCAL_PY=1"
shift
goto :parse_args
:args_done

echo ============================================
echo   安装依赖（首次使用 · 一键全自动）
echo ============================================
echo   依赖会尽量装在本项目目录内，删目录即清理干净。
echo   不需要预装 Node / Python，缺什么会自动下载。
echo.

rem ---------------------------------------------------------------------------
rem  0) 管理员检查
rem ---------------------------------------------------------------------------
set "IS_ADMIN="
net session >nul 2>&1
if not errorlevel 1 set "IS_ADMIN=1"
if defined IS_ADMIN goto :admin_done
fsutil dirty query %SystemDrive% >nul 2>&1
if not errorlevel 1 set "IS_ADMIN=1"
:admin_done
if defined IS_ADMIN echo [OK] 以管理员身份运行。
if not defined IS_ADMIN echo [提示] 当前不是管理员，环境变量将写入【当前用户】。
if not defined IS_ADMIN echo        如果本工具目录在 C:\Program Files 等受保护位置，
if not defined IS_ADMIN echo        请关掉本窗口，右键 01-安装依赖.bat → 以管理员身份运行。
echo.

rem ---------------------------------------------------------------------------
rem  1) Node 20（WMPFDebugger 依赖 frida@16.6.6，只支持 Node 20）
rem ---------------------------------------------------------------------------
echo [1/6] 准备 Node 20 ...
set "NODE_HOME="
set "NODE_FROM="

if defined FORCE_NODE goto :node_probe_env
if not exist "%NODE_DIR%\node.exe" goto :node_probe_env
call :node_major "%NODE_DIR%\node.exe"
if /i not "%NODE_MAJOR%"=="v20" goto :node_local_bad
set "NODE_HOME=%NODE_DIR%"
set "NODE_FROM=项目内 .runtime\node20"
goto :node_ready
:node_local_bad
echo      项目内的 Node 不是 v20，将重新下载。

:node_probe_env
if not defined WMPF_NODE20_DIR goto :node_download
if not exist "%WMPF_NODE20_DIR%\node.exe" goto :node_download
call :node_major "%WMPF_NODE20_DIR%\node.exe"
if /i not "%NODE_MAJOR%"=="v20" goto :node_env_bad
set "NODE_HOME=%WMPF_NODE20_DIR%"
set "NODE_FROM=环境变量 WMPF_NODE20_DIR"
goto :node_ready
:node_env_bad
echo      环境变量 WMPF_NODE20_DIR 指向的 Node 不是 v20，将重新下载。

:node_download
echo      本机没有可用的 Node 20，开始下载便携版到项目内 ...
if not exist "%DL_DIR%" mkdir "%DL_DIR%" >nul 2>&1
set "NODE_DL_OK="
set "NODE_VER_USED="
for %%V in (%NODE_VERSIONS%) do if not defined NODE_DL_OK call :try_node "%%V"
if not defined NODE_DL_OK goto :fail_node

echo      解压 Node %NODE_VER_USED% ...
call :extract "%DL_DIR%\node-%NODE_VER_USED%-win-x64.zip" "%DL_DIR%\node-extract"
if errorlevel 1 goto :fail_node
set "NODE_INNER="
for /d %%D in ("%DL_DIR%\node-extract\*") do set "NODE_INNER=%%D"
if not defined NODE_INNER goto :fail_node
if exist "%NODE_DIR%" rd /s /q "%NODE_DIR%" >nul 2>&1
move "%NODE_INNER%" "%NODE_DIR%" >nul
if not exist "%NODE_DIR%\node.exe" goto :fail_node
rd /s /q "%DL_DIR%\node-extract" >nul 2>&1
del /f /q "%DL_DIR%\node-%NODE_VER_USED%-win-x64.zip" >nul 2>&1
set "NODE_HOME=%NODE_DIR%"
set "NODE_FROM=项目内 .runtime\node20（本次下载）"

:node_ready
if not defined NODE_HOME goto :fail_node
for /f "delims=" %%v in ('"%NODE_HOME%\node.exe" -v 2^>nul') do set "NODE_VER=%%v"
echo      [OK] Node %NODE_VER%
echo           来源：%NODE_FROM%
echo           位置："%NODE_HOME%"
set "PATH=%NODE_HOME%;%PATH%"
echo.

rem ---------------------------------------------------------------------------
rem  2) Python（优先项目内 .venv，其次系统 Python，都没有就下载可嵌入版）
rem ---------------------------------------------------------------------------
echo [2/6] 准备 Python ...
set "PY_EXE="

if defined FORCE_LOCAL_PY goto :python_local_only
if not exist "%VENV_DIR%\Scripts\python.exe" goto :python_find_base
"%VENV_DIR%\Scripts\python.exe" -c "import sys" >nul 2>&1
if errorlevel 1 goto :python_find_base
rem 光「能跑」还不够：必须确认里面还有 pip。上次安装被中断
rem （网络断 / 被安全软件拦 / 磁盘满）会留下一个能跑但没有 pip 的残缺 venv，
rem 复用它只会在装依赖时抛出 No module named pip —— 用户完全看不懂。
"%VENV_DIR%\Scripts\python.exe" -m pip --version >nul 2>&1
if errorlevel 1 goto :python_venv_broken
set "PY_EXE=%VENV_DIR%\Scripts\python.exe"
echo      [OK] 复用项目内已有的 Python 环境：%VENV_DIR%
goto :python_ready

:python_venv_broken
echo      项目内的 .venv 不完整（缺少 pip，多半是上次安装中断留下的），正在重建 ...
rd /s /q "%VENV_DIR%" >nul 2>&1
goto :python_find_base

:python_local_only
if not exist "%PY_LOCAL_DIR%\python.exe" goto :python_download
"%PY_LOCAL_DIR%\python.exe" -c "import sys" >nul 2>&1
if errorlevel 1 goto :python_download
rem 可嵌入版的 pip 靠 get-pip 引导，中断后同样会缺 —— 缺了就重新下载
"%PY_LOCAL_DIR%\python.exe" -m pip --version >nul 2>&1
if errorlevel 1 goto :python_download
set "PY_EXE=%PY_LOCAL_DIR%\python.exe"
echo      [OK] 使用项目内的可嵌入版 Python：%PY_LOCAL_DIR%
goto :python_ready

:python_find_base
set "BASE_PY="
if not exist "%PY_LOCAL_DIR%\python.exe" goto :python_probe_system
"%PY_LOCAL_DIR%\python.exe" -c "import sys" >nul 2>&1
if errorlevel 1 goto :python_probe_system
set "BASE_PY=%PY_LOCAL_DIR%\python.exe"
echo      [OK] 复用项目内已有的可嵌入版 Python。

:python_probe_system
if defined BASE_PY goto :python_have_base
for /f "delims=" %%p in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do if not defined BASE_PY set "BASE_PY=%%p"
if not defined BASE_PY goto :python_probe_path
echo      [OK] 找到系统 Python："%BASE_PY%"
goto :python_have_base

:python_probe_path
for /f "delims=" %%p in ('where python 2^>nul') do if not defined BASE_PY call :probe_python "%%p"
if not defined BASE_PY goto :python_download
echo      [OK] 找到系统 Python："%BASE_PY%"

:python_have_base
rem 只接受 3.10+（直接命令 + errorlevel，避免 for /f 里的嵌套引号）
"%BASE_PY%" -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
if errorlevel 1 goto :python_base_bad
goto :python_make_env
:python_base_bad
echo      这个 Python 低于 3.10，将改用项目内可嵌入版。

:python_download
echo      本机没有可用的 Python 3.10+，开始下载可嵌入版到项目内 ...
if not exist "%DL_DIR%" mkdir "%DL_DIR%" >nul 2>&1
set "PY_DL_OK="
set "PY_VER_USED="
for %%V in (%PY_VERSIONS%) do if not defined PY_DL_OK call :try_python "%%V"
if not defined PY_DL_OK goto :fail_python

echo      解压 Python %PY_VER_USED% ...
call :extract "%DL_DIR%\python-%PY_VER_USED%-embed-amd64.zip" "%PY_LOCAL_DIR%"
if errorlevel 1 goto :fail_python
del /f /q "%DL_DIR%\python-%PY_VER_USED%-embed-amd64.zip" >nul 2>&1

rem 可嵌入版默认用 python3xx._pth 锁死 sys.path，pip 装了也 import 不到，
rem 必须把 Lib\site-packages 加进去并打开 import site。
set "PY_TAG=%PY_VER_USED:.=%"
set "PY_TAG=%PY_TAG:~0,3%"
set "PTH_DONE="
for %%F in ("%PY_LOCAL_DIR%\python*._pth") do if not defined PTH_DONE call :write_pth "%%F" "%PY_TAG%"
if not defined PTH_DONE goto :fail_python

echo      引导 pip ...
call :download "%DL_DIR%\get-pip.py" "https://bootstrap.pypa.io/get-pip.py" "https://mirrors.aliyun.com/pypi/get-pip.py" ""
if errorlevel 1 goto :fail_python
"%PY_LOCAL_DIR%\python.exe" "%DL_DIR%\get-pip.py" --no-warn-script-location --disable-pip-version-check
if errorlevel 1 goto :fail_python
del /f /q "%DL_DIR%\get-pip.py" >nul 2>&1
set "BASE_PY=%PY_LOCAL_DIR%\python.exe"

:python_make_env
rem 有 venv 模块就在项目内建专用环境；可嵌入版没有 venv，直接用它本身。
"%BASE_PY%" -c "import venv" >nul 2>&1
if errorlevel 1 goto :python_use_base
if exist "%VENV_DIR%\Scripts\python.exe" goto :python_use_venv
echo      正在创建项目专用 Python 环境 .venv ...
"%BASE_PY%" -m venv "%VENV_DIR%"
if not exist "%VENV_DIR%\Scripts\python.exe" goto :python_use_base

rem 建完必须验一次 pip。`python -m venv` 中途失败（磁盘满 / 被安全软件拦 /
rem 用户 Ctrl+C）会留下一个能起、但没有 pip 的 venv；若直接拿它去 pip install，
rem 报的是 "No module named pip" —— 用户完全看不懂，而且下次再跑 01 时
rem 因为「能起且有 pip 探针」还可能被误复用。这里当场兜底补一次。
"%VENV_DIR%\Scripts\python.exe" -m pip --version >nul 2>&1
if not errorlevel 1 goto :python_use_venv
echo      venv 建好了但没有 pip，正在补装（ensurepip）...
"%VENV_DIR%\Scripts\python.exe" -m ensurepip --default-pip >nul 2>&1
"%VENV_DIR%\Scripts\python.exe" -m pip --version >nul 2>&1
if errorlevel 1 goto :python_venv_no_pip

:python_use_venv
set "PY_EXE=%VENV_DIR%\Scripts\python.exe"
echo      [OK] 使用项目专用 Python 环境：%VENV_DIR%
goto :python_ready

:python_venv_no_pip
rem 补 pip 也失败：这个 venv 不可信，删掉并回退到 base Python，避免留下坏环境。
echo      [WARN] venv 里补不上 pip，删除它并改用基础 Python（依赖将装进它自己的 site-packages）。
rd /s /q "%VENV_DIR%" >nul 2>&1
goto :python_use_base

:python_use_base
set "PY_EXE=%BASE_PY%"
echo      [OK] 使用 Python："%BASE_PY%"
echo           依赖会装进它自己的 site-packages（不在 .venv 里）。

:python_ready
if not defined PY_EXE goto :fail_python
if not exist "%PY_EXE%" goto :fail_python
for /f "delims=" %%v in ('"%PY_EXE%" -V 2^>nul') do set "PY_VER_SHOW=%%v"
echo      [OK] %PY_VER_SHOW%
echo           位置："%PY_EXE%"
echo.

rem ---------------------------------------------------------------------------
rem  3) 写环境变量（一键设置，供 02~05 直接找到运行时）
rem ---------------------------------------------------------------------------
echo [3/6] 配置环境变量 ...
if /i not "%NODE_HOME%"=="%NODE_DIR%" goto :env_python
setx WMPF_NODE20_DIR "%NODE_DIR%" >nul 2>&1
if errorlevel 1 goto :env_node_fail
echo      [OK] WMPF_NODE20_DIR = "%NODE_DIR%"
goto :env_python
:env_node_fail
echo      [WARN] 写入 WMPF_NODE20_DIR 失败，请手工添加环境变量：
echo             WMPF_NODE20_DIR = "%NODE_DIR%"

:env_python
rem 【不再改写 PATH】
rem 02~05 以前用裸 `python`，所以这里必须把项目 Python 写进 PATH（甚至系统级）。
rem 那条路有个致命代价：PATH 是全局的，一旦写进去的条目失效（比如 .venv 后来损坏），
rem 裸 `python` 就会解析到坏掉的解释器上，02/03/05 全部报错，而且症状和本工具无关，
rem 极难排查 —— 这正是「装完用着用着整个链路就崩了」的由来。
rem
rem 现在 02~05 改为经 scripts\find-python.bat **显式定位**本项目 Python 并直接用绝对
rem 路径调用，完全不再依赖 PATH。所以本脚本不再改写 PATH：
rem   * 对机器零侵入 —— 06 也少一样要撤销的东西；
rem   * 删掉项目目录后，机器上不留任何指向本项目的残留。
rem
rem 只保留 WMPF_NODE20_DIR 一个环境变量（Node 那边由 WMPFDebugger 自己的启动脚本读，
rem 且提权子进程也能看到用户级变量），同样由 06 负责撤销。
rem
rem 旧版本写进 PATH 的条目（如果有），06-一键清理依赖.bat 仍会负责清掉。
echo      [OK] 不改写 PATH（02~05 已改为显式定位项目 Python，不再依赖 PATH）
echo.


rem ---------------------------------------------------------------------------
rem  4) Python 依赖
rem ---------------------------------------------------------------------------
if not defined DO_PIP goto :skip_pip
echo [4/6] 安装 Python 依赖 ...
call :pip_install "%ROOT%\e0e1-wx\requirements.txt" "e0e1-wx"
if errorlevel 1 goto :fail_pip
call :pip_install "%ROOT%\偏移提取工具\requirements.txt" "偏移提取工具"
if errorlevel 1 goto :fail_pip
echo.
goto :step_node

:skip_pip
echo [4/6] 已按参数跳过 Python 依赖安装。
echo.

rem ---------------------------------------------------------------------------
rem  5) Node 依赖
rem ---------------------------------------------------------------------------
:step_node
if not defined DO_NPM goto :skip_npm
echo [5/6] 安装 Node 依赖（WMPFDebugger）...
pushd "%WMPF_DIR%" >nul
call npm.cmd install --no-audit --no-fund
if errorlevel 1 echo      [WARN] npm install 返回非 0，继续做后续校验。

rem package-lock.json 里 frida 锁在 16.6.6；再显式装一次确保版本正确。
rem --no-save：不改动 package.json。
call npm.cmd install frida@16.6.6 --no-save --no-audit --no-fund
if errorlevel 1 echo      [WARN] 固定 frida@16.6.6 时返回非 0，继续。

if exist "node_modules\frida\build\frida_binding.node" goto :frida_ok
echo      frida_binding.node 缺失，尝试用 prebuild-install 补装 ...
pushd "node_modules\frida" >nul
call node "..\prebuild-install\bin.js"
popd >nul
if exist "node_modules\frida\build\frida_binding.node" goto :frida_ok
echo      仍然缺失，尝试 npm rebuild frida ...
call npm.cmd rebuild frida
if exist "node_modules\frida\build\frida_binding.node" goto :frida_ok
popd >nul
echo.
echo [FAIL] frida 原生绑定 frida_binding.node 装不上。
echo        常见原因：该文件需要从 GitHub 下载，网络受限时会失败。
echo        处理：配置代理后重跑本脚本，并确认用的是 Node 20。
goto :fail

:frida_ok
echo      [OK] frida 16.6.6 + frida_binding.node 已就绪
popd >nul
echo.
goto :step_verify

:skip_npm
echo [5/6] 已按参数跳过 Node 依赖安装。
echo.

rem ---------------------------------------------------------------------------
rem  6) 复核
rem ---------------------------------------------------------------------------
:step_verify
echo [6/6] 复核 ...
set "VERIFY_FAIL="
if not defined DO_PIP goto :verify_node
"%PY_EXE%" -c "import frida,PySide6,qasync,websockets,httpx,mcp" >nul 2>&1
if errorlevel 1 set "VERIFY_FAIL=1"
if defined VERIFY_FAIL echo      [FAIL] e0e1-wx Python 依赖缺失
if not defined VERIFY_FAIL echo      [OK] e0e1-wx Python 依赖齐全
"%PY_EXE%" -c "import pefile,capstone" >nul 2>&1
if errorlevel 1 set "VERIFY_FAIL=1"
if defined VERIFY_FAIL echo      [FAIL] 偏移提取工具 Python 依赖缺失
if not defined VERIFY_FAIL echo      [OK] 偏移提取工具 Python 依赖齐全

:verify_node
if not defined DO_NPM goto :verify_done
if not exist "%WMPF_DIR%\node_modules\frida\build\frida_binding.node" set "VERIFY_FAIL=1"
if not exist "%WMPF_DIR%\node_modules\ts-node\register\index.js" set "VERIFY_FAIL=1"
if defined VERIFY_FAIL echo      [FAIL] WMPFDebugger Node 依赖不完整
if not defined VERIFY_FAIL echo      [OK] WMPFDebugger Node 依赖齐全

:verify_done
echo.
if defined VERIFY_FAIL goto :fail
echo ============================================
echo   [完成] 依赖安装完毕
echo ============================================
echo   依赖位置（都在本项目目录内，删目录即清理干净）：
echo     Node 20    "%NODE_HOME%"
echo     Python     "%PY_EXE%"
echo     Node 依赖  "%WMPF_DIR%\node_modules"
echo   已写入的环境变量（用 06-一键清理依赖.bat 可撤销）：
echo     WMPF_NODE20_DIR
echo   未改写 PATH（02~05 已改为显式定位项目 Python，不再依赖 PATH）。
echo.
:done_hint
echo   下一步：双击 02-一键启动.bat
echo   想先确认环境：双击 03-检测依赖.bat
echo.
pause
exit /b 0

rem ---------------------------------------------------------------------------
rem  失败出口
rem ---------------------------------------------------------------------------
:fail_node
echo.
echo [FAIL] Node 20 准备失败：所有下载源都不可用。
echo        处理：确认网络可达 nodejs.org 或 npmmirror.com 后重跑本脚本。
goto :fail

:fail_python
echo.
echo [FAIL] Python 准备失败。
echo        处理：确认网络可达 python.org 或阿里云镜像后重跑本脚本；
echo              或自行安装 Python 3.10+ 后重跑。
goto :fail

:fail_pip
echo.
if defined REQ_BROKEN goto :fail_req_broken
echo [FAIL] Python 依赖安装失败（官方源与清华镜像都失败）。
echo        处理：检查网络 / 代理后重跑本脚本。
goto :fail

:fail_req_broken
echo [FAIL] requirements 文件无法解析，pip 在「读取阶段」就退出了。
echo        文件：%REQ_BROKEN%
echo.
echo        这不是网络问题（换镜像也救不了）。原因是该文件不是纯 ASCII：
echo        pip 在中文 Windows 上按 GBK 猜编码，碰到 UTF-8 的多字节字符就会报
echo        UnicodeDecodeError: 'gbk' codec can't decode byte 0x..
echo.
echo        处理：把上面那个文件里的中文（**包括注释**）删掉或改成英文，
echo              保持纯 ASCII，然后重跑本脚本。
echo        自检：03-检测依赖.bat 有「requirements 编码」一项会直接指出问题文件。
goto :fail

:fail
echo.
echo ============================================
echo   依赖安装未完成，请按上面的提示处理后重试
echo ============================================
echo.
pause
exit /b 1

rem ===========================================================================
rem  子过程
rem ===========================================================================

rem ---------------------------------------------------------------------------
rem  下载：%1=输出文件 %2/%3/%4=候选 URL（可空）
rem  优先用系统自带 curl，失败或缺失时退回 PowerShell
rem ---------------------------------------------------------------------------
:download
set "D_OUT=%~1"
set "D_U1=%~2"
set "D_U2=%~3"
set "D_U3=%~4"
if exist "%D_OUT%" del /f /q "%D_OUT%" >nul 2>&1
where curl.exe >nul 2>&1
if errorlevel 1 goto :download_ps
if not defined D_U1 goto :download_ps
curl.exe -L --fail --silent --show-error --connect-timeout 20 --retry 2 -o "%D_OUT%" "%D_U1%" && if exist "%D_OUT%" exit /b 0
if not defined D_U2 goto :download_ps
curl.exe -L --fail --silent --show-error --connect-timeout 20 --retry 2 -o "%D_OUT%" "%D_U2%" && if exist "%D_OUT%" exit /b 0
if not defined D_U3 goto :download_ps
curl.exe -L --fail --silent --show-error --connect-timeout 20 --retry 2 -o "%D_OUT%" "%D_U3%" && if exist "%D_OUT%" exit /b 0

:download_ps
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue';[Net.ServicePointManager]::SecurityProtocol='Tls12';foreach($u in @('%D_U1%','%D_U2%','%D_U3%')){if($u){try{Invoke-WebRequest -Uri $u -OutFile '%D_OUT%' -UseBasicParsing;exit 0}catch{Write-Host ('        下载失败: '+$u)}}};exit 1"
if errorlevel 1 exit /b 1
if not exist "%D_OUT%" exit /b 1
exit /b 0

rem ---------------------------------------------------------------------------
rem  解压 zip：%1=zip %2=目标目录
rem ---------------------------------------------------------------------------
:extract
if exist "%~2" rd /s /q "%~2" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop';Add-Type -AssemblyName System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory('%~1','%~2');exit 0"
exit /b %errorlevel%

rem ---------------------------------------------------------------------------
rem  取 Node 主版本：%1=node.exe 路径，结果写入 NODE_MAJOR（形如 v20）
rem ---------------------------------------------------------------------------
:node_major
set "NODE_MAJOR="
set "NODE_RAW="
for /f "delims=" %%v in ('"%~1" -v 2^>nul') do set "NODE_RAW=%%v"
if not defined NODE_RAW exit /b 0
for /f "tokens=1 delims=." %%a in ("%NODE_RAW%") do set "NODE_MAJOR=%%a"
exit /b 0

rem ---------------------------------------------------------------------------
rem  校验一个 python 是否真能跑（挡掉 WindowsApps 的商店占位壳）
rem  %1=候选路径；能用则写入 BASE_PY
rem ---------------------------------------------------------------------------
:probe_python
if defined BASE_PY exit /b 0
"%~1" -c "import sys" >nul 2>&1
if errorlevel 1 exit /b 0
set "BASE_PY=%~1"
exit /b 0

rem ---------------------------------------------------------------------------
rem  尝试下载某个 Node 版本：%1=版本（如 v20.20.2）
rem ---------------------------------------------------------------------------
:try_node
echo      尝试 Node %~1 ...
call :download "%DL_DIR%\node-%~1-win-x64.zip" "https://nodejs.org/dist/%~1/node-%~1-win-x64.zip" "https://npmmirror.com/mirrors/node/%~1/node-%~1-win-x64.zip" ""
if errorlevel 1 exit /b 0
set "NODE_VER_USED=%~1"
set "NODE_DL_OK=1"
exit /b 0

rem ---------------------------------------------------------------------------
rem  尝试下载某个 Python 版本：%1=版本（如 3.12.10）
rem ---------------------------------------------------------------------------
:try_python
echo      尝试 Python %~1 ...
call :download "%DL_DIR%\python-%~1-embed-amd64.zip" "https://www.python.org/ftp/python/%~1/python-%~1-embed-amd64.zip" "https://mirrors.aliyun.com/python-release/windows/python-%~1-embed-amd64.zip" "https://registry.npmmirror.com/-/binary/python/%~1/python-%~1-embed-amd64.zip"
if errorlevel 1 exit /b 0
set "PY_VER_USED=%~1"
set "PY_DL_OK=1"
exit /b 0

rem ---------------------------------------------------------------------------
rem  写可嵌入版的 python3xx._pth：%1=文件 %2=版本号标签（如 312）
rem ---------------------------------------------------------------------------
:write_pth
> "%~1" echo python%~2.zip
>> "%~1" echo .
>> "%~1" echo Lib\site-packages
>> "%~1" echo import site
set "PTH_DONE=1"
exit /b 0

rem ---------------------------------------------------------------------------
rem  安装一份 requirements：%1=requirements.txt %2=名称
rem  官方源失败时自动换清华镜像重试
rem
rem  分两种失败：
rem    A) 本地文件读不了（UnicodeDecodeError）—— 重试镜像**没有用**，问题在文件
rem    B) 网络/源的问题 —— 换镜像重试有意义
rem  用 REQ_BROKEN 标记，交给 :fail_pip 给出对症的提示。
rem ---------------------------------------------------------------------------
:pip_install
set "REQ_BROKEN="
"%PY_EXE%" -m pip install -r "%~1" --disable-pip-version-check --no-warn-script-location --timeout 60 --retries 3
if not errorlevel 1 goto :pip_ok
rem 先判断是不是「文件本身读不了」：用 pip 自己的解码器试读一遍
"%PY_EXE%" -c "import sys;from pip._internal.utils.encoding import auto_decode;auto_decode(open(sys.argv[1],'rb').read())" "%~1" >nul 2>&1
if errorlevel 1 set "REQ_BROKEN=%~1"
echo      [WARN] 官方源安装失败，改用清华镜像重试 ...
rem 这里【不要】顺手 pip install --upgrade pip：那会先卸掉 venv 里的 pip 再装新版，
rem 一旦中断（网络抖动 / 被安全软件拦 / 用户 Ctrl+C），venv 就永久没有 pip 了，
rem 后面的重试必然失败，而且报错指向不清。pip 够不够新由 venv 的 ensurepip 决定。
"%PY_EXE%" -m pip install -r "%~1" -i "%PY_MIRROR%" --disable-pip-version-check --no-warn-script-location --timeout 60 --retries 3
if errorlevel 1 exit /b 1
echo      [OK] %~2 依赖安装完成（清华镜像）
exit /b 0
:pip_ok
echo      [OK] %~2 依赖安装完成
exit /b 0

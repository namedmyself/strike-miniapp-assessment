@echo off
setlocal
title WMPFDebugger Launcher

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul
set "NODE_HOME="

rem ��λ Node 20���Ȼ�������������Ŀ�� .runtime\node20 ���ס�
rem
rem ΪʲôҪ���ף����������ǽ�������ʱ�Ŀ��ա���ĿĿ¼�Ĺ���/Ų��λ��ʱ��
rem registry ������·������**�Ķ�ǰ�ʹ򿪵Ĵ���**�ﻹ�Ǿ�ֵ ���� ֻ�ϻ��������ͻ�
rem �Ҳ��� Node 20����������ϵͳ Node������ v22������ frida@16.6.6 �ܲ��� v22��
rem
rem ����������壺����Ŀ·�����ܴ� ASCII ���ţ��� "...v3.0 (1)"����cmd �������
rem ���ţ��������ﲻ�ö��� if ( ... ) �飬һ�ɵ��� if + goto��
set "NODE_HOME="
if not defined WMPF_NODE20_DIR goto :wmpf_try_local
if not exist "%WMPF_NODE20_DIR%\node.exe" goto :wmpf_try_local
set "NODE_HOME=%WMPF_NODE20_DIR%"
goto :wmpf_node_ready

:wmpf_try_local
if not exist "%SCRIPT_DIR%..\.runtime\node20\node.exe" goto :wmpf_node_ready
set "NODE_HOME=%SCRIPT_DIR%..\.runtime\node20"

:wmpf_node_ready
if defined NODE_HOME (
    set "PATH=%NODE_HOME%;%PATH%"
)

echo =======================================
echo [1/4] Checking Node.js...
node -v >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js was not found.
    echo         Install Node.js 20 LTS from https://nodejs.org/
    popd >nul
    pause
    exit /b 1
)

for /f "tokens=1 delims=v." %%a in ('node -v') do set "NODE_VER=%%a"
echo      Current Node.js: v%NODE_VER%
if defined NODE_HOME (
    echo      Runtime source: %NODE_HOME%
)
if %NODE_VER% GEQ 22 (
    echo [ERROR] Node.js v%NODE_VER% is not supported by frida@16.6.6.
    echo         Use Node.js 20 LTS or set WMPF_NODE20_DIR to a Node 20 folder.
    popd >nul
    pause
    exit /b 1
)
echo.

echo [2/4] Checking local dependencies...
if not exist "node_modules\ts-node\register\index.js" (
    echo [ERROR] Local ts-node is missing.
    echo         Run: ..\01-��װ����.bat
    popd >nul
    pause
    exit /b 1
)
if not exist "node_modules\frida" (
    echo [ERROR] Local frida is missing.
    echo         Run: ..\01-��װ����.bat
    popd >nul
    pause
    exit /b 1
)
echo.

echo [3/4] Launching WMPFDebugger...
echo.
echo   Start order:
echo     1. Launch this script first for Frida injection.
echo     2. Then run e0e1-wx\start_engine.py.
echo     3. Re-open the mini-program after the engine is listening.
echo.

node -r ts-node/register src/index.ts --debug-frida
if errorlevel 1 (
    echo.
    echo [ERROR] WMPFDebugger exited with an error.
    popd >nul
    pause
    exit /b 1
)

echo.
echo [4/4] WMPFDebugger exited normally.
popd >nul
pause
endlocal

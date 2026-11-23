@echo off
setlocal
chcp 65001 >nul
title WMPF Offset Sync

set "SCRIPT_DIR=%~dp0"
set "SYNC_SCRIPT="
for /d %%I in ("%SCRIPT_DIR%..\*") do (
    if exist "%%~fI\sync_latest_wmpf_offsets.py" set "SYNC_SCRIPT=%%~fI\sync_latest_wmpf_offsets.py"
)

echo ============================================
echo   WMPF Offset Sync
echo   Sync latest flue.dll offsets into both runtimes
echo ============================================
echo.

if not defined SYNC_SCRIPT (
    echo [ERROR] Sync script path could not be resolved.
    pause
    exit /b 1
)

if not exist "%SYNC_SCRIPT%" (
    echo [ERROR] Sync script not found:
    echo         %SYNC_SCRIPT%
    pause
    exit /b 1
)

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found in PATH.
    pause
    exit /b 1
)

python "%SYNC_SCRIPT%" %*
if errorlevel 1 (
    echo.
    echo [ERROR] Offset sync failed.
    echo         You can retry with:
    echo         python "%SYNC_SCRIPT%" --force
    pause
    exit /b 1
)

echo.
echo [OK] Offset sync completed.
echo      WMPFDebugger config: "%SCRIPT_DIR%frida\config"
echo      e0e1-wx config:      "%SCRIPT_DIR%..\e0e1-wx\tools\config\win"
echo.
pause
endlocal

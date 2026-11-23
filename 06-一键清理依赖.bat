@echo off
setlocal DisableDelayedExpansion
title 一键清理依赖（撤销环境变量）

rem ==========================================================================
rem  06-一键清理依赖.bat
rem
rem  定位：`01-安装依赖.bat` 会把依赖尽量装进【本项目目录】，同时往
rem  【用户级环境变量】里写了一样东西：
rem
rem        WMPF_NODE20_DIR     指向本项目 .runtime\node20
rem
rem  本脚本负责把它**撤销**（这才是删项目目录清不掉的部分）。
rem
rem  【PATH】01 现在**不再改写 PATH**（02~05 已改为经 scripts\find-python.bat
rem  显式定位项目 Python，不再依赖 PATH）。所以正常情况下这里没有 PATH 要撤。
rem  但旧版本 01 可能往 PATH 写过指向本项目的条目，本脚本仍会一并清掉 ——
rem  换用新版本后跑一次，那边遗留的条目就会被收拾干净。
rem
rem  项目目录内的依赖（.runtime / .venv / WMPFDebugger\node_modules）**默认不动** ——
rem  它们会跟着项目目录一起被删掉，没必要单独处理。确实想现在就清空，用 --purge。
rem
rem  可选参数
rem        --report-only   只看现状，什么都不改
rem        --dry-run       列出将要改的内容，不动手
rem        --purge         额外删除项目目录内的依赖目录
rem        --yes  / -y     跳过确认（配合 --purge 使用）
rem
rem  【维护注意】项目路径可能带 ASCII 括号（如 "...v3.0 (1)"），cmd 会先配对括号，
rem  所以本文件同样遵守：不写多行 ( ... ) 命令块；路径变量一律加引号。
rem ==========================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "VENV_DIR=%ROOT%\.venv"
set "RT_DIR=%ROOT%\.runtime"
set "NODE_MODULES=%ROOT%\WMPFDebugger\node_modules"

set "DRY="
set "YES="
set "PURGE="
set "REPORT="

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--report-only" set "REPORT=1"
if /i "%~1"=="--dry-run" set "DRY=1"
if /i "%~1"=="--purge" set "PURGE=1"
if /i "%~1"=="--yes" set "YES=1"
if /i "%~1"=="-y" set "YES=1"
shift
goto :parse_args
:args_done

echo ============================================
echo   一键清理依赖（撤销环境变量）
echo ============================================
echo   会撤销：01 写入的 WMPF_NODE20_DIR，以及旧版本写进 PATH 的遗留条目
echo   不动：  项目目录内的 .runtime / .venv / node_modules
echo           它们跟着项目目录一起删掉即可，要用 --purge 才清
echo.
echo   项目目录：%ROOT%
echo.

rem ---------------------------------------------------------------------------
rem  1) 现状
rem ---------------------------------------------------------------------------
echo [1/3] 项目内的依赖目录
powershell -NoProfile -ExecutionPolicy Bypass -Command "foreach($p in @('%VENV_DIR%','%RT_DIR%','%NODE_MODULES%')){ if(Test-Path -LiteralPath $p){ $s=(Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; Write-Host ('      [存在] '+$p+'   '+[Math]::Round($s/1MB,1)+' MB') } else { Write-Host ('      [ -- ] '+$p) } };exit 0"
echo.

if defined REPORT goto :done

rem ---------------------------------------------------------------------------
rem  2) 撤销 01 写入的环境变量（用户级 + 系统级）
rem ---------------------------------------------------------------------------
echo [2/3] 撤销 01 写入的环境变量
if defined DRY echo      （--dry-run：只列出，不修改）
rem 两个作用域都要查：管理员跑 01 时写的是【系统级】PATH，非管理员写的是【用户级】。
powershell -NoProfile -ExecutionPolicy Bypass -Command "$root='%ROOT%'.TrimEnd('\');$rl=$root.ToLower();$dry=('%DRY%' -eq '1');foreach($sc in @(@('用户级','HKCU:\Environment'),@('系统级','HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'))){$name=$sc[0];$key=$sc[1];try{$prop=Get-ItemProperty -Path $key -ErrorAction Stop}catch{Write-Host ('      [SKIP] 读不到'+$name+'环境变量，跳过');continue};if($prop.Path){$parts=@($prop.Path -split ';' | Where-Object{$_ -ne ''});$keep=@($parts | Where-Object{$t=$_.Trim().TrimEnd('\').ToLower();-not($t -eq $rl -or $t.StartsWith($rl+'\') -or $t -like '*wmp-pentest*')});$n=$parts.Count-$keep.Count;if($n -gt 0){if($dry){Write-Host ('      [DRY] 将从'+$name+' PATH 移除 '+$n+' 项')}else{$ok=$true;try{Set-ItemProperty -Path $key -Name Path -Value ($keep -join ';') -Type ExpandString -ErrorAction Stop}catch{$ok=$false};if($ok){Write-Host ('      [OK] 已从'+$name+' PATH 移除 '+$n+' 项')}else{Write-Host ('      [WARN] 改'+$name+' PATH 失败（需要管理员权限）')}}}else{Write-Host ('      [ -- ] '+$name+' PATH 里没有本项目的条目')}}else{Write-Host ('      [ -- ] '+$name+' PATH 不存在')};if($prop.WMPF_NODE20_DIR){$v=$prop.WMPF_NODE20_DIR;$t=$v.TrimEnd('\').ToLower();if($t -eq $rl -or $t.StartsWith($rl+'\') -or $t -like '*wmp-pentest*'){if($dry){Write-Host ('      [DRY] 将删除'+$name+' WMPF_NODE20_DIR')}else{$ok2=$true;try{Remove-ItemProperty -Path $key -Name WMPF_NODE20_DIR -ErrorAction Stop}catch{$ok2=$false};if($ok2){Write-Host ('      [OK] 已删除'+$name+' WMPF_NODE20_DIR')}else{Write-Host ('      [WARN] 删'+$name+' WMPF_NODE20_DIR 失败（需要管理员权限）')}}}else{Write-Host ('      [ -- ] '+$name+' WMPF_NODE20_DIR 指向项目外，保留：'+$v)}}else{Write-Host ('      [ -- ] '+$name+' WMPF_NODE20_DIR 不存在')}};exit 0"
if defined DRY goto :env_done
rem 触发一次环境变量刷新广播，让新开的窗口立刻看到改动
setx WMP_ENV_REFRESH 1 >nul 2>&1
reg delete "HKCU\Environment" /v WMP_ENV_REFRESH /f >nul 2>&1
:env_done
echo.

rem ---------------------------------------------------------------------------
rem  3) 可选：彻底清掉项目内的依赖目录
rem ---------------------------------------------------------------------------
echo [3/3] 项目内依赖目录
if not defined PURGE goto :no_purge
if defined DRY goto :purge_dry

if defined YES goto :purge_go
set "ANS="
set /p "ANS=      确认删除上面列出的项目内依赖目录？[y/N] "
if /i not "%ANS%"=="y" goto :purge_cancel

:purge_go
call :rm_dir "%VENV_DIR%"
call :rm_dir "%RT_DIR%"
call :rm_dir "%NODE_MODULES%"
goto :done

:purge_dry
echo      [DRY] 将删除下列目录：
echo            "%VENV_DIR%"
echo            "%RT_DIR%"
echo            "%NODE_MODULES%"
goto :done

:purge_cancel
echo      已取消删除。

:no_purge
if defined PURGE goto :done
echo      [ -- ] 未指定 --purge，保持原样。
echo            删掉整个项目目录时会一并消失，无需单独清理。

:done
echo.
echo ============================================
echo   [完成]
echo ============================================
echo   现在直接删除项目目录即可彻底清除全部依赖。
echo.
pause
exit /b 0

rem ---------------------------------------------------------------------------
rem  删除一个目录：%1=路径
rem ---------------------------------------------------------------------------
:rm_dir
if not exist "%~1" exit /b 0
rd /s /q "%~1" >nul 2>&1
if exist "%~1" goto :rm_dir_fail
echo      [OK] 已删除 "%~1"
exit /b 0
:rm_dir_fail
echo      [WARN] 删除失败（文件被占用？先跑 05-一键停止.bat）："%~1"
exit /b 0

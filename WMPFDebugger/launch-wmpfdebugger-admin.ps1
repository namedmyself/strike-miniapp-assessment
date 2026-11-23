param(
    [switch]$ElevatedChild
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = Join-Path $scriptDir "logs"
$logFile = Join-Path $logDir "wmpfdebugger-admin.log"
$pidFile = Join-Path $logDir "wmpfdebugger-admin.pid"
function Resolve-NodeHome {
    # 只认环境变量 WMPF_NODE20_DIR（由根目录 `01-安装依赖.bat` 自动设置）。
    # 提权子进程的环境虽是重新构建的，但用户级环境变量在提权后依然可见，所以这里读得到。
    if ($env:WMPF_NODE20_DIR) {
        $candidate = $env:WMPF_NODE20_DIR
        if (Test-Path (Join-Path $candidate "node.exe")) {
            return $candidate
        }
    }
    return $null
}

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

if (-not $ElevatedChild) {
    $psExe = Join-Path $PSHOME "powershell.exe"
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $MyInvocation.MyCommand.Path,
        "-ElevatedChild"
    )
    Start-Process -FilePath $psExe -ArgumentList $args -Verb RunAs -WindowStyle Hidden
    Write-Output "Started elevated WMPFDebugger helper. Log: $logFile"
    exit 0
}

Set-Location $scriptDir
$nodeHome = Resolve-NodeHome
if ($nodeHome) {
    $env:PATH = "$nodeHome;$env:PATH"
}

"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting elevated WMPFDebugger" | Set-Content -Path $logFile -Encoding UTF8
"ScriptDir: $scriptDir" | Add-Content -Path $logFile -Encoding UTF8
"WrapperPid: $PID" | Add-Content -Path $logFile -Encoding UTF8
if ($nodeHome) {
    "NodeHome: $nodeHome" | Add-Content -Path $logFile -Encoding UTF8
}

try {
    Set-Content -Path $pidFile -Value $PID -Encoding ASCII
    & node -v 2>&1 | ForEach-Object {
        Add-Content -Path $logFile -Value "$_" -Encoding UTF8
    }
    & node -r ts-node/register src/index.ts --debug-frida 2>&1 | ForEach-Object {
        Add-Content -Path $logFile -Value "$_" -Encoding UTF8
    }
}
catch {
    Add-Content -Path $logFile -Value ($_ | Out-String) -Encoding UTF8
    throw
}
finally {
    Remove-Item -LiteralPath $pidFile -ErrorAction SilentlyContinue
}

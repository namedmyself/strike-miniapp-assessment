# 以管理员身份重新运行一个批处理，并把它的输出留在新窗口里。
# 用途：注入器（WMPFDebugger）是提权启动的，普通权限杀不掉，需要提权后再结束。
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$ExtraArgs = ""
)

$inner = '"' + $Target + '"'
if ($ExtraArgs.Trim().Length -gt 0) {
    $inner = $inner + ' ' + $ExtraArgs
}

Write-Host "[INFO] 正在请求管理员权限（UAC 弹窗请点“是”）..." -ForegroundColor Yellow
Write-Host "[INFO] 提权后的窗口会保留输出，请在那个窗口里看结果。" -ForegroundColor Yellow

try {
    # /k 让新窗口执行完不关闭，方便看输出
    Start-Process -FilePath 'cmd.exe' -ArgumentList '/k', $inner -Verb RunAs -ErrorAction Stop
    Write-Host "[OK] 已在新窗口中以管理员身份启动。" -ForegroundColor Green
} catch {
    Write-Host "[WARN] 提权被取消或失败：$($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[WARN] 可以右键本按钮 -> 以管理员身份运行，重试一次。" -ForegroundColor Red
}

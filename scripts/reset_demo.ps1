$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$RunDir = Join-Path $ProjectRoot ".run"
foreach ($Name in @("csd.pid", "dashboard.pid")) {
    $PidFile = Join-Path $RunDir $Name
    if (Test-Path -LiteralPath $PidFile) {
        $ProcessId = [int](Get-Content -LiteralPath $PidFile -Raw)
        $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($Process) { Stop-Process -Id $ProcessId }
        Remove-Item -LiteralPath $PidFile
    }
}
Write-Host "SafeConnectKey demo processes stopped. Keys, samples, and evidence were preserved."


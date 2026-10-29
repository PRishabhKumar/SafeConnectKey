param(
    [Parameter(Mandatory = $true)]
    [string]$BindAddress,
    [ValidateRange(1, 65535)]
    [int]$Port = 8001
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$EnvFile = Join-Path $ProjectRoot ".env"
$SampleFile = Join-Path $ProjectRoot "csd_data\sample.txt"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Missing .venv. Complete the setup section in docs/TWO_LAPTOP_WIFI_GUIDE.md."
}
if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw "Missing .env. Generate keys on the CSD laptop, then copy the same .env to the Host laptop."
}
if (-not (Test-Path -LiteralPath $SampleFile)) {
    throw "Missing CSD sample data. Run: .\.venv\Scripts\python.exe -m scripts.generate_sample_data"
}

Write-Host "Starting CSD on http://${BindAddress}:$Port (foreground; Ctrl+C stops it)"
& $Python -m csd_app.main --host $BindAddress --port $Port
exit $LASTEXITCODE

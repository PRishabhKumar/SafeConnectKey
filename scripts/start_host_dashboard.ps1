param(
    [Parameter(Mandatory = $true)]
    [string]$CsdAddress,
    [ValidateRange(1, 65535)]
    [int]$CsdPort = 8001,
    [string]$DashboardAddress = "127.0.0.1",
    [ValidateRange(1, 65535)]
    [int]$DashboardPort = 8501
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Streamlit = Join-Path $ProjectRoot ".venv\Scripts\streamlit.exe"
$EnvFile = Join-Path $ProjectRoot ".env"

if (-not (Test-Path -LiteralPath $Python) -or -not (Test-Path -LiteralPath $Streamlit)) {
    throw "Missing .venv. Complete the setup section in docs/TWO_LAPTOP_WIFI_GUIDE.md."
}
if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw "Missing .env. Copy the exact CSD .env to this Host laptop first."
}

$env:SCK_CSD_MODE = "external"
$env:SCK_CSD_BASE_URL = "http://${CsdAddress}:$CsdPort"

& $Python -m host_app.client check --base-url $env:SCK_CSD_BASE_URL
if ($LASTEXITCODE -ne 0) {
    throw "The CSD readiness check failed; the dashboard was not started."
}

Write-Host "Starting Host dashboard at http://${DashboardAddress}:$DashboardPort"
& $Streamlit run (Join-Path $ProjectRoot "streamlit_app.py") --server.address $DashboardAddress --server.port $DashboardPort
exit $LASTEXITCODE

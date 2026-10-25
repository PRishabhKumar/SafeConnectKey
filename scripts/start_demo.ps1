param([switch]$NoDashboard)
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Streamlit = Join-Path $ProjectRoot ".venv\Scripts\streamlit.exe"
if (-not (Test-Path -LiteralPath $Python)) { throw "Missing .venv. Follow README setup first." }
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot ".env"))) { & $Python -m scripts.generate_demo_keys }
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "csd_data\sample.txt"))) { & $Python -m scripts.generate_sample_data }
$RunDir = Join-Path $ProjectRoot ".run"
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
$Csd = Start-Process -FilePath $Python -ArgumentList "-m","uvicorn","csd_app.main:app","--host","127.0.0.1","--port","8001" -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru
Set-Content -LiteralPath (Join-Path $RunDir "csd.pid") -Value $Csd.Id
if (-not $NoDashboard) {
    $Dashboard = Start-Process -FilePath $Streamlit -ArgumentList "run","dashboard\app.py","--server.address","127.0.0.1","--server.headless","true" -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru
    Set-Content -LiteralPath (Join-Path $RunDir "dashboard.pid") -Value $Dashboard.Id
}
Write-Host "CSD: http://127.0.0.1:8001  Dashboard: http://127.0.0.1:8501"


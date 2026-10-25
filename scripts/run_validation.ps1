$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
& $Python -m validation.run_validation
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -m validation.run_benchmarks @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -m validation.analyze_results
exit $LASTEXITCODE

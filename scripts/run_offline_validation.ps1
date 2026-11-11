$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}

$python = (Resolve-Path ".venv\Scripts\python.exe").Path
& $python -m pip install -r requirements.txt -r requirements-member-b.txt -r requirements-member-c.txt

$env:PYTHONPATH = Join-Path (Get-Location) "src"
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"

if (-not $env:CYBERHEAL_OPA_EXE) {
    Write-Error "OPA is required. Set CYBERHEAL_OPA_EXE to the official OPA executable and rerun."
}
if (-not (Test-Path $env:CYBERHEAL_OPA_EXE -PathType Leaf)) {
    Write-Error "CYBERHEAL_OPA_EXE does not point to a file: $env:CYBERHEAL_OPA_EXE"
}

& $python -m compileall -q src
# Do not silently omit the symlink traversal protection test. On older Windows
# systems this can require Developer Mode or an elevated terminal. If it fails,
# enable symlink support or rerun inside WSL/Linux; do not claim a full pass.
& $python -m pytest -q tests
if ($LASTEXITCODE -ne 0) {
    throw 'Python tests failed. If test_hash_scan_blocks_symlinks reports WinError 1314, enable Windows Developer Mode or use WSL, then rerun.'
}
& $env:CYBERHEAL_OPA_EXE test respond/policies -v
if ($LASTEXITCODE -ne 0) { throw 'OPA policy tests failed.' }
& $python -m cyberheal_recover.demo
if ($LASTEXITCODE -ne 0) { throw 'Member C mock demo failed.' }

Write-Host "Offline validation passed. No AWS calls or live recovery occurred."

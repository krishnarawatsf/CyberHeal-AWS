$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '../..')
if (-not (Test-Path '.venv/Scripts/python.exe')) {
    if (Get-Command python -ErrorAction SilentlyContinue) { python -m venv .venv }
    else { py -3 -m venv .venv }
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11+ is required.' }
}
& ./.venv/Scripts/python.exe -m pip install -r requirements.txt -r requirements-member-c.txt -r requirements-member-b.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
New-Item -ItemType Directory -Force work | Out-Null
if (-not (Test-Path 'work/opa.exe')) {
    Invoke-WebRequest 'https://github.com/open-policy-agent/opa/releases/download/v1.0.1/opa_windows_amd64.exe' -OutFile 'work/opa.exe'
}
& ./work/opa.exe version
Write-Host 'Setup finished. See docs/member-b/README.md for tests, demo and API.'

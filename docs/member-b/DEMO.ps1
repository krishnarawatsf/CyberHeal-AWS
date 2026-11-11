$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '../..')
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
& ./.venv/Scripts/python.exe -m cyberheal_investigate.demo --opa ./work/opa.exe
if ($LASTEXITCODE -ne 0) { throw 'Demo failed; inspect the output.' }

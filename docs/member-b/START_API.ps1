$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '../..')
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
$env:CYBERHEAL_OPA_EXE = (Resolve-Path './work/opa.exe').Path
foreach ($role in @('DETECTOR','OPERATOR','INTERNAL')) {
    $name = "CYBERHEAL_${role}_TOKEN"
    if (-not [Environment]::GetEnvironmentVariable($name)) {
        $value = & ./.venv/Scripts/python.exe -c 'import secrets; print(secrets.token_urlsafe(32))'
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
    Write-Host "$name = $([Environment]::GetEnvironmentVariable($name))"
}
Write-Host 'Local development tokens above: keep private, do not screenshot/share. Swagger: http://127.0.0.1:8000/docs'
& ./.venv/Scripts/python.exe -m uvicorn cyberheal_investigate.api:app_from_env --factory --host 127.0.0.1 --port 8000

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptRoot

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $python) {
    Write-Error "Python interpreter not found. Install Python or use py."
    exit 1
}

Write-Host "Running Azure RBAC diff demo..."
& $python.Source rbac_diff.py examples/role-definition-old.json examples/role-definition-new.json
Write-Host "`nRole assignment diff:`n"
& $python.Source rbac_diff.py examples/role-assignment-old.json examples/role-assignment-new.json

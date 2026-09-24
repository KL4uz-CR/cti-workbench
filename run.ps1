$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "Environment not initialized. Run .\setup.ps1 first." -ForegroundColor Yellow
    exit 1
}
& .\.venv\Scripts\python.exe .\src\main.py

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "CTI Workbench v0.5.6 - Setup" -ForegroundColor Cyan

if (-not (Get-Command py -ErrorAction SilentlyContinue) -and -not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python 3 is required. Install Python for Windows, then run this script again." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    if (Get-Command py -ErrorAction SilentlyContinue) { py -3 -m venv .venv }
    else { python -m venv .venv }
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

if (-not (Test-Path ".\config\virustotal.json")) {
    Copy-Item ".\config\virustotal.json.example" ".\config\virustotal.json"
    Write-Host "Created config\virustotal.json - add your VirusTotal API key." -ForegroundColor Yellow
}
if (-not (Test-Path ".\config\abusech.json")) {
    Copy-Item ".\config\abusech.json.example" ".\config\abusech.json"
    Write-Host "Created config\abusech.json - add your abuse.ch Auth-Key." -ForegroundColor Yellow
}

Write-Host "Setup complete." -ForegroundColor Green
Write-Host "1. Add your API keys to the two config JSON files."
Write-Host "2. Run: .\run.ps1"

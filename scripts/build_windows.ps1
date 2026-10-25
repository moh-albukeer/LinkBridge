# PowerShell Build Script for LinkBridge Windows Standalone Package (PyInstaller)
$ErrorActionPreference = "Stop"
Write-Host "=== Building LinkBridge Windows Desktop Package ===" -ForegroundColor Cyan

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

python -m pip install --upgrade pip
python -m pip install -r windows/requirements.txt

pyinstaller --noconfirm --clean `
    --name "LinkBridge" `
    --windowed `
    --paths "$ProjectRoot" `
    "$ProjectRoot/windows/app.py"

Write-Host "Build completed: dist/LinkBridge/LinkBridge.exe" -ForegroundColor Green

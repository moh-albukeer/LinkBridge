@echo off
chcp 65001 >nul
title LinkBridge v1.0.0 — Windows One-Click Builder & Launcher
echo ========================================================
echo   LinkBridge v1.0.0 — Smart Local Clipboard ^& File Bridge
echo   Developed by Mohammed Albukeer (mohammedalbukeer@gmail.com)
echo ========================================================

if exist "dist\LinkBridge-Windows.exe" (
    echo Starting LinkBridge-Windows.exe ...
    start "" "dist\LinkBridge-Windows.exe"
    exit /b 0
)

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] Please install Python 3.11 from Microsoft Store or python.org to build the .exe for the first time.
    pause
    exit /b 1
)

echo [1/2] Installing requirements and building standalone LinkBridge-Windows.exe...
python -m pip install --upgrade pip
python -m pip install -r windows\requirements.txt
pyinstaller --noconfirm --clean --onefile --windowed --noupx --version-file "windows\version_info.txt" --name "LinkBridge-Windows" --paths "." windows\app.py

echo [2/2] Build completed: dist\LinkBridge-Windows.exe
start "" "dist\LinkBridge-Windows.exe"

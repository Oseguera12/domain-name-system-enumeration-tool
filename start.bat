@echo off

REM  DNS Enumeration Tool – Launcher (Windows)
REM  Double-click this file to start the web UI.

cd /d "%~dp0"

echo.
echo ===========================================
echo   DNS Enumeration Tool - Launcher (Windows)
echo ===========================================
echo.

REM Detect Python
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] Python 3 is not installed. Please install it from https://python.org
    pause
    exit /b 1
)

python --version

REM Create virtual environment if it doesn't exist
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Install dependencies
echo [*] Installing dependencies...
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo.
echo [*] Starting DNS Enumeration Tool Web UI...
echo [*] Open http://127.0.0.1:5000 in your browser
echo [*] Press Ctrl+C to stop
echo.

python frontend\app.py
pause

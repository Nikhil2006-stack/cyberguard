@echo off
title CYBERGUARD Platform Launcher
color 0B
echo ====================================================================
echo   CYBERGUARD: LIVE ETHICAL HACKING & DEFENSIVE CYBERSECURITY PLATFORM
echo ====================================================================
echo.

:: Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in system PATH.
    echo Please install Python 3.10+ from https://python.org and check "Add Python to PATH".
    pause
    exit /b 1
)

echo [*] Python detected. Installing / verifying dependencies...
python -m pip install -r requirements.txt --quiet

echo [*] Initializing database and generating classroom demo assets...
python -c "from app import create_app; create_app()"

echo [*] Launching CYBERGUARD Platform...
echo [*] Local URL:     http://localhost:5000
echo [*] Classroom Hotspot target will be displayed in console.
echo.
echo Press Ctrl+C in this terminal window to stop the server.
echo ====================================================================

start http://localhost:5000
python app.py
pause

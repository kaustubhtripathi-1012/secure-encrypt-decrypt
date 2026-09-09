@echo off
title Secure Shield - Message Encryption Platform
echo ========================================================
echo          SECURE SHIELD ENCRYPTION PLATFORM
echo ========================================================
echo.

set VENV_PATH=C:\Users\Public\SecureDecryptVenv
set REQS_PATH=%~dp0requirements.txt
set APP_PATH=%~dp0app.py

:: Prevent Python from trying to write __pycache__ files in this OneDrive workspace
set PYTHONDONTWRITEBYTECODE=1

echo [1/3] Checking Python environment...
if not exist "%VENV_PATH%" (
    echo Virtual environment not found. Creating it now...
    python -m venv "%VENV_PATH%"
    if errorlevel 1 (
        echo Error: Failed to create Python virtual environment. Please ensure Python is installed and added to PATH.
        pause
        exit /b 1
    )
)
echo [OK] Virtual environment found at %VENV_PATH%
echo.

echo [2/3] Checking and installing dependencies...
"%VENV_PATH%\Scripts\pip" install -r "%REQS_PATH%"
if errorlevel 1 (
    echo Error: Failed to install Python dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies verified.
echo.

echo [3/3] Starting server and launching browser...
:: Launch default web browser in 2 seconds (non-blocking)
start /b cmd /c "timeout /t 2 >nul && start http://127.0.0.1:5000"

:: Start the Flask app
"%VENV_PATH%\Scripts\python" "%APP_PATH%"

if errorlevel 1 (
    echo.
    echo Server stopped or failed to start.
    pause
)

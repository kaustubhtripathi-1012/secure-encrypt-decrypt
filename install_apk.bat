@echo off
title Secure Shield - Android APK Installer
echo ========================================================
echo          SECURE SHIELD ANDROID APK INSTALLER
echo ========================================================
echo.

set ADB_PATH=C:\Users\hacrrr\AppData\Local\Android\Sdk\platform-tools\adb.exe
set APK_PATH=%~dp0SecureShield-v1.0.apk

if not exist "%ADB_PATH%" (
    echo [ERROR] ADB not found at %ADB_PATH%
    pause
    exit /b 1
)

if not exist "%APK_PATH%" (
    echo [ERROR] APK not found at %APK_PATH%
    echo Please run build_apk.bat first.
    pause
    exit /b 1
)

echo Checking for connected Android devices or emulators...
"%ADB_PATH%" devices
echo.

echo Installing SecureShield-v1.0.apk...
"%ADB_PATH%" install -r "%APK_PATH%"
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install APK. Please ensure USB Debugging is enabled or an emulator is running.
    pause
    exit /b 1
)

echo.
echo Launching Secure Shield on device...
"%ADB_PATH%" shell am start -n com.example.secureshield/.MainActivity
echo.
echo ========================================================
echo [SUCCESS] App installed and launched on your device!
echo ========================================================
echo.
pause

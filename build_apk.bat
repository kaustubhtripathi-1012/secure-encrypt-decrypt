@echo off
title Secure Shield - Android APK Builder
echo ========================================================
echo          SECURE SHIELD ANDROID APK BUILDER
echo ========================================================
echo.

set JAVA_HOME=C:\Program Files\Java\jdk-25.0.2
set BUILD_WORK_DIR=C:\Users\Public\SecureShieldApp
set PROJECT_DIR=%~dp0
set ANDROID_SRC=%PROJECT_DIR%android
set OUTPUT_APK=%PROJECT_DIR%SecureShield-v1.0.apk

echo [1/4] Checking Java environment...
if not exist "%JAVA_HOME%\bin\java.exe" (
    echo Error: JDK not found at %JAVA_HOME%
    pause
    exit /b 1
)
echo [OK] JDK verified: %JAVA_HOME%
echo.

echo [2/4] Syncing Android project files...
if not exist "%BUILD_WORK_DIR%" (
    mkdir "%BUILD_WORK_DIR%"
)
xcopy /E /I /Y /Q "%ANDROID_SRC%" "%BUILD_WORK_DIR%" >nul
echo [OK] Project synced to build workspace.
echo.

echo [3/4] Compiling and assembling APK with Gradle...
pushd "%BUILD_WORK_DIR%"
call gradlew.bat assembleDebug
if errorlevel 1 (
    popd
    echo.
    echo [ERROR] Build failed! Check Gradle output above.
    pause
    exit /b 1
)
popd
echo [OK] Gradle build successful.
echo.

echo [4/4] Copying generated APK to project folder...
copy /Y "%BUILD_WORK_DIR%\app\build\outputs\apk\debug\app-debug.apk" "%OUTPUT_APK%" >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy APK to destination.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo [SUCCESS] APK generated successfully!
echo Location: %OUTPUT_APK%
echo ========================================================
echo.
pause

@echo off
setlocal
cd /d "%~dp0"
set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot"
if not exist "%JAVA_HOME%\bin\java.exe" (
  echo No se encontro el JDK 25 en la ruta esperada.
  pause
  exit /b 1
)
if not defined ANDROID_HOME set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%ANDROID_HOME%"
set "PATH=%JAVA_HOME%\bin;%ANDROID_HOME%\platform-tools;%PATH%"
call gradlew.bat --no-daemon assembleDebug
if errorlevel 1 (
  echo.
  echo La compilacion fallo. Comprueba que aceptaste las licencias e instalaste Android SDK Platform 36 y Build Tools 36.0.0.
  pause
  exit /b 1
)
echo.
echo APK generado en: app\build\outputs\apk\debug\app-debug.apk
pause

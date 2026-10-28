@echo off
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo No se encontro Node.js. Instala Node.js y vuelve a abrir este archivo.
  pause
  exit /b 1
)

if not defined ADB_PATH if exist "C:\platform-tools\adb.exe" set "ADB_PATH=C:\platform-tools\adb.exe"
if not defined ADB_PATH (
  where adb >nul 2>nul
  if errorlevel 1 (
    echo No se encontro adb.exe. Instala Android Platform Tools o define ADB_PATH.
    pause
    exit /b 1
  )
)

echo Iniciando beta local. Detenla con Ctrl+C.
start "" cmd /c "timeout /t 2 /nobreak ^>nul ^& start http://127.0.0.1:8787"
node server.js
pause

@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop_console.ps1"
if errorlevel 1 (
    echo Claude Local Clean is not running on port 8190.
    if exist server.pid del /q server.pid >nul 2>&1
    pause
    exit /b 1
)

echo Claude Local Clean stopped.
exit /b 0

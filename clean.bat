@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Claude Local Clean

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_console.ps1"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" pause
exit /b %EXIT_CODE%

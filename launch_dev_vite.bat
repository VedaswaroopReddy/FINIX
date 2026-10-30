@echo off
title FINIX - Vite Live Dev Server
cd /d "%~dp0\frontend"

echo ======================================================================
echo                 FINIX VITE LIVE DEVELOPMENT SERVER
echo ======================================================================
echo [*] Starting Vite server on port 5173...
echo [*] Opening your browser at http://localhost:5173...
echo ======================================================================
echo.

start "" cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:5173"
npm run dev

pause

@echo off
title FINIX - Automata & ReDoS Mitigation Platform
cd /d "%~dp0"

echo ======================================================================
echo                 FINIX AUTOMATA & RE-DOS PLATFORM
echo ======================================================================
echo [*] Initializing FINIX Server on port 8000...
echo [*] Launching your web browser at http://localhost:8000...
echo ======================================================================
echo.

:: Automatically open default browser after brief 1s pause
start "" cmd /c "timeout /t 1 /nobreak >nul & start http://localhost:8000"

:: Start zero-dependency Python server
python server.py 8000

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [-] 'python' command failed. Trying 'py -3'...
    py -3 server.py 8000
)

echo.
echo Server closed. Press any key to exit.
pause >nul

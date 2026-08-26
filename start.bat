@echo off
chcp 65001 >nul
title ZEFIRA PANEL
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [Setup] Creating virtual environment...
    where python >nul 2>nul
    if errorlevel 1 (
        where py >nul 2>nul && (py -m venv .venv || goto :error) || goto :nopython
    ) else (
        python -m venv .venv || goto :error
    )
    echo [Setup] Installing dependencies... please wait...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :error
)

echo.
echo  ============================================
echo    ZEFIRA PANEL  ->  http://127.0.0.1:8000
echo    Keep this window OPEN while using panel
echo    First-run password is printed below!
echo  ============================================
echo.

start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8000"
".venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header --no-proxy-headers
pause
goto :eof

:nopython
echo [Error] Python not found! Install from https://www.python.org/downloads/
echo         IMPORTANT: check "Add Python to PATH" during install.
pause
goto :eof
:error
echo [Error] Setup failed. Check messages above.
pause

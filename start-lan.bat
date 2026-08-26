@echo off
chcp 65001 >nul
title ZEFIRA PANEL - LAN/Tunnel mode
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Run start.bat first to install.
    pause
    goto :eof
)

echo.
echo  ============================================================
echo   ZEFIRA PANEL - LAN / TUNNEL MODE
echo   Local:      http://127.0.0.1:8000
echo   LAN/Tunnel: http://^<this-pc-ip^>:8000  or  http://10.8.0.1:8000
echo   Windows Firewall may ask permission - click ALLOW.
echo   Keep this window OPEN while using panel
echo  ============================================================
echo.

start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8000"
".venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8000 --no-server-header --no-proxy-headers --forwarded-allow-ips "*"
pause

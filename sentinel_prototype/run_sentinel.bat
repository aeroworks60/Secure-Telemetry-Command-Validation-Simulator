@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   SENTINEL - Local Satellite Message Security Simulator
echo   Custom Flask Console / Orange Mission-Control Theme
echo ============================================================
echo.
if not exist ".venv\Scripts\python.exe" (
    echo Creating a private Python environment...
    py -3 -m venv .venv 2>nul
    if errorlevel 1 python -m venv .venv
    if errorlevel 1 goto :error
)
echo Installing/checking the required package. First run needs internet.
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :error
echo.
echo Starting Sentinel on this computer only.
echo Keep this terminal window open while using Sentinel.
echo The browser should open at http://127.0.0.1:8765
echo.
".venv\Scripts\python.exe" app.py
if errorlevel 1 goto :error
goto :eof
:error
echo.
echo Sentinel could not start. Check the error shown above.
echo Confirm Python 3.10+ is installed and internet is available for first-time package setup.
echo You can follow README.md for manual launch steps.
pause

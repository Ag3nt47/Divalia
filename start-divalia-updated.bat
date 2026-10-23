@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Divalia's project virtual environment is missing.
    echo Follow README.md to create .venv and install Divalia first.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" "tools\update_divalia.py" --run watch
exit /b %ERRORLEVEL%

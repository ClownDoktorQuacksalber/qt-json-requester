@echo off
cd /d "%~dp0"

echo =============================
echo   QtPy JSON Client Starter
echo =============================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo Python wurde nicht gefunden!
    pause
    exit /b 1
)

if not exist ".venv\" (
    echo Erstelle virtuelle Umgebung...
    python -m venv .venv
)

call ".venv\Scripts\activate"

echo Aktualisiere pip...
python -m pip install --upgrade pip >nul

if exist requirements.txt (
    echo Installiere Requirements...
    pip install -r requirements.txt
) else (
    echo requirements.txt nicht gefunden — installiere Standardpakete...
    pip install qtpy PyQt6 requests
)

echo.
echo Starte Programm...
echo.

python app.py
pause
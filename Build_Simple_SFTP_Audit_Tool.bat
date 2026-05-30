@echo off
REM ============================================================
REM Build script for Simple SFTP Audit Tool - standalone Windows exe
REM Author: JDE-Projects
REM ============================================================
REM
REM This script will:
REM   1. Verify Python and Git are installed
REM   2. Create a virtual environment (to keep things clean)
REM   3. Install pywebview + PyQt6, ssh-audit (GitHub master), PyInstaller
REM   4. Build a standalone exe that requires NO dependencies
REM
REM The resulting exe in dist\ can be copied to any Windows PC and
REM runs without Python, Git, or anything else installed.
REM
REM NOTE: ssh-audit is pulled from the GitHub master branch instead of
REM the PyPI release. PyPI lags master (often 1+ years), so master gives
REM up-to-date algorithm coverage, post-quantum warnings, and policies.
REM ============================================================

echo.
echo ============================================================
echo   Simple SFTP Audit Tool - Standalone Executable Builder
echo ============================================================
echo.

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.9+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

REM Check for Git (required to pull ssh-audit from GitHub master)
git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed or not in PATH.
    echo Please install Git for Windows from https://git-scm.com
    echo Git is required to pull the latest ssh-audit from GitHub.
    pause
    exit /b 1
)

echo [1/5] Creating virtual environment...
python -m venv build_env
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment.
    pause
    exit /b 1
)

echo [2/5] Activating virtual environment...
call build_env\Scripts\activate.bat

echo [3/5] Installing dependencies...
echo       (pywebview + PyQt6, ssh-audit from GitHub master, PyInstaller)
pip install --upgrade pip >nul
pip install pywebview PyQt6 PyQt6-WebEngine qtpy pyinstaller
if errorlevel 1 (
    echo ERROR: Failed to install UI / build dependencies.
    pause
    exit /b 1
)
pip install git+https://github.com/jtesta/ssh-audit.git
if errorlevel 1 (
    echo ERROR: Failed to install ssh-audit from GitHub.
    pause
    exit /b 1
)

echo [4/5] Building standalone executable...
echo       This may take a few minutes (Qt is large)...
pyinstaller --onefile --windowed --name "Simple SFTP Audit Tool" ^
    --icon "simple_sftp_audit_tool.ico" ^
    --splash "simple_sftp_audit_tool-splash.png" ^
    --add-data "simple_sftp_audit_tool-UI.html;." ^
    --add-data "simple_sftp_audit_tool.png;." ^
    --add-data "fonts;fonts" ^
    --collect-all PyQt6 ^
    --collect-all qtpy ^
    --collect-all webview ^
    simple_sftp_audit_tool.py

if errorlevel 1 (
    echo ERROR: Build failed.
    pause
    exit /b 1
)

echo [5/5] Cleaning up...
deactivate
rmdir /s /q build_env 2>nul
rmdir /s /q build 2>nul
del /q "*.spec" 2>nul

echo.
echo ============================================================
echo   BUILD SUCCESSFUL!
echo ============================================================
echo.
echo Your standalone executable is ready:
echo.
echo   dist\Simple SFTP Audit Tool.exe
echo.
echo This file can be copied to ANY Windows computer and will
echo work without Python or any other software installed!
echo.
echo ============================================================
pause

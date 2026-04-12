@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================================
REM Vulntron - Installation Setup
REM
REM Usage:
REM   setup.bat           Install all dependencies
REM   setup.bat -h        Show this help
REM   setup.bat --help    Show this help
REM ============================================================================

title Vulntron - Installation Setup
color 0A

REM UTF-8 friendly environment
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

REM Handle help flag
if /i "%~1"=="-h"     goto :show_help
if /i "%~1"=="--help" goto :show_help

cls
echo.
echo ===============================================================================
echo.
echo        VULNTRON - INSTALLATION WIZARD
echo.
echo ===============================================================================
echo.

REM Check Python
echo [*] Checking Python installation...
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Python is not installed!
    echo.
    echo [+] Opening Python download page...
    start https://www.python.org/downloads/
    echo.
    echo     Please install Python 3.11+ and run this setup again.
    echo.
    pause
    exit /b 1
)

echo [+] Python found:
python --version
echo.

REM Check for requirements.txt
if not exist "%~dp0requirements.txt" (
    echo [!] requirements.txt not found in script directory.
    echo     Please run this script from the Vulntron repository root.
    echo.
    pause
    exit /b 1
)

REM Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip
if !errorlevel! neq 0 (
    echo [!] Failed to upgrade pip. Continuing with existing pip version.
)
echo.

REM Install from requirements.txt
echo [*] Installing dependencies from requirements.txt...
python -m pip install -r "%~dp0requirements.txt"
if !errorlevel! neq 0 (
    color 0C
    echo.
    echo [!] Some dependencies failed to install.
    echo     Review the errors above, then re-run setup.bat.
    echo.
    pause
    exit /b 1
)

REM Optional: install pywinrm for WinRM-based credentialed scanning
echo.
echo [*] Installing optional WinRM support (pywinrm)...
python -m pip install pywinrm --quiet
if !errorlevel! neq 0 (
    echo [!] pywinrm could not be installed - WinRM credentialed scanning will not work.
    echo     This is optional; all other scan modes will still work.
)

color 0A
echo.
echo ===============================================================================
echo.
echo [+] INSTALLATION COMPLETE!
echo.
echo ===============================================================================
echo.
echo NEXT STEPS:
echo.
echo 1. Run a quick scan:
echo      vultron-quick-scan.bat
echo.
echo 2. Run a local host assessment:
echo      vultron-local.bat
echo.
echo 3. Run a network vulnerability scan:
echo      vultron-network.bat
echo.
echo 4. Run a comprehensive scan (all ports, full CVE history):
echo      vultron-comprehensive-scan.bat
echo.
echo 5. Launch the local Vulntron UI dashboard:
echo      python vultron.py ui --data-dir . --open-browser
echo.
echo 6. Get an NVD API key (free) to enable CVE lookups:
echo      https://nvd.nist.gov/developers/request-an-api-key
echo.
echo ===============================================================================
echo.
pause
endlocal
exit /b 0

:show_help
echo.
echo   Vulntron Setup - Installs all Python dependencies.
echo.
echo   Usage:
echo     setup.bat           Install all dependencies from requirements.txt
echo     setup.bat -h        Show this help message
echo     setup.bat --help    Show this help message
echo.
echo   Requirements: Python 3.11+ must already be installed.
echo   Download Python: https://www.python.org/downloads/
echo.
exit /b 0

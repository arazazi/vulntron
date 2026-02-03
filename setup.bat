@echo off
REM ============================================================================
REM Vultron v2.0 - Automated Setup Script
REM This script will:
REM   1. Check if Python 3.12+ is installed
REM   2. Install Python if needed
REM   3. Install required dependencies
REM   4. Verify installation
REM ============================================================================

echo.
echo ========================================
echo    VULTRON v2.0 - Setup Wizard
echo ========================================
echo.

REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: This script must be run as Administrator!
    echo [!] Right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo [+] Running with Administrator privileges
echo.

REM ============================================================================
REM Step 1: Check if Python is installed
REM ============================================================================

echo [*] Checking for Python installation...
python --version >nul 2>&1

if %errorLevel% equ 0 (
    echo [+] Python is already installed
    python --version
    goto :check_version
) else (
    echo [!] Python is not installed
    goto :install_python
)

:check_version
REM Extract Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i

REM Check if version is 3.12 or higher
echo [*] Checking Python version: %PYTHON_VERSION%

REM Simple version check (assumes format 3.x.y)
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

if %MAJOR% LSS 3 (
    echo [!] Python version is too old (need 3.12+)
    goto :install_python
)

if %MAJOR% EQU 3 (
    if %MINOR% LSS 12 (
        echo [!] Python version is too old (need 3.12+, found %PYTHON_VERSION%)
        echo [*] Upgrading Python...
        goto :install_python
    )
)

echo [+] Python version is compatible: %PYTHON_VERSION%
goto :install_requirements

REM ============================================================================
REM Step 2: Install Python
REM ============================================================================

:install_python
echo.
echo ========================================
echo    Installing Python 3.12
echo ========================================
echo.

echo [*] Downloading Python 3.12 installer...

REM Create temp directory
if not exist "%TEMP%\vultron_setup" mkdir "%TEMP%\vultron_setup"

REM Download Python installer using PowerShell
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\vultron_setup\python_installer.exe'}"

if %errorLevel% neq 0 (
    echo [!] ERROR: Failed to download Python installer
    echo [!] Please download and install Python 3.12+ manually from:
    echo [!] https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [+] Download complete
echo [*] Installing Python (this may take a few minutes)...

REM Install Python silently with pip and add to PATH
"%TEMP%\vultron_setup\python_installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1

if %errorLevel% neq 0 (
    echo [!] ERROR: Python installation failed
    echo [!] Please install Python 3.12+ manually from:
    echo [!] https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [+] Python installation complete
echo [*] Refreshing environment variables...

REM Refresh PATH
call refreshenv >nul 2>&1

REM Verify installation
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Python installed but not found in PATH
    echo [!] Please restart your computer and run this script again
    echo.
    pause
    exit /b 1
)

echo [+] Python is now available
python --version

REM Clean up installer
del "%TEMP%\vultron_setup\python_installer.exe" >nul 2>&1

REM ============================================================================
REM Step 3: Install Requirements
REM ============================================================================

:install_requirements
echo.
echo ========================================
echo    Installing Dependencies
echo ========================================
echo.

echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

if %errorLevel% neq 0 (
    echo [!] WARNING: Failed to upgrade pip, continuing anyway...
)

echo [+] Pip upgraded

echo [*] Installing colorama...
python -m pip install colorama --quiet

if %errorLevel% neq 0 (
    echo [!] ERROR: Failed to install colorama
    pause
    exit /b 1
)
echo [+] colorama installed

echo [*] Installing requests...
python -m pip install requests --quiet

if %errorLevel% neq 0 (
    echo [!] ERROR: Failed to install requests
    pause
    exit /b 1
)
echo [+] requests installed

echo [*] Installing psutil...
python -m pip install psutil --quiet

if %errorLevel% neq 0 (
    echo [!] WARNING: Failed to install psutil (optional)
    echo [*] Continuing without psutil...
) else (
    echo [+] psutil installed
)

REM ============================================================================
REM Step 4: Verify Installation
REM ============================================================================

echo.
echo ========================================
echo    Verifying Installation
echo ========================================
echo.

echo [*] Checking installed packages...

python -c "import colorama; print('[+] colorama: OK')" 2>nul
if %errorLevel% neq 0 (
    echo [!] colorama: FAILED
    set INSTALL_FAILED=1
)

python -c "import requests; print('[+] requests: OK')" 2>nul
if %errorLevel% neq 0 (
    echo [!] requests: FAILED
    set INSTALL_FAILED=1
)

python -c "import psutil; print('[+] psutil: OK')" 2>nul
if %errorLevel% neq 0 (
    echo [*] psutil: Not installed (optional)
)

if defined INSTALL_FAILED (
    echo.
    echo [!] Some packages failed to install
    echo [!] Please check the errors above
    pause
    exit /b 1
)

REM ============================================================================
REM Step 5: Create Launcher Scripts
REM ============================================================================

echo.
echo [*] Creating launcher scripts...

REM Create comprehensive scan launcher
(
echo @echo off
echo echo Starting Vultron v2.0 - COMPREHENSIVE SCAN
echo echo.
echo python vultron_v2.py
echo pause
) > "vultron_comprehensive.bat"

echo [+] Created: vultron_comprehensive.bat

REM Create quick scan launcher
(
echo @echo off
echo echo Starting Vultron v2.0 - QUICK SCAN
echo echo.
echo echo 2 ^| python vultron_v2.py
echo pause
) > "vultron_quick.bat"

echo [+] Created: vultron_quick.bat

REM ============================================================================
REM Completion
REM ============================================================================

echo.
echo ========================================
echo    Setup Complete!
echo ========================================
echo.
echo [+] Vultron v2.0 is ready to use
echo.
echo NEXT STEPS:
echo   1. Run vultron_comprehensive.bat for full scan (recommended)
echo   2. Run vultron_quick.bat for quick scan
echo   3. Or run: python vultron_v2.py
echo.
echo NOTE: All scripts must be run as Administrator
echo.

pause

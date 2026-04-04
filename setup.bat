@echo off
title VULTRON v4.0 - Installation Setup
color 0A
cls

echo.
echo ===============================================================================
echo.
echo      ╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦4.0 - ULTIMATE SETUP
echo      ╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝
echo       ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝   ╚╝
echo.
echo                   INSTALLATION WIZARD
echo.
echo ===============================================================================
echo.

echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed!
    echo.
    echo [+] Downloading Python 3.12...
    echo [+] Opening Python download page...
    start https://www.python.org/downloads/
    echo.
    echo Please install Python 3.12+ and run this setup again.
    pause
    exit /b 1
)

echo [+] Python found!
python --version
echo.

echo [*] Upgrading pip...
python -m pip install --upgrade pip
echo.

echo [*] Installing required dependencies...
echo.
echo [1/6] Installing colorama (terminal colors)...
pip install colorama --quiet

echo [2/6] Installing requests (HTTP library)...
pip install requests --quiet

echo [3/6] Installing psutil (system info)...
pip install psutil --quiet

echo [4/6] Installing pywinrm (optional - remote scanning)...
pip install pywinrm --quiet

echo [5/6] Installing impacket (optional - SMB tools)...
pip install impacket --quiet

echo [6/6] Installing beautifulsoup4 (optional - web parsing)...
pip install beautifulsoup4 --quiet

echo.
echo ===============================================================================
echo.
echo [+] INSTALLATION COMPLETE!
echo.
echo Dependencies installed:
echo   - colorama (terminal colors)
echo   - requests (HTTP/API calls)
echo   - psutil (system information)
echo   - pywinrm (remote Windows management)
echo   - impacket (network protocols)
echo   - beautifulsoup4 (web scraping)
echo.
echo ===============================================================================
echo.
echo NEXT STEPS:
echo.
echo 1. Get NVD API key (FREE):
echo    https://nvd.nist.gov/developers/request-an-api-key
echo.
echo 2. Add API key to vultron_v4_ultimate.py (line 38):
echo    NVD_API_KEY = "your-api-key-here"
echo.
echo 3. Run a scan:
echo    - vultron_local.bat       (Deep local forensics)
echo    - vultron_network.bat     (Network vulnerability scan)
echo    - vultron_ultimate.bat    (Complete assessment)
echo.
echo ===============================================================================
echo.
pause

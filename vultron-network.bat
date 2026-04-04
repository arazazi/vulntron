@echo off
title VULTRON v4.0 - Network Scan Mode
color 0E
cls

echo.
echo ===============================================================================
echo.
echo      ╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦4.0 - NETWORK SCANNER
echo      ╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝
echo       ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝   ╚╝
echo.
echo          ACTIVE VULNERABILITY SCANNING
echo.
echo ===============================================================================
echo.
echo [*] Mode: NETWORK VULNERABILITY ASSESSMENT
echo [*] Features:
echo     - Port scanning (150+ services)
echo     - Service version detection
echo     - Active exploitation checks
echo     - EternalBlue/BlueKeep/SMBGhost detection
echo     - Web server vulnerability scanning
echo     - Database security assessment
echo     - SSL/TLS configuration testing
echo     - Compliance validation (PCI DSS, CIS)
echo.
echo ===============================================================================
echo.

set /p target="[?] Enter target IP or hostname: "

if "%target%"=="" (
    echo [!] Error: No target specified!
    pause
    exit /b 1
)

echo.
echo [*] Target: %target%
echo.
echo [?] Scan options:
echo    1 - Quick scan (common ports only)
echo    2 - Full scan (all 65535 ports)
echo    3 - Custom port range
echo.
set /p choice="Select option (1-3): "

if "%choice%"=="1" (
    echo [*] Running quick scan...
    python vultron_v4_ultimate.py -t %target% --quick
) else if "%choice%"=="2" (
    echo [*] Running full port scan...
    python vultron_v4_ultimate.py -t %target% -p 1-65535
) else if "%choice%"=="3" (
    set /p portrange="[?] Enter port range (e.g., 1-10000): "
    echo [*] Scanning ports: !portrange!
    python vultron_v4_ultimate.py -t %target% -p !portrange!
) else (
    echo [!] Invalid choice!
    pause
    exit /b 1
)

echo.
echo ===============================================================================
echo.
echo [+] SCAN COMPLETE!
echo.
echo Reports generated in current directory.
echo.
echo ===============================================================================
echo.
pause

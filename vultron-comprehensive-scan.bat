@echo off
REM ============================================================================
REM Vultron v2.0 - COMPREHENSIVE SCAN
REM 
REM This mode performs:
REM   - Full CVE scan from 2015 to present (ALL historical vulnerabilities)
REM   - 15+ forensic artifact types
REM   - Deep threat hunting
REM   - Complete persistence analysis
REM 
REM Estimated time: 3-5 minutes
REM Recommended for: Old Windows 10 systems, thorough audits, compliance
REM ============================================================================

title Vultron v2.0 - COMPREHENSIVE SECURITY SCAN

REM Set console colors
color 0B

echo.
echo ===============================================================================
echo.
echo     ██╗   ██╗██╗   ██╗██╗  ████████╗██████╗  ██████╗ ███╗   ██╗
echo     ██║   ██║██║   ██║██║  ╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
echo     ██║   ██║██║   ██║██║     ██║   ██████╔╝██║   ██║██╔██╗ ██║
echo     ╚██╗ ██╔╝██║   ██║██║     ██║   ██╔══██╗██║   ██║██║╚██╗██║
echo      ╚████╔╝ ╚██████╔╝███████╗██║   ██║  ██║╚██████╔╝██║ ╚████║
echo       ╚═══╝   ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
echo.
echo                    Windows Security Auditor v2.0
echo                          COMPREHENSIVE SCAN MODE
echo.
echo ===============================================================================
echo.

REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo.
    echo    [!] ERROR: Administrator privileges required!
    echo.
    echo    Please right-click this file and select "Run as Administrator"
    echo.
    echo ===============================================================================
    echo.
    pause
    exit /b 1
)

echo [+] Running with Administrator privileges
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    color 0E
    echo.
    echo    [!] ERROR: Python not found!
    echo.
    echo    Please run setup.bat first to install Python and dependencies
    echo.
    echo ===============================================================================
    echo.
    pause
    exit /b 1
)

REM Check if vultron.py exists
if not exist "vultron.py" (
    color 0E
    echo.
    echo    [!] ERROR: vultron.py not found!
    echo.
    echo    Please ensure vultron_v2.py is in the same directory as this script
    echo.
    echo ===============================================================================
    echo.
    pause
    exit /b 1
)

echo [*] Python version: 
python --version
echo.

echo ===============================================================================
echo.
echo    COMPREHENSIVE SCAN MODE SELECTED
echo.
echo    This scan will:
echo      [✓] Query ALL CVEs from 2015-present
echo      [✓] Analyze 15+ forensic artifact types
echo      [✓] Deep threat hunting and persistence analysis
echo      [✓] Generate comprehensive HTML and JSON reports
echo.
echo    Estimated time: 3-5 minutes
echo    Perfect for: Legacy systems, thorough audits, compliance checks
echo.
echo ===============================================================================
echo.
echo [*] Press any key to start the comprehensive scan...
pause >nul

echo.
echo [*] Starting Vultron v2.0...
echo.

REM Auto-select comprehensive mode (option 1 or just Enter)
echo. | python vultron.py

REM Check if scan completed successfully
if %errorLevel% neq 0 (
    color 0C
    echo.
    echo ===============================================================================
    echo.
    echo    [!] Scan encountered errors!
    echo.
    echo    Please review the errors above and try again.
    echo.
    echo ===============================================================================
    echo.
    pause
    exit /b 1
)

REM Success!
color 0A
echo.
echo ===============================================================================
echo.
echo    [✓] SCAN COMPLETE!
echo.
echo    Reports generated:
echo      - vultron_report.html (Interactive dashboard)
echo      - vultron_report.json (Machine-readable data)
echo.
echo    Opening HTML report...
echo.
echo ===============================================================================
echo.

REM Open HTML report if it exists
if exist "vultron_report.html" (
    start vultron_report.html
) else (
    echo [!] HTML report not found
)

echo.
echo [*] Press any key to exit...
pause >nul

@echo off
REM ============================================================================
REM Vultron v2.0 - QUICK SCAN
REM 
REM This mode performs:
REM   - CVE scan for last 120 days only
REM   - 15+ forensic artifact types (same as comprehensive)
REM   - Fast threat detection
REM   - Essential persistence analysis
REM 
REM Estimated time: 1-2 minutes
REM Recommended for: Recently updated systems, quick checks
REM ============================================================================

title Vultron v2.0 - QUICK SECURITY SCAN

REM Set console colors
color 0E

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
echo                              QUICK SCAN MODE
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
    color 0C
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
    color 0C
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
echo    QUICK SCAN MODE SELECTED
echo.
echo    This scan will:
echo      [✓] Query CVEs from last 120 days
echo      [✓] Analyze 15+ forensic artifact types
echo      [✓] Fast threat detection
echo      [✓] Generate HTML and JSON reports
echo.
echo    Estimated time: 1-2 minutes
echo    Perfect for: Recently patched systems, quick security checks
echo.
echo    NOTE: For legacy systems or thorough audits, use COMPREHENSIVE mode
echo.
echo ===============================================================================
echo.
echo [*] Press any key to start the quick scan...
pause >nul

echo.
echo [*] Starting Vultron v2.0 in Quick Mode...
echo.

REM Auto-select quick mode (option 2)
echo 2 | python vultron.py

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
echo    [✓] QUICK SCAN COMPLETE!
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

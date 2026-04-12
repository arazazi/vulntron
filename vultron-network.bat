@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================================
REM Vulntron - Network Vulnerability Scan
REM
REM Performs an active vulnerability assessment against a network target.
REM Includes port scanning, service detection, CVE correlation, TLS inspection,
REM compliance baseline, and optional web scanning.
REM
REM Usage:
REM   vultron-network.bat [target]    Scan target (prompted if omitted)
REM   vultron-network.bat -h          Show this help
REM   vultron-network.bat --help      Show this help
REM ============================================================================

title Vulntron - Network Vulnerability Scan
color 0E

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
echo        VULNTRON - NETWORK VULNERABILITY ASSESSMENT
echo.
echo ===============================================================================
echo.
echo [*] Features:
echo     - Port scanning (common / top-1000 / full 65535)
echo     - Service version detection
echo     - CVE correlation (NVD)
echo     - TLS/SSL configuration inspection
echo     - Compliance baseline (CIS, PCI DSS)
echo     - Optional web application scanning (P8 -- opt-in)
echo.
echo ===============================================================================
echo.

REM ------------------------------------------------------------------
REM Resolve invocation: prefer installed 'vulntron', else python module
REM ------------------------------------------------------------------
call :resolve_vulntron
if !errorlevel! neq 0 (
    pause
    exit /b 1
)
echo [*] Invocation: !VULNTRON_CMD!
echo.

REM Accept target from command line or prompt
set "TARGET=%~1"
if "!TARGET!"=="" (
    set /p TARGET="[?] Enter target IP or hostname: "
)
if "!TARGET!"=="" (
    echo [!] Error: No target specified.
    echo.
    pause
    exit /b 1
)

echo.
echo [*] Target: !TARGET!
echo.

REM Scan mode selection
echo [?] Scan depth:
echo    1 - Quick    (common ports, last 120 days CVEs)
echo    2 - Standard (top 1000 ports, last 365 days CVEs)  [recommended]
echo    3 - Full     (all 65535 ports, full CVE history)
echo    4 - Custom   (specify port range)
echo.
set /p _choice="Select option (1-4) [2]: "
if "!_choice!"=="" set _choice=2

if "!_choice!"=="1" (
    set SCAN_MODE=common
    set CVE_DAYS=120
    set PORT_EXTRA=
) else if "!_choice!"=="2" (
    set SCAN_MODE=top1000
    set CVE_DAYS=365
    set PORT_EXTRA=
) else if "!_choice!"=="3" (
    set SCAN_MODE=full
    set CVE_DAYS=3650
    set PORT_EXTRA=
) else if "!_choice!"=="4" (
    set /p _ports="[?] Enter port range (e.g., 1-10000): "
    if "!_ports!"=="" (
        echo [!] No port range specified. Defaulting to top1000.
        set SCAN_MODE=top1000
        set CVE_DAYS=365
        set PORT_EXTRA=
    ) else (
        set SCAN_MODE=custom
        set CVE_DAYS=365
        set PORT_EXTRA=--ports !_ports!
    )
) else (
    echo [!] Invalid choice. Defaulting to Standard scan.
    set SCAN_MODE=top1000
    set CVE_DAYS=365
    set PORT_EXTRA=
)

echo.
echo [*] Mode: !SCAN_MODE! / CVE lookback: !CVE_DAYS! days
echo.

REM Web scanning opt-in
echo [?] Enable web application scanning?
echo     (Performs read-only, non-destructive checks on HTTP/HTTPS services)
echo.
set /p _webscan="    Enable web scan? (y/N): "
set WEB_SCAN_FLAG=
if /i "!_webscan!"=="y" (
    set WEB_SCAN_FLAG=--web-scan
    echo [*] Web scanning ENABLED (read-only, non-destructive)
) else (
    echo [*] Web scanning DISABLED
)
echo.

REM Create timestamped output directory
for /f "tokens=1-6 delims=/:. " %%a in ("%date% %time%") do (
    set _D=%%a%%b%%c
    set _T=%%d%%e%%f
)
set RUNS_DIR=%~dp0runs
set OUT_DIR=%RUNS_DIR%\!_D!_!_T!
if not exist "!RUNS_DIR!" mkdir "!RUNS_DIR!"
if not exist "!OUT_DIR!" mkdir "!OUT_DIR!"
echo [*] Output directory: !OUT_DIR!
echo.

echo [*] Starting network assessment...
echo.

!VULNTRON_CMD! -t "!TARGET!" ^
    --scan-mode !SCAN_MODE! ^
    --cve-lookback-days !CVE_DAYS! ^
    !PORT_EXTRA! !WEB_SCAN_FLAG!

if !errorlevel! neq 0 (
    color 0C
    echo.
    echo [!] Scan encountered errors. Review the output above.
    echo.
    pause
    exit /b 1
)

REM Move generated reports into the output directory
color 0A
for %%f in ("%~dp0vultron_hybrid_*.html" "%~dp0vultron_hybrid_*.json") do (
    if exist "%%f" move /y "%%f" "!OUT_DIR!\" >nul
)

echo.
echo ===============================================================================
echo.
echo [+] NETWORK ASSESSMENT COMPLETE!
echo.
echo     Reports saved to: !OUT_DIR!
echo       - vultron_hybrid_*.html  (Interactive HTML report)
echo       - vultron_hybrid_*.json  (Machine-readable JSON)
echo.
echo ===============================================================================
echo.

REM Offer to open HTML report
set /p _open="[?] Open HTML report in browser? (Y/n): "
if /i "!_open!"=="n" goto :offer_ui
for %%f in ("!OUT_DIR!\vultron_hybrid_*.html") do (
    if exist "%%f" start "" "%%f"
)

:offer_ui
echo.
set /p _ui="[?] Launch Vulntron UI dashboard (browse all runs)? (y/N): "
if /i "!_ui!"=="y" (
    echo.
    echo [*] Starting Vulntron UI on http://127.0.0.1:8000 ...
    echo     Press Ctrl+C to stop the UI server.
    echo.
    !VULNTRON_CMD! ui --data-dir "!RUNS_DIR!" --open-browser
)

echo.
pause
endlocal
exit /b 0

:show_help
echo.
echo   Vulntron Network Vulnerability Scan
echo.
echo   Usage:
echo     vultron-network.bat                   Prompt for target and options
echo     vultron-network.bat 192.168.1.100     Scan specific target
echo     vultron-network.bat -h / --help       Show this help
echo.
echo   Scan depths:
echo     1 - Quick    common ports, 120-day CVEs
echo     2 - Standard top-1000 ports, 365-day CVEs  (default)
echo     3 - Full     all 65535 ports, full CVE history
echo     4 - Custom   user-specified port range
echo.
echo   Web scanning (--web-scan) is opt-in. It is read-only and non-destructive.
echo   Output is written to: runs\TIMESTAMP\
echo.
exit /b 0

REM ------------------------------------------------------------------
REM Subroutine: resolve vulntron invocation
REM ------------------------------------------------------------------
:resolve_vulntron
set VULNTRON_CMD=
where vulntron >nul 2>&1
if !errorlevel! equ 0 (
    set VULNTRON_CMD=vulntron
    exit /b 0
)
if exist "%~dp0venv\Scripts\python.exe" (
    set VULNTRON_CMD="%~dp0venv\Scripts\python.exe" -m vulntron
    exit /b 0
)
python -m vulntron --version >nul 2>&1
if !errorlevel! equ 0 (
    set VULNTRON_CMD=python -m vulntron
    exit /b 0
)
if exist "%~dp0vultron.py" (
    set VULNTRON_CMD=python "%~dp0vultron.py"
    exit /b 0
)
echo [!] ERROR: Cannot find Vulntron. Run setup.bat first.
exit /b 1

@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================================
REM Vulntron - Comprehensive Security Scan
REM
REM Full port scan (1-65535) with complete CVE history (2015-present),
REM TLS inspection, compliance baseline, asset inventory, and optional
REM web application scanning.  Recommended for audits and compliance checks.
REM
REM Estimated time: 3-10 minutes depending on target responsiveness.
REM
REM Usage:
REM   vultron-comprehensive-scan.bat [target]   Scan target (prompt if omitted)
REM   vultron-comprehensive-scan.bat -h         Show this help
REM   vultron-comprehensive-scan.bat --help     Show this help
REM ============================================================================

title Vulntron - Comprehensive Security Scan
color 0B

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
echo        VULNTRON - COMPREHENSIVE SECURITY SCAN
echo.
echo ===============================================================================
echo.
echo [*] Mode:     Full port scan (1-65535) + complete CVE history
echo [*] Features:
echo     - Full port range scan
echo     - CVE correlation (2015-present)
echo     - TLS/SSL deep inspection
echo     - Asset inventory
echo     - Compliance baseline (CIS, PCI DSS)
echo     - Optional web application scanning (opt-in)
echo.
echo [*] Estimated time: 3-10 minutes
echo [*] Best for: Legacy systems, audits, compliance checks
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
    set /p TARGET="[?] Enter target IP or hostname (or press Enter for localhost): "
)
if "!TARGET!"=="" set TARGET=127.0.0.1

echo.
echo [*] Target: !TARGET!
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

echo [!] NOTE: For best results, right-click and "Run as Administrator".
echo.
echo [*] Press any key to start the comprehensive scan...
pause >nul

echo.
echo [*] Starting Vulntron comprehensive scan...
echo.

!VULNTRON_CMD! -t "!TARGET!" ^
    --scan-mode full ^
    --cve-lookback-days 3650 ^
    !WEB_SCAN_FLAG!

if !errorlevel! neq 0 (
    color 0C
    echo.
    echo ===============================================================================
    echo.
    echo [!] Scan encountered errors. Review the output above.
    echo.
    echo ===============================================================================
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
echo [+] COMPREHENSIVE SCAN COMPLETE!
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
echo [*] Press any key to exit...
pause >nul
endlocal
exit /b 0

:show_help
echo.
echo   Vulntron Comprehensive Security Scan
echo.
echo   Usage:
echo     vultron-comprehensive-scan.bat                   Prompt for target
echo     vultron-comprehensive-scan.bat 192.168.1.100     Scan specific target
echo     vultron-comprehensive-scan.bat -h / --help       Show this help
echo.
echo   Performs a full 65535-port scan with complete CVE history (2015-present),
echo   TLS inspection, asset inventory, and compliance baseline.
echo   Web scanning is opt-in (read-only, non-destructive).
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

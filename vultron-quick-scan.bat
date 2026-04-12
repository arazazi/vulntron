@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================================
REM Vulntron - Quick Scan
REM
REM Performs a fast scan of common ports against a target, using CVEs from
REM the last 120 days only.  Suitable for quick health-checks.
REM
REM Usage:
REM   vultron-quick-scan.bat [target]   Scan target (prompt if omitted)
REM   vultron-quick-scan.bat -h         Show this help
REM   vultron-quick-scan.bat --help     Show this help
REM ============================================================================

title Vulntron - Quick Scan
color 0A

REM UTF-8 friendly environment
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

REM Handle help / no-args
if /i "%~1"=="-h"     goto :show_help
if /i "%~1"=="--help" goto :show_help

cls
echo.
echo ===============================================================================
echo.
echo        VULNTRON - QUICK SCAN
echo.
echo ===============================================================================
echo.
echo [*] Mode:     Common ports, last 120 days of CVEs
echo [*] Speed:    Fast (suitable for quick health-checks)
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

echo [*] Starting quick scan...
echo.

!VULNTRON_CMD! -t "!TARGET!" --scan-mode common --cve-lookback-days 120

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
set "_safe_target=!TARGET::=-!"
set "_safe_target=!_safe_target:/=-!"
for %%f in ("%~dp0vultron_hybrid_*.html" "%~dp0vultron_hybrid_*.json") do (
    if exist "%%f" move /y "%%f" "!OUT_DIR!\" >nul
)

echo.
echo ===============================================================================
echo.
echo [+] QUICK SCAN COMPLETE!
echo.
echo     Reports saved to: !OUT_DIR!
echo       - vultron_hybrid_*.html  (Interactive HTML report)
echo       - vultron_hybrid_*.json  (Machine-readable JSON)
echo.
echo ===============================================================================
echo.

REM Offer to open HTML report
set /p _open="[?] Open HTML report in browser? (Y/n): "
if /i "!_open!"=="n" goto :done
for %%f in ("!OUT_DIR!\vultron_hybrid_*.html") do (
    if exist "%%f" start "" "%%f"
)

:done
echo.
pause
endlocal
exit /b 0

:show_help
echo.
echo   Vulntron Quick Scan - Fast vulnerability health-check.
echo.
echo   Usage:
echo     vultron-quick-scan.bat                   Prompt for target
echo     vultron-quick-scan.bat 192.168.1.100      Scan specific target
echo     vultron-quick-scan.bat -h / --help        Show this help
echo.
echo   Scans common ports, queries CVEs from the last 120 days.
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

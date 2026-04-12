@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================================
REM Vulntron - Local Host Assessment
REM
REM Scans localhost (127.0.0.1) with full port range and complete CVE history.
REM Recommended for: Self-assessment, compliance checks, patch audits.
REM
REM Usage:
REM   vultron-local.bat           Run local host assessment
REM   vultron-local.bat -h        Show this help
REM   vultron-local.bat --help    Show this help
REM ============================================================================

title Vulntron - Local Host Assessment
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
echo        VULNTRON - LOCAL HOST ASSESSMENT
echo.
echo ===============================================================================
echo.
echo [*] Target:   127.0.0.1 (localhost)
echo [*] Mode:     Full port scan + complete CVE history
echo [*] Features: Port scanning, service detection, CVE correlation,
echo               TLS inspection, inventory, compliance baseline
echo.
echo ===============================================================================
echo.

REM ------------------------------------------------------------------
REM Resolve invocation: prefer installed 'vulntron', else python module
REM ------------------------------------------------------------------
call :resolve_vulntron
echo [*] Invocation: !VULNTRON_CMD!
echo.

REM Create timestamped output directory under runs\
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

echo [!] NOTE: Some checks require Administrator privileges.
echo     For best results, right-click and "Run as Administrator".
echo.
echo [*] Press any key to start the local assessment...
pause >nul

echo.
echo [*] Starting Vulntron local assessment...
echo.

REM Run scan with full port range and all CVE history
!VULNTRON_CMD! -t 127.0.0.1 ^
    --scan-mode full ^
    --cve-lookback-days 3650

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
echo.
echo [*] Moving reports to !OUT_DIR!...
for %%f in ("%~dp0vultron_hybrid_127.0.0.1_*.html" "%~dp0vultron_hybrid_127.0.0.1_*.json") do (
    if exist "%%f" move /y "%%f" "!OUT_DIR!\" >nul
)

echo.
echo ===============================================================================
echo.
echo [+] LOCAL ASSESSMENT COMPLETE!
echo.
echo     Reports saved to: !OUT_DIR!
echo       - vultron_hybrid_127.0.0.1_*.html  (Interactive HTML report)
echo       - vultron_hybrid_127.0.0.1_*.json  (Machine-readable JSON)
echo.
echo ===============================================================================
echo.

REM Offer to open HTML report
set /p _open="[?] Open HTML report in browser? (Y/n): "
if /i "!_open!"=="n" goto :offer_ui
for %%f in ("!OUT_DIR!\vultron_hybrid_127.0.0.1_*.html") do (
    if exist "%%f" start "" "%%f"
)

:offer_ui
echo.
set /p _ui="[?] Launch Vulntron UI dashboard? (y/N): "
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
echo   Vulntron Local Host Assessment
echo   Scans localhost with full port range and complete CVE history.
echo.
echo   Usage:
echo     vultron-local.bat           Run assessment against 127.0.0.1
echo     vultron-local.bat -h        Show this help message
echo     vultron-local.bat --help    Show this help message
echo.
echo   Output is written to: runs\TIMESTAMP\
echo.
exit /b 0

REM ------------------------------------------------------------------
REM Subroutine: resolve vulntron invocation
REM Sets VULNTRON_CMD to "vulntron" if available, else "python vultron.py"
REM ------------------------------------------------------------------
:resolve_vulntron
set VULNTRON_CMD=
REM Try installed 'vulntron' on PATH
where vulntron >nul 2>&1
if !errorlevel! equ 0 (
    set VULNTRON_CMD=vulntron
    exit /b 0
)
REM Try venv python
if exist "%~dp0venv\Scripts\python.exe" (
    set VULNTRON_CMD="%~dp0venv\Scripts\python.exe" -m vulntron
    exit /b 0
)
REM Fall back to python -m vulntron (module installed)
python -m vulntron --version >nul 2>&1
if !errorlevel! equ 0 (
    set VULNTRON_CMD=python -m vulntron
    exit /b 0
)
REM Final fallback: call vultron.py directly
if exist "%~dp0vultron.py" (
    set VULNTRON_CMD=python "%~dp0vultron.py"
    exit /b 0
)
echo [!] ERROR: Cannot find Vulntron. Run setup.bat first.
exit /b 1

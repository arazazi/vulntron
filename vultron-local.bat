@echo off
title VULTRON v4.0 - Local Forensics Mode
color 0B
cls

echo.
echo ===============================================================================
echo.
echo      ╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦4.0 - LOCAL FORENSICS
echo      ╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝
echo       ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝   ╚╝
echo.
echo            DEEP SYSTEM ANALYSIS MODE
echo.
echo ===============================================================================
echo.
echo [*] Mode: LOCAL FORENSICS + CVE INTELLIGENCE
echo [*] Features:
echo     - Registry artifact collection
echo     - Prefetch file analysis
echo     - PowerShell history scanning
echo     - Event log analysis
echo     - Network connection mapping
echo     - USB device history
echo     - Installed patch inventory
echo     - NVD CVE correlation
echo.
echo ===============================================================================
echo.

echo [!] IMPORTANT: This scan requires Administrator privileges!
echo.
echo Press any key to start the scan...
pause >nul

echo.
echo [*] Starting local forensics scan...
echo.

python vultron_v4_ultimate.py --local --comprehensive

echo.
echo ===============================================================================
echo.
echo [+] SCAN COMPLETE!
echo.
echo Check the generated reports:
echo   - vultron_ultimate_localhost_TIMESTAMP.html (Interactive dashboard)
echo   - vultron_ultimate_localhost_TIMESTAMP.json (Full data)
echo   - vultron_ultimate_localhost_TIMESTAMP.csv  (Summary)
echo.
echo ===============================================================================
echo.
pause

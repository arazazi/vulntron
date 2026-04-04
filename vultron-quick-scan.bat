@echo off
title VULTRON v4.0 - Quick Scan
color 0A
cls

echo.
echo ╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦4.0 - QUICK SCAN
echo ╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝
echo  ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝   ╚╝
echo.
echo [*] Quick scan mode (last 120 days CVEs only)
echo.

set /p target="Target (or Enter for localhost): "

if "%target%"=="" (
    python vultron_v4_ultimate.py --local --quick
) else (
    python vultron_v4_ultimate.py -t %target% --quick
)

echo.
pause

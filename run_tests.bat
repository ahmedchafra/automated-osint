@echo off
REM OSINT Platform - theHarvester + h8mail Test Script
REM Double-click this to run tests. Results in test_output.log
cd /d "C:\Users\user\Documents\automated osint"

echo ============================================================
echo  OSINT Platform - Tool Verification Test
echo  Target: utm.tn
echo ============================================================
echo.

REM ── Step 1: Install theHarvester (if not already) ──
echo [1/4] Checking theHarvester installation...
.venv\Scripts\pip show theHarvester >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing theHarvester from GitHub...
    .venv\Scripts\python -m pip install git+https://github.com/laramies/theHarvester.git@master
) else (
    echo theHarvester already installed
)
echo.

REM ── Step 2: Install h8mail (if not already) ──
echo [2/4] Checking h8mail installation...
.venv\Scripts\pip show h8mail >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing h8mail...
    .venv\Scripts\python -m pip install h8mail
) else (
    echo h8mail already installed
)
echo.

REM ── Step 3: Run the test script ──
echo [3/4] Running test script...
.venv\Scripts\python test_harvester.py
echo.
echo Test completed. Check test_output.log for full results.
echo.

REM ── Step 4: Show results summary ──
echo [4/4] Results summary:
findstr /C:"TEST" /C:"DONE" /C:"ERROR" test_output.log 2>nul
echo.
echo ============================================================
echo  Full output: test_output.log
echo ============================================================

pause

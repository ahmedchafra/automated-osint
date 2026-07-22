@echo off
REM ──────────────────────────────────────────────────────────────────────
REM OSINT Platform — Automated API Test Script (Windows)
REM Usage:  test_api.bat
REM         test_api.bat http://localhost:8000
REM ──────────────────────────────────────────────────────────────────────

setlocal enabledelayedexpansion

set "API_URL=%~1"
if "%API_URL%"=="" set "API_URL=http://localhost:8000"
set "API_KEY=osint-local-dev-key-12345"
set PASS=0
set FAIL=0

echo.
echo [INFO] Testing API at %API_URL%
echo.

REM ── 1. Health check ────────────────────────────────────────────────
echo [TEST 1] Health Check
curl -sf "%API_URL%/health" >nul 2>&1
if %errorlevel% equ 0 (
  for /f "tokens=*" %%i in ('curl -sf "%API_URL%/health" ^| python -c "import sys,json; d=json.load(sys.stdin); print('DB:', d.get('database','?'), '| Redis:', d.get('redis','?'))"') do echo   [OK] %%i
  set /a PASS+=1
) else (
  echo   [FAIL] Health endpoint unreachable
  set /a FAIL+=1
)

REM ── 2. Create scan — INFRASTRUCTURE ────────────────────────────────
echo.
echo [TEST 2] Create Scan (INFRASTRUCTURE)
for /f "tokens=*" %%i in ('curl -sf -X POST "%API_URL%/api/scans/" -H "X-API-Key: %API_KEY%" -H "Content-Type: application/json" -d "{\"target_domain\":\"example.com\",\"selected_vectors\":[\"INFRASTRUCTURE\"]}" ^| python -c "import sys,json; d=json.load(sys.stdin); print(d['scan']['id'])"') do (
  set "SCAN_ID=%%i"
  if "%%i"=="" (
    echo   [FAIL] No scan ID returned
    set /a FAIL+=1
  ) else (
    echo   [OK] Scan created: %%i
    set /a PASS+=1
  )
)

REM ── 3. Create scan — IDENTITY ─────────────────────────────────────
echo.
echo [TEST 3] Create Scan (IDENTITY)
for /f "tokens=*" %%i in ('curl -sf -X POST "%API_URL%/api/scans/" -H "X-API-Key: %API_KEY%" -H "Content-Type: application/json" -d "{\"target_domain\":\"example.com\",\"selected_vectors\":[\"IDENTITY\"]}" ^| python -c "import sys,json; d=json.load(sys.stdin); print(d['scan']['id'])"') do (
  set "IDENTITY_SCAN_ID=%%i"
  if "%%i"=="" (
    echo   [FAIL] No scan ID returned
    set /a FAIL+=1
  ) else (
    echo   [OK] IDENTITY scan created: %%i
    set /a PASS+=1
  )
)

REM ── 4. Create scan — USERNAME ─────────────────────────────────────
echo.
echo [TEST 4] Create Scan (USERNAME)
for /f "tokens=*" %%i in ('curl -sf -X POST "%API_URL%/api/scans/" -H "X-API-Key: %API_KEY%" -H "Content-Type: application/json" -d "{\"target_domain\":\"example.com\",\"selected_vectors\":[\"USERNAME\"],\"target_usernames\":[\"testuser\"]}" ^| python -c "import sys,json; d=json.load(sys.stdin); print(d['scan']['id'])"') do (
  set "USERNAME_SCAN_ID=%%i"
  if "%%i"=="" (
    echo   [FAIL] No scan ID returned
    set /a FAIL+=1
  ) else (
    echo   [OK] USERNAME scan created: %%i
    set /a PASS+=1
  )
)

REM ── 5. Wait for scans to complete ──────────────────────────────────
echo.
echo [TEST 5] Waiting for scans to complete (up to 120s)
set /a ATTEMPT=0
:wait_loop
set /a ATTEMPT+=1
if %ATTEMPT% gtr 20 goto wait_done
timeout /t 6 /nobreak >nul

set ALL_DONE=1
for %%S in (%SCAN_ID% %IDENTITY_SCAN_ID% %USERNAME_SCAN_ID%) do (
  for /f "tokens=*" %%i in ('curl -sf "%API_URL%/api/scans/%%S" -H "X-API-Key: %API_KEY%" ^| python -c "import sys,json; print(json.load(sys.stdin).get('status',''))"') do (
    if "%%i"=="COMPLETED" (
      echo   [OK] Scan %%S: COMPLETED
    ) else if "%%i"=="FAILED" (
      echo   [WARN] Scan %%S: FAILED
    ) else (
      set ALL_DONE=0
    )
  )
)
if %ALL_DONE% equ 0 goto wait_loop
:wait_done

REM ── 6. Check findings ──────────────────────────────────────────────
echo.
echo [TEST 6] Findings Summary
for /f "tokens=*" %%i in ('curl -sf "%API_URL%/api/findings/?scan_id=%SCAN_ID%&limit=100" -H "X-API-Key: %API_KEY%" ^| python -c "import sys,json; print(len(json.load(sys.stdin)))"') do (
  echo   [OK] INFRASTRUCTURE: %%i finding(s)
  set /a PASS+=1
)

REM ── 7. Export test ─────────────────────────────────────────────────
echo.
echo [TEST 7] Export (CSV)
for /f "tokens=*" %%i in ('curl -sf -o /dev/null -w "%%{http_code}" "%API_URL%/api/findings/export?scan_id=%SCAN_ID%&format=csv" -H "X-API-Key: %API_KEY%"') do (
  if "%%i"=="200" (
    echo   [OK] CSV export: HTTP %%i
    set /a PASS+=1
  ) else (
    echo   [FAIL] CSV export: HTTP %%i
    set /a FAIL+=1
  )
)

REM ── Summary ────────────────────────────────────────────────────────
echo.
echo ========================================
echo   Results: %PASS% passed, %FAIL% failed
echo ========================================

if %FAIL% gtr 0 (
  exit /b 1
) else (
  exit /b 0
)

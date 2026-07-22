@echo off
REM ──────────────────────────────────────────────────────────────────────
REM OSINT Platform — Stop all services
REM Usage:  stop.bat            (stop all services)
REM         stop.bat --clean    (stop + remove volumes + images)
REM ──────────────────────────────────────────────────────────────────────

setlocal

title OSINT Platform — Stop

echo.
echo [INFO] Stopping all services...
echo.

if /i "%~1"=="--clean" (
  echo [WARN] This will remove all containers, volumes, and images!
  echo [WARN] All data will be lost!
  echo.
  set /p CONFIRM="Type 'yes' to confirm: "
  if /i "!CONFIRM!"=="yes" (
    docker compose down --volumes --rmi all
    echo [OK] All services stopped and cleaned up.
  ) else (
    echo [CANCELLED] Aborting.
  )
) else (
  docker compose down
  echo [OK] All services stopped. Data preserved.
  echo.
  echo To stop and remove everything: stop.bat --clean
)

echo.
pause

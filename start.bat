@echo off
REM ──────────────────────────────────────────────────────────────────────
REM OSINT Platform — One-Click Launcher (Windows)
REM Usage:  start.bat            (start all services)
REM         start.bat --test     (start + run API tests)
REM         stop.bat             (stop all services)
REM ──────────────────────────────────────────────────────────────────────

setlocal

title OSINT Platform Launcher

echo.
echo   OSINT Platform -- Automated Launcher
echo   ======================================
echo.

REM Check prerequisites
docker --version >nul 2>&1
if %errorlevel% neq 0 (
  echo [ERROR] Docker is not installed or not in PATH.
  echo Install Docker Desktop: https://www.docker.com/products/docker-desktop/
  pause
  exit /b 1
)

docker compose version >nul 2>&1
if %errorlevel% neq 0 (
  echo [ERROR] Docker Compose not found.
  echo Make sure Docker Desktop is up to date.
  pause
  exit /b 1
)

REM Create .env if missing
if not exist ".env" (
  echo [INFO] Creating .env from .env.example...
  copy ".env.example" ".env" >nul
  echo [OK] .env created. Edit it to add API keys for premium collectors.
  echo.
)

REM Start services
echo [INFO] Starting all services (postgres, redis, backend, worker)...
echo.

docker compose up -d --build

if %errorlevel% neq 0 (
  echo.
  echo [ERROR] Docker compose failed. Check the output above.
  pause
  exit /b 1
)

echo.
echo [OK] All services starting...
echo.
echo   API:             http://localhost:8000
echo   API docs:        http://localhost:8000/docs
echo   Frontend (dev):  http://localhost:5173
echo   Flower (Celery): http://localhost:5555
echo.

REM Wait for health
echo [INFO] Waiting for backend API to be ready...
set /a ATTEMPT=0
:health_check
set /a ATTEMPT+=1
if %ATTEMPT% gtr 30 goto health_timeout
curl -sf http://localhost:8000/health >nul 2>&1
if %errorlevel% equ 0 (
  echo [OK] Backend API is ready!
  goto health_done
)
timeout /t 2 /nobreak >nul
goto health_check

:health_timeout
echo [WARN] Backend API not ready after 60s. It may still be starting.
echo Check with: docker compose logs backend

:health_done

REM Start frontend dev server
echo.
echo [INFO] Starting frontend dev server...
cd frontend
start "" npx vite --host 0.0.0.0 --port 5173
cd ..
echo [OK] Frontend starting at http://localhost:5173
echo.

REM Run tests if requested
if /i "%~1"=="--test" (
  echo.
  echo [INFO] Running API tests...
  call test_api.bat
)

echo.
echo ==========================================
echo   Platform is running!
echo   Stop with: stop.bat
echo ==========================================
echo.

pause

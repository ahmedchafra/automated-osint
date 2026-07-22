#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# OSINT Platform — One-Click Launcher (Linux/Mac/Git Bash)
# Usage:  ./start.sh            (start all services)
#         ./start.sh --test     (start + run API tests)
#         ./stop.sh             (stop all services)
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "
  ╔══════════════════════════════════════════╗
  ║   OSINT Platform — Automated Launcher   ║
  ╚══════════════════════════════════════════╝
"

# ── Prerequisites ───────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || {
  echo -e "${RED}[ERROR] Docker is not installed.${RESET}"
  echo "Install Docker: https://docs.docker.com/get-docker/"
  exit 1
}

docker compose version >/dev/null 2>&1 || {
  echo -e "${RED}[ERROR] Docker Compose not found.${RESET}"
  exit 1
}

# ── Create .env if missing ──────────────────────────────────────────
if [ ! -f .env ]; then
  echo -e "${CYAN}[INFO]${RESET} Creating .env from .env.example..."
  cp .env.example .env
  echo -e "${GREEN}[OK]${RESET} .env created. Edit it to add API keys for premium collectors."
  echo ""
fi

# ── Start services ──────────────────────────────────────────────────
echo -e "${CYAN}[INFO]${RESET} Starting all services (postgres, redis, backend, worker)..."
echo ""

docker compose up -d --build

echo -e "${GREEN}[OK]${RESET} All services starting..."
echo ""
echo "  Frontend (dev):  http://localhost:5173"
echo "  Frontend (prod): http://localhost:80"
echo "  API:             http://localhost:8000"
echo "  API docs:        http://localhost:8000/docs"
echo "  Flower (Celery): http://localhost:5555"
echo ""

# ── Wait for health ─────────────────────────────────────────────────
echo -e "${CYAN}[INFO]${RESET} Waiting for backend API to be ready..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo -e "${GREEN}[OK]${RESET} Backend API is ready!"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo -e "${YELLOW}[WARN]${RESET} Backend API not ready after 60s. Check: docker compose logs backend"
  fi
  sleep 2
done

# ── Run tests if requested ──────────────────────────────────────────
if [ "${1:-}" = "--test" ]; then
  echo ""
  echo -e "${CYAN}[INFO]${RESET} Running API tests..."
  bash test_api.sh
fi

# ── Done ────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "  ${GREEN}║   Platform is running!                  ║${RESET}"
echo -e "  ${GREEN}║   Stop with: ./stop.sh                  ║${RESET}"
echo -e "  ${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""

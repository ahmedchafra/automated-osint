#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# OSINT Platform — Stop all services
# Usage:  ./stop.sh            (stop all services, preserve data)
#         ./stop.sh --clean    (stop + remove volumes + images)
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

echo ""
echo -e "${CYAN}[INFO]${RESET} Stopping all services..."
echo ""

if [ "${1:-}" = "--clean" ]; then
  echo -e "${RED}[WARN]${RESET} This will remove all containers, volumes, and images!"
  echo -e "${RED}[WARN]${RESET} All data will be lost!"
  echo ""
  read -p "Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" = "yes" ]; then
    docker compose down --volumes --rmi all
    echo -e "${GREEN}[OK]${RESET} All services stopped and cleaned up."
  else
    echo -e "${CYAN}[CANCELLED]${RESET} Aborting."
  fi
else
  docker compose down
  echo -e "${GREEN}[OK]${RESET} All services stopped. Data preserved."
  echo ""
  echo "To stop and remove everything: ./stop.sh --clean"
fi

echo ""

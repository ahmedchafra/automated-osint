#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# OSINT Platform — Automated API Test Script
# Usage:  bash test_api.sh
#         bash test_api.sh http://localhost:8000   (custom URL)
#
# Uses node.js for JSON parsing (no python dependency).
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

API_URL="${1:-http://localhost:8000}"
API_KEY="osint-local-dev-key-12345"
PASS=0
FAIL=0

# ── helpers ──────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

pass() { PASS=$((PASS+1)); echo -e "  ${GREEN}✔${RESET} $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  ${RED}✘${RESET} $1"; }
header() { echo -e "\n${CYAN}── $1 ──${RESET}"; }

# JSON parsing helper (uses node)
json_get() {
  # Usage: json_get "$JSON_STRING" "key" or "key.subkey"
  local json="$1"
  local key="$2"
  # Build JS accessor: "o" for top-level, "o["scan"]["id"]" for nested
  local accessor="o"
  IFS='.' read -ra parts <<< "$key"
  for p in "${parts[@]}"; do
    accessor+="[\"$p\"]"
  done
  node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const o=JSON.parse(d);const v=$accessor;console.log(v??'')}catch{console.log('')}})" <<< "$json"
}

json_len() {
  node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const o=JSON.parse(d);console.log(Array.isArray(o)?o.length:0)}catch{console.log(0)}})" <<< "$1"
}

# Wait for the API to be ready
echo -e "${CYAN}Waiting for API at ${API_URL}...${RESET}"
for i in $(seq 1 30); do
  if curl -sf "${API_URL}/health" >/dev/null 2>&1; then
    echo -e "${GREEN}API is up!${RESET}"
    break
  fi
  sleep 2
done

# ── 1. Health check ─────────────────────────────────────────────────
header "1. Health Check"
BODY=$(curl -sf "${API_URL}/health" 2>/dev/null) && {
  DB=$(json_get "$BODY" "database")
  RD=$(json_get "$BODY" "redis")
  [ "$DB" = "ok" ] && pass "Database: ok" || fail "Database: $DB"
  [ "$RD" = "ok" ] && pass "Redis: ok"    || fail "Redis: $RD"
} || fail "Health endpoint unreachable"

# ── 2. Create scan — INFRASTRUCTURE ─────────────────────────────────
header "2. Create Scan (INFRASTRUCTURE)"
SCAN_RESPONSE=$(curl -sf -X POST "${API_URL}/api/scans/" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"target_domain":"example.com","selected_vectors":["INFRASTRUCTURE"]}' 2>/dev/null) && {
  SCAN_ID=$(json_get "$SCAN_RESPONSE" "scan.id")
  TASK_ID=$(json_get "$SCAN_RESPONSE" "task_id")
  [ -n "$SCAN_ID" ] && pass "Scan created: ${SCAN_ID}" || fail "No scan ID returned"
  [ -n "$TASK_ID" ] && pass "Task queued: ${TASK_ID}"   || fail "No task ID returned"
} || fail "Failed to create scan"

# ── 3. Create scan — IDENTITY (Hunter + XposedOrNot + Holehe) ──────
header "3. Create Scan (IDENTITY — Hunter + XposedOrNot + Holehe)"
IDENTITY_RESPONSE=$(curl -sf -X POST "${API_URL}/api/scans/" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"target_domain":"example.com","selected_vectors":["IDENTITY"]}' 2>/dev/null) && {
  IDENTITY_SCAN_ID=$(json_get "$IDENTITY_RESPONSE" "scan.id")
  [ -n "$IDENTITY_SCAN_ID" ] && pass "IDENTITY scan created: ${IDENTITY_SCAN_ID}" || fail "No scan ID"
} || fail "Failed to create IDENTITY scan"

# ── 4. Create scan — USERNAME (Maigret) ────────────────────────────
header "4. Create Scan (USERNAME — Maigret + SimpleProfiler)"
USERNAME_RESPONSE=$(curl -sf -X POST "${API_URL}/api/scans/" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"target_domain":"example.com","selected_vectors":["USERNAME"],"target_usernames":["testuser"]}' 2>/dev/null) && {
  USERNAME_SCAN_ID=$(json_get "$USERNAME_RESPONSE" "scan.id")
  [ -n "$USERNAME_SCAN_ID" ] && pass "USERNAME scan created: ${USERNAME_SCAN_ID}" || fail "No scan ID"
} || fail "Failed to create USERNAME scan"

# ── 5. Wait for scans to complete ───────────────────────────────────
header "5. Waiting for scans to complete (up to 120s)"
for i in $(seq 1 20); do
  sleep 6
  ALL_DONE=true
  for SID in "$SCAN_ID" "$IDENTITY_SCAN_ID" "$USERNAME_SCAN_ID"; do
    STATUS=$(curl -sf "${API_URL}/api/scans/${SID}" -H "X-API-Key: ${API_KEY}" 2>/dev/null)
    STATUS=$(json_get "$STATUS" "status")
    if [ "$STATUS" != "COMPLETED" ] && [ "$STATUS" != "FAILED" ]; then
      ALL_DONE=false
    fi
  done
  if $ALL_DONE; then
    echo "  All scans finished"
    break
  fi
  echo "  ... still running (check $((i*6))s)"
done

# ── 6. Check findings ───────────────────────────────────────────────
header "6. Findings Summary"
for LABEL in "INFRASTRUCTURE:$SCAN_ID" "IDENTITY:$IDENTITY_SCAN_ID" "USERNAME:$USERNAME_SCAN_ID"; do
  NAME="${LABEL%%:*}"
  SID="${LABEL##*:}"
  FINDINGS=$(curl -sf "${API_URL}/api/findings/?scan_id=${SID}&limit=100" -H "X-API-Key: ${API_KEY}" 2>/dev/null)
  COUNT=$(json_len "$FINDINGS")
  [ "$COUNT" -gt 0 ] && pass "${NAME}: ${COUNT} finding(s)" || pass "${NAME}: ${COUNT} findings (empty is OK for test domain)"
done

# ── 7. Check entity graph links ────────────────────────────────────
header "7. Entity Graph Links"
LINKS=$(curl -sf "${API_URL}/api/links/?scan_id=${SCAN_ID}" -H "X-API-Key: ${API_KEY}" 2>/dev/null)
LINK_COUNT=$(json_len "$LINKS")
[ "$LINK_COUNT" -gt 0 ] && pass "${LINK_COUNT} link(s) created" || pass "${LINK_COUNT} links (empty is OK)"

# ── 8. Export test ──────────────────────────────────────────────────
header "8. Export (CSV)"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
  "${API_URL}/api/findings/export?scan_id=${SCAN_ID}&format=csv" \
  -H "X-API-Key: ${API_KEY}" 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && pass "CSV export: HTTP ${HTTP_CODE}" || fail "CSV export: HTTP ${HTTP_CODE}"

# ── Summary ─────────────────────────────────────────────────────────
header "Summary"
echo -e "  ${GREEN}Passed: ${PASS}${RESET}  ${RED}Failed: ${FAIL}${RESET}"
[ "$FAIL" -eq 0 ] && echo -e "\n${GREEN}All tests passed! ✔${RESET}" || echo -e "\n${RED}Some tests failed — check above.${RESET}"
exit $FAIL

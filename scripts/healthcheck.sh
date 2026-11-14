#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# GuardNous — Health Check
#
# Quick check of all services. Useful for CI/CD smoke tests.
#
# Usage:
#   ./scripts/healthcheck.sh
#
# Exit codes:
#   0 — All services healthy
#   1 — One or more services unhealthy
# ─────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

ERRORS=0

check_service() {
    local name="$1" url="$2"
    if curl -sf "$url" &>/dev/null; then
        echo -e "  ${GREEN}✔${NC}  $name"
    else
        echo -e "  ${RED}✖${NC}  $name"
        ERRORS=$((ERRORS + 1))
    fi
}

tcp_open() {
    if command -v nc &>/dev/null; then
        nc -z "$1" "$2" 2>/dev/null
    else
        (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null
    fi
}

# Reported, but does not count as a failure (e.g. API docs are off in production).
check_optional() {
    local name="$1" url="$2" note="$3"
    if curl -sf "$url" &>/dev/null; then
        echo -e "  ${GREEN}✔${NC}  $name"
    else
        echo -e "  ${YELLOW}–${NC}  $name not available (${note})"
    fi
}

check_tcp() {
    local name="$1" host="$2" port="$3"
    if tcp_open "$host" "$port"; then
        echo -e "  ${GREEN}✔${NC}  $name (${host}:${port})"
    else
        echo -e "  ${RED}✖${NC}  $name (${host}:${port})"
        ERRORS=$((ERRORS + 1))
    fi
}

echo -e "${BOLD}GuardNous Health Check${NC}"
echo ""

check_tcp    "PostgreSQL" "localhost" "7000"
check_tcp    "Redis"      "localhost" "7001"
check_service "API"       "http://localhost:7002/api/health"
check_service "Frontend"  "http://localhost:7003"
check_optional "API Docs" "http://localhost:7002/docs" "expected when ENVIRONMENT=production"

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All services healthy ✔${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}${ERRORS} service(s) unhealthy ✖${NC}"
    echo -e "${YELLOW}Run 'docker compose logs' to debug${NC}"
    exit 1
fi

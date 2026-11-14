#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# GuardNous — Reset & Clean
#
# Wipes all data and restarts fresh. Useful for:
#   - Starting over with a clean database
#   - Testing the first-run experience
#   - Clearing corrupt state
#
# Usage:
#   ./scripts/reset.sh          # Reset data only (keeps images)
#   ./scripts/reset.sh --full   # Reset data + rebuild images
# ─────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f .env ]]; then
    echo -e "${RED}✖  No .env found. Run ./scripts/setup.sh first.${NC}" >&2
    exit 1
fi

echo -e "${YELLOW}⚠  This will destroy all GuardNous data (scans, users, findings).${NC}"
read -rp "$(echo -e "${BOLD}Are you sure? (yes/no): ${NC}")" CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo -e "${BOLD}Stopping containers...${NC}"
docker compose down -v

if [[ "${1:-}" == "--full" ]]; then
    echo -e "${BOLD}Removing images...${NC}"
    docker compose down -v --rmi local
    echo -e "${BOLD}Rebuilding images...${NC}"
    docker compose build
fi

echo -e "${BOLD}Starting fresh...${NC}"
docker compose up -d

echo ""
echo -e "${GREEN}✔  GuardNous has been reset.${NC}"
echo -e "   Dashboard: http://localhost:7003"
echo -e "   Login:     admin@guardnous.com is created again on first start when"
echo -e "              GUARDNOUS_SEED_ADMIN=true, with the INITIAL_ADMIN_PASSWORD from .env."
echo -e "              If that is empty, a password is generated and printed once in:"
echo -e "              docker compose logs api"

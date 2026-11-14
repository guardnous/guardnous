#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# GuardNous — One-command setup
#
# Usage:
#   ./scripts/setup.sh            # Interactive setup
#   ./scripts/setup.sh --defaults # Accept all defaults (CI/CD)
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

USE_DEFAULTS=false
[[ "${1:-}" == "--defaults" ]] && USE_DEFAULTS=true

# ── Helper functions ─────────────────────────────────────────
info()    { echo -e "${BLUE}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✔${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✖${NC}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

ask() {
    local prompt="$1" default="$2" var_name="$3" input=""
    if ! $USE_DEFAULTS; then
        read -rp "$(echo -e "${YELLOW}?${NC} ${prompt} [${default}]: ")" input || input=""
    fi
    printf -v "$var_name" '%s' "${input:-$default}"
}

# ── .env helpers ─────────────────────────────────────────────
# Value of KEY in .env (last occurrence), empty when absent.
env_get() {
    local line
    line=$(grep -E "^$1=" .env 2>/dev/null | tail -n 1 || true)
    printf '%s' "${line#*=}"
}

# Set KEY=VALUE in .env: replaces the line when the key exists, appends otherwise.
env_set() {
    local key="$1" value="$2" escaped
    if grep -qE "^${key}=" .env 2>/dev/null; then
        escaped=$(printf '%s' "$value" | sed -e 's/[\\&|]/\\&/g')
        sed -i.bak "s|^${key}=.*|${key}=${escaped}|" .env && rm -f .env.bak
    else
        printf '\n%s=%s\n' "$key" "$value" >> .env
    fi
}

# ── Secret generators (no Python packages needed) ────────────
gen_hex_key() {
    openssl rand -hex 32 2>/dev/null \
        || python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
        || true
}

# A Fernet key is 32 random bytes, URL-safe base64: 44 characters ending in "=".
gen_fernet_key() {
    local key=""
    key=$(openssl rand -base64 32 2>/dev/null | tr -d '\r\n' | tr '+/' '-_' || true)
    if [[ ${#key} -ne 44 ]]; then
        key=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())" 2>/dev/null || true)
    fi
    printf '%s' "$key"
}

is_fernet_key() {
    [[ ${#1} -eq 44 && "$1" =~ ^[A-Za-z0-9_-]{43}=$ ]]
}

# 24 characters: 22 random letters/digits (upper, lower and digit guaranteed)
# plus two symbols that are safe in a shell, in .env and in a URL-encoded form.
gen_password() {
    local raw="" attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        raw=$(openssl rand -base64 48 2>/dev/null | LC_ALL=C tr -dc 'A-Za-z0-9' || true)
        if [[ ${#raw} -lt 22 ]]; then
            raw=$(python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(22)))" 2>/dev/null || true)
        fi
        if [[ ${#raw} -lt 22 ]]; then
            raw=$(head -c 256 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' || true)
        fi
        raw="${raw:0:22}"
        if [[ ${#raw} -eq 22 && "$raw" =~ [A-Z] && "$raw" =~ [a-z] && "$raw" =~ [0-9] ]]; then
            printf '%s@%s^%s' "${raw:0:7}" "${raw:7:8}" "${raw:15:7}"
            return 0
        fi
    done
    return 1
}

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        error "$1 is not installed. $2"
        return 1
    fi
    success "$1 found: $(command -v "$1")"
    return 0
}

# ── Banner ───────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
   ______                     ___   __
  / ____/_  ______ __________/ / | / /___  __  _______
 / / __/ / / / __ `/ ___/ __  /  |/ / __ \/ / / / ___/
/ /_/ / /_/ / /_/ / /  / /_/ / /|  / /_/ / /_/ (__  )
\____/\__,_/\__,_/_/   \__,_/_/ |_/\____/\__,_/____/
BANNER
echo -e "${NC}"
echo -e "${BOLD}Open-source Cloud Security & IaC Posture Management${NC}"
echo ""

# ── Step 1: Prerequisite Check ───────────────────────────────
header "Step 1/5 — Checking Prerequisites"

MISSING=0
check_cmd docker   "Install from https://docs.docker.com/get-docker/"   || MISSING=1
check_cmd curl     "Install curl with your package manager"             || MISSING=1
if ! command -v openssl &>/dev/null && ! command -v python3 &>/dev/null; then
    error "Neither openssl nor python3 is installed; one of them is needed to generate keys."
    MISSING=1
fi

# docker-compose.yml uses env_file with `required: false`, which needs
# Docker Compose v2.24 or newer. The legacy docker-compose v1 cannot read it.
COMPOSE_CMD="docker compose"
if docker compose version &>/dev/null; then
    COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "")
    COMPOSE_VERSION="${COMPOSE_VERSION#v}"
    COMPOSE_MAJOR="${COMPOSE_VERSION%%.*}"
    COMPOSE_REST="${COMPOSE_VERSION#*.}"
    COMPOSE_MINOR="${COMPOSE_REST%%.*}"
    if [[ "$COMPOSE_MAJOR" =~ ^[0-9]+$ && "$COMPOSE_MINOR" =~ ^[0-9]+$ ]] \
        && { [[ "$COMPOSE_MAJOR" -lt 2 ]] || { [[ "$COMPOSE_MAJOR" -eq 2 ]] && [[ "$COMPOSE_MINOR" -lt 24 ]]; }; }; then
        error "Docker Compose ${COMPOSE_VERSION} is too old. Version 2.24 or newer is required."
        MISSING=1
    else
        success "docker compose found (${COMPOSE_VERSION:-version unknown})"
    fi
else
    error "The 'docker compose' plugin (v2.24 or newer) is not available."
    error "Install it: https://docs.docker.com/compose/install/"
    MISSING=1
fi

if [[ $MISSING -eq 1 ]]; then
    error "Missing prerequisites. Please install the tools above and re-run."
    exit 1
fi

# Check Docker daemon is running
if ! docker info &>/dev/null; then
    error "Docker daemon is not running. Please start Docker Desktop or dockerd."
    exit 1
fi
success "Docker daemon is running"

# ── Step 2: Environment Configuration ────────────────────────
header "Step 2/5 — Environment Configuration"

if [[ -f .env ]]; then
    warn ".env file already exists"
    ask "Overwrite existing .env?" "no" OVERWRITE_ENV
    if [[ "$OVERWRITE_ENV" != "yes" && "$OVERWRITE_ENV" != "y" ]]; then
        info "Keeping existing .env"
    else
        cp .env.example .env
        success "Copied .env.example → .env"
    fi
else
    cp .env.example .env
    success "Created .env from .env.example"
fi

chmod 600 .env 2>/dev/null || true

# Keys are generated only when .env still has a placeholder or an empty value.
# An existing key is never replaced: data encrypted with the old ENCRYPTION_KEY
# would become unreadable and every session signed with SECRET_KEY would end.
CURRENT=$(env_get SECRET_KEY)
if [[ -z "$CURRENT" || "$CURRENT" == *change-me* || "$CURRENT" == *CHANGE* ]]; then
    env_set SECRET_KEY "$(gen_hex_key)"
    success "Generated random SECRET_KEY"
else
    info "Keeping the SECRET_KEY already in .env"
fi

CURRENT=$(env_get ENCRYPTION_KEY)
if [[ -z "$CURRENT" || "$CURRENT" == *change-me* ]]; then
    env_set ENCRYPTION_KEY "$(gen_fernet_key)"
    success "Generated ENCRYPTION_KEY"
else
    info "Keeping the ENCRYPTION_KEY already in .env"
fi

# Verify what is actually in .env now; never continue with a placeholder.
CURRENT=$(env_get SECRET_KEY)
if [[ "$CURRENT" == *change-me* || "$CURRENT" == *CHANGE* || ${#CURRENT} -lt 32 ]]; then
    error "SECRET_KEY in .env is missing, a placeholder, or shorter than 32 characters."
    error "Set it by hand (openssl rand -hex 32) and run this script again."
    exit 1
fi
CURRENT=$(env_get ENCRYPTION_KEY)
if ! is_fernet_key "$CURRENT"; then
    error "ENCRYPTION_KEY in .env is not a valid key (expected 44 URL-safe base64 characters ending in '=')."
    error "Set it by hand (openssl rand -base64 32 | tr '+/' '-_') and run this script again."
    error "If this installation already holds encrypted data, restore the key it was created with instead."
    exit 1
fi
unset CURRENT
success "SECRET_KEY and ENCRYPTION_KEY in .env verified"

# First administrator. The API creates admin@guardnous.com on its first start
# when GUARDNOUS_SEED_ADMIN=true, using INITIAL_ADMIN_PASSWORD.
ADMIN_SEEDED=false
ADMIN_PASSWORD_SHOWN=""
SEED_FLAG=$(env_get GUARDNOUS_SEED_ADMIN | tr '[:upper:]' '[:lower:]')
if [[ "$SEED_FLAG" == "true" || "$SEED_FLAG" == "1" || "$SEED_FLAG" == "yes" ]]; then
    ADMIN_SEEDED=true
    if [[ -z "$(env_get INITIAL_ADMIN_PASSWORD)" ]]; then
        if ! ADMIN_PASSWORD_SHOWN=$(gen_password); then
            error "Could not generate an administrator password. Set INITIAL_ADMIN_PASSWORD in .env by hand."
            exit 1
        fi
        env_set INITIAL_ADMIN_PASSWORD "$ADMIN_PASSWORD_SHOWN"
        if [[ "$(env_get INITIAL_ADMIN_PASSWORD)" != "$ADMIN_PASSWORD_SHOWN" ]]; then
            error "Could not write INITIAL_ADMIN_PASSWORD to .env."
            exit 1
        fi
        success "Generated the initial administrator password (shown once at the end)"
    else
        info "Keeping the INITIAL_ADMIN_PASSWORD already in .env"
    fi
else
    info "GUARDNOUS_SEED_ADMIN is not true in .env: no administrator account will be created."
fi

# Optional: AI configuration
if ! $USE_DEFAULTS; then
    echo ""
    info "AI Copilot runs in ${BOLD}mock mode${NC} by default (no API key needed)."
    ask "Enable real AI? (openai/azure/anthropic/ollama/no)" "no" AI_PROVIDER
    if [[ "$AI_PROVIDER" != "no" && "$AI_PROVIDER" != "" ]]; then
        env_set LLM_PROVIDER "$AI_PROVIDER"
        read -rsp "$(echo -e "${YELLOW}?${NC} Enter your API key (not shown): ")" AI_KEY || AI_KEY=""
        echo ""
        if [[ -n "$AI_KEY" ]]; then
            env_set LLM_API_KEY "$AI_KEY"
        fi
        unset AI_KEY
        success "AI provider set to ${AI_PROVIDER}"
    fi
fi

if ! $COMPOSE_CMD config -q; then
    error "docker-compose.yml could not be validated with this .env (see the message above)."
    exit 1
fi

# ── Step 3: Build Images ─────────────────────────────────────
header "Step 3/5 — Building Docker Images"
info "This may take 2-5 minutes on first run..."

if ! $COMPOSE_CMD build; then
    error "Building the images failed (see the output above)."
    exit 1
fi
success "Docker images built"

# ── Step 4: Start Services ───────────────────────────────────
header "Step 4/5 — Starting Services"

$COMPOSE_CMD up -d
echo ""

# Wait for API to be healthy
info "Waiting for API to be healthy..."
MAX_WAIT=120
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
    if curl -sf http://localhost:7002/api/health &>/dev/null; then
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    printf "."
done
echo ""

API_HEALTHY=true
if [[ $WAITED -ge $MAX_WAIT ]]; then
    API_HEALTHY=false
    warn "The API did not answer within ${MAX_WAIT}s. Check logs with: docker compose logs api"
else
    success "API is healthy (took ${WAITED}s)"
fi

# ── Step 5: Verify ───────────────────────────────────────────
header "Step 5/5 — Verification"

echo -e "${BOLD}Service Status:${NC}"
$COMPOSE_CMD ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
    || $COMPOSE_CMD ps

echo ""
echo -e "${BOLD}Health Check:${NC}"
HEALTH=$(curl -sf http://localhost:7002/api/health 2>/dev/null || echo '{"status":"unavailable"}')
echo "  API: $HEALTH"

FRONTEND_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" http://localhost:7003 2>/dev/null || echo "unavailable")
echo "  Frontend: HTTP $FRONTEND_STATUS"

# ── Done ─────────────────────────────────────────────────────
echo ""
if $API_HEALTHY; then
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  ✔ GuardNous is ready!${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
else
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${YELLOW}  ⚠ GuardNous was started but the API is not healthy yet${NC}"
    echo -e "${BOLD}${YELLOW}    docker compose ps   /   docker compose logs api${NC}"
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════════${NC}"
fi
echo ""
echo -e "  ${BOLD}Dashboard:${NC}    http://localhost:7003"
echo -e "  ${BOLD}API:${NC}          http://localhost:7002"
echo -e "  ${BOLD}API Docs:${NC}     http://localhost:7002/docs  (not served when ENVIRONMENT=production)"
echo ""
echo -e "  ${BOLD}Login:${NC}"
if $ADMIN_SEEDED; then
    echo -e "    Email:    admin@guardnous.com"
    if [[ -n "$ADMIN_PASSWORD_SHOWN" ]]; then
        echo -e "    Password: ${ADMIN_PASSWORD_SHOWN}"
        echo ""
        echo -e "    ${YELLOW}This password is shown only now. It is also stored in .env as${NC}"
        echo -e "    ${YELLOW}INITIAL_ADMIN_PASSWORD. Change it after your first login.${NC}"
    else
        echo -e "    Password: the INITIAL_ADMIN_PASSWORD value in .env (not shown here)"
    fi
    echo -e "    The password applies when the account is first created; if this"
    echo -e "    database already had the account, its existing password is unchanged."
else
    echo -e "    No administrator account is created (GUARDNOUS_SEED_ADMIN is not true)."
    echo -e "    Sign up at http://localhost:7003/register to create the first account."
fi
echo ""
echo -e "  ${BOLD}Next Steps:${NC}"
echo -e "    1. Open http://localhost:7003 and log in"
echo -e "    2. Go to Integrations → Connect a VCS provider"
echo -e "    3. Run your first security scan"
echo -e "    4. Explore the AI Copilot (Settings → AI Configuration)"
echo ""
echo -e "  ${BOLD}Useful Commands:${NC}"
echo -e "    View logs:     docker compose logs -f api"
echo -e "    Stop:          docker compose down"
echo -e "    Reset data:    docker compose down -v"
echo -e "    Rebuild:       docker compose build api web && docker compose up -d"
echo ""

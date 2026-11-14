#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# GuardNous — Development Mode
#
# Starts PostgreSQL + Redis in Docker, runs backend & frontend
# locally with hot-reload for rapid development.
#
# Usage:
#   ./scripts/dev.sh          # Start everything
#   ./scripts/dev.sh backend  # Backend only (infra + API + workers)
#   ./scripts/dev.sh frontend # Frontend only (assumes API running)
#   ./scripts/dev.sh infra    # Infrastructure only (PG + Redis)
#   ./scripts/dev.sh stop     # Stop infrastructure containers
# ─────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

info()    { echo -e "${BLUE}ℹ${NC}  $*"; }
success() { echo -e "${GREEN}✔${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✖${NC}  $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}── $* ──${NC}\n"; }

MODE="${1:-all}"

# ── Stop command ─────────────────────────────────────────────
if [[ "$MODE" == "stop" ]]; then
    header "Stopping infrastructure"
    docker compose stop postgres redis 2>/dev/null || true
    info "Infrastructure stopped. Kill backend/frontend terminals manually."
    exit 0
fi

require_env_file() {
    if [[ ! -f "$REPO_ROOT/.env" ]]; then
        error "No .env found. Run ./scripts/setup.sh first (it generates the keys)."
        exit 1
    fi
}

# Export KEY=VALUE lines of .env exactly as written. The file is not sourced:
# a value such as CORS_ORIGINS=["http://a","http://b"] would lose its quotes.
load_env() {
    require_env_file
    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        key="${line%%=*}"
        value="${line#*=}"
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        if [[ ${#value} -ge 2 ]]; then
            if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
                value="${value:1:${#value}-2}"
            fi
        fi
        export "$key=$value"
    done < "$REPO_ROOT/.env"
}

# ── Infrastructure (Postgres + Redis) ────────────────────────
start_infra() {
    header "Starting Infrastructure (PostgreSQL + Redis)"
    require_env_file
    docker compose up -d postgres redis
    info "Waiting for PostgreSQL..."
    local waited=0
    until docker compose exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' &>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [[ $waited -ge 60 ]]; then
            error "PostgreSQL did not become ready in 60s. Check: docker compose logs postgres"
            exit 1
        fi
    done
    success "PostgreSQL ready on localhost:7000"
    success "Redis ready on localhost:7001"
}

# ── Backend ──────────────────────────────────────────────────
start_backend() {
    header "Starting Backend (FastAPI + Celery)"

    cd "$REPO_ROOT/backend"

    # Ensure virtualenv exists
    if [[ ! -d .venv ]]; then
        info "Creating Python virtualenv..."
        python3 -m venv .venv
    fi

    # Activate
    # shellcheck disable=SC1091
    source .venv/bin/activate

    # Install deps if needed
    if ! python3 -c "import fastapi" &>/dev/null; then
        info "Installing Python dependencies..."
        pip install -q poetry==1.8.2
        poetry install --no-interaction --no-root
    fi
    # Cloud SDKs (boto3, azure, google) are not part of the Poetry dependencies
    if ! python3 -c "import boto3" &>/dev/null; then
        info "Installing cloud provider SDKs..."
        pip install -q -r requirements-cloud.txt
    fi

    load_env

    # Override for local development (connect to Docker-exposed ports)
    local pg_user="${POSTGRES_USER:-guardnous}" pg_pass="${POSTGRES_PASSWORD:-guardnous}" pg_db="${POSTGRES_DB:-guardnous}"
    export DATABASE_URL="postgresql+asyncpg://${pg_user}:${pg_pass}@localhost:7000/${pg_db}"
    export DATABASE_URL_SYNC="postgresql+psycopg2://${pg_user}:${pg_pass}@localhost:7000/${pg_db}"
    export REDIS_URL="redis://localhost:7001/0"
    export CELERY_BROKER_URL="redis://localhost:7001/1"
    export CELERY_RESULT_BACKEND="redis://localhost:7001/2"
    export DEBUG=true
    # Agent prompts read AGENTS.md / SKILLS.md / PROMPTS.md from here
    export PROJECT_ROOT="$REPO_ROOT"
    # Scanner binaries downloaded by the plugin manager (the default is /app/data)
    export GUARDNOUS_PLUGIN_CACHE="${GUARDNOUS_PLUGIN_CACHE:-$REPO_ROOT/backend/data/plugin_cache}"
    mkdir -p "$GUARDNOUS_PLUGIN_CACHE"

    # Create or upgrade the schema (the same routine the API runs at startup;
    # plain `alembic upgrade head` cannot build an empty database)
    info "Preparing the database schema..."
    python3 -m app.core.migrations

    # Start Celery worker in background
    info "Starting Celery worker..."
    celery -A app.tasks.celery_app worker --loglevel=info --concurrency=2 &
    CELERY_PID=$!

    # Start Celery beat in background
    info "Starting Celery beat..."
    celery -A app.tasks.celery_app beat --loglevel=info &
    BEAT_PID=$!

    # Stop the Celery processes when the API stops (Ctrl+C or exit)
    trap 'echo ""; info "Shutting down..."; kill $CELERY_PID $BEAT_PID 2>/dev/null || true' EXIT
    trap 'exit 0' INT TERM

    success "Celery workers started (PIDs: $CELERY_PID, $BEAT_PID)"

    # Start API with hot-reload (not exec'd, so the trap above still runs)
    echo ""
    success "Starting API server on http://localhost:7002"
    info "Press Ctrl+C to stop"
    echo ""
    uvicorn app.main:app --reload --host 0.0.0.0 --port 7002
}

# ── Frontend ─────────────────────────────────────────────────
start_frontend() {
    header "Starting Frontend (Next.js)"

    cd "$REPO_ROOT/frontend"

    if [[ ! -d node_modules ]]; then
        info "Installing frontend dependencies..."
        npm install
    fi

    export NEXT_PUBLIC_API_URL="http://localhost:7002"

    success "Starting frontend on http://localhost:7003"
    info "Press Ctrl+C to stop"
    echo ""
    exec npm run dev -- -p 7003
}

# ── Main ─────────────────────────────────────────────────────
case "$MODE" in
    infra)
        start_infra
        ;;
    backend)
        start_infra
        start_backend
        ;;
    frontend)
        start_frontend
        ;;
    all)
        start_infra
        echo ""
        info "Infrastructure is up. Now start in separate terminals:"
        echo ""
        echo -e "  ${BOLD}Terminal 1 (Backend):${NC}"
        echo "    ./scripts/dev.sh backend"
        echo ""
        echo -e "  ${BOLD}Terminal 2 (Frontend):${NC}"
        echo "    ./scripts/dev.sh frontend"
        echo ""
        info "Or use Docker for everything: ./scripts/setup.sh"
        ;;
    *)
        echo "Usage: ./scripts/dev.sh [all|backend|frontend|infra|stop]"
        exit 1
        ;;
esac

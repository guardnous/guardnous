# ─────────────────────────────────────────────────────────────
# GuardNous — Development Makefile
# Usage:  make help
# ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose
API_URL := http://localhost:7002
WEB_URL := http://localhost:7003

# ── Colours ──────────────────────────────────────────────────
GREEN  := \033[0;32m
YELLOW := \033[0;33m
CYAN   := \033[0;36m
RESET  := \033[0m

# ── Administrator login for `make seed` and `make check` ──────
# The password is never stored here. It is taken from ADMIN_PASSWORD:
#   make check ADMIN_PASSWORD='…'      (or export ADMIN_PASSWORD first)
# and, when that is empty, from INITIAL_ADMIN_PASSWORD in .env (correct only
# until the password is changed in the application).
ADMIN_EMAIL ?= admin@guardnous.com

# Shell fragment: sets $$TOKEN or stops the recipe with a clear message.
define ADMIN_TOKEN
pw="$${ADMIN_PASSWORD:-}"; \
if [ -z "$$pw" ] && [ -f .env ]; then \
	pw="$$(grep -E '^INITIAL_ADMIN_PASSWORD=' .env | tail -n 1 | cut -d= -f2-)"; \
fi; \
if [ -z "$$pw" ]; then \
	echo "  ✗ Administrator password not known. Pass it: make $@ ADMIN_PASSWORD='<password>'" >&2; \
	echo "    (or set INITIAL_ADMIN_PASSWORD in .env before the first start)" >&2; \
	exit 1; \
fi; \
TOKEN="$$(curl -sf -X POST $(API_URL)/api/v1/auth/login \
	--data-urlencode "username=$(ADMIN_EMAIL)" --data-urlencode "password=$$pw" \
	| python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])' 2>/dev/null)" \
	|| { echo "  ✗ Login as $(ADMIN_EMAIL) failed (wrong ADMIN_PASSWORD, or the API is not running)" >&2; exit 1; }
endef

.PHONY: help dev up down restart build rebuild logs status \
        migrate seed seed-test-data test eval-triage lint fmt clean \
        shell-api shell-db shell-redis \
        health check

# ═══════════════════════════════════════════════════════════════
#  Help
# ═══════════════════════════════════════════════════════════════
help: ## Show this help
	@printf "\n$(CYAN)GuardNous$(RESET) — Cloud Security & IaC Posture Management\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-18s$(RESET) %s\n", $$1, $$2}'
	@printf "\n"

# ═══════════════════════════════════════════════════════════════
#  Docker Lifecycle
# ═══════════════════════════════════════════════════════════════
dev: ## Start all services (foreground logs)
	$(COMPOSE) up --build

up: ## Start all services (background)
	$(COMPOSE) up -d --build
	@printf "\n$(GREEN)✓$(RESET) Services starting…\n"
	@printf "  API:  $(CYAN)$(API_URL)$(RESET)\n"
	@printf "  Web:  $(CYAN)$(WEB_URL)$(RESET)\n\n"

down: ## Stop all services
	$(COMPOSE) down

restart: ## Restart all services
	$(COMPOSE) restart

build: ## Build containers (no cache)
	$(COMPOSE) build --no-cache

rebuild: ## Rebuild & restart API + Web only
	$(COMPOSE) build api web --no-cache
	$(COMPOSE) up -d api web

logs: ## Tail logs for all services
	$(COMPOSE) logs -f --tail=100

logs-api: ## Tail API logs only
	$(COMPOSE) logs -f --tail=200 api

logs-web: ## Tail Web logs only
	$(COMPOSE) logs -f --tail=200 web

status: ## Show service status
	$(COMPOSE) ps

# ═══════════════════════════════════════════════════════════════
#  Database
# ═══════════════════════════════════════════════════════════════
migrate: ## Run Alembic migrations
	$(COMPOSE) exec api python -m app.core.migrations

seed: ## Seed governance frameworks + knowledge base (needs ADMIN_PASSWORD, see above)
	@$(ADMIN_TOKEN); \
	printf "$(YELLOW)→ Seeding governance frameworks…$(RESET)\n"; \
	curl -sf -X POST $(API_URL)/api/v1/governance/seed -H "Authorization: Bearer $$TOKEN" \
		| python3 -c 'import sys,json;d=json.load(sys.stdin);print("  ✓", d.get("message", d) if isinstance(d, dict) else d)' 2>/dev/null || echo "  ⚠ Governance seed skipped"; \
	printf "$(YELLOW)→ Seeding knowledge base…$(RESET)\n"; \
	curl -sf -X POST $(API_URL)/api/v1/knowledge/seed -H "Authorization: Bearer $$TOKEN" \
		| python3 -c 'import sys,json;d=json.load(sys.stdin);print("  ✓", d.get("message", d) if isinstance(d, dict) else d)' 2>/dev/null || echo "  ⚠ Knowledge seed skipped"
	@printf "$(GREEN)✓ Seeding complete$(RESET)\n"

# ═══════════════════════════════════════════════════════════════
#  Testing & Linting
# ═══════════════════════════════════════════════════════════════
seed-test-data: ## DEV ONLY: wipe the database and load test tenants/users/scans
	$(COMPOSE) exec api python seed_test_data.py --reset

# The backend image contains neither the tests nor pytest, so tests and lint
# run on the host with backend/.venv when it exists (python3 otherwise).
# One-time setup: cd backend && python3 -m venv .venv && .venv/bin/pip install poetry==1.8.2 ruff \
#   && .venv/bin/poetry install --no-root && .venv/bin/pip install -r requirements-cloud.txt
BACKEND_PY := $(shell [ -x backend/.venv/bin/python ] && echo .venv/bin/python || echo python3)

test: ## Run backend tests (on the host, see comment above)
	cd backend && $(BACKEND_PY) -m pytest tests/ -v --tb=short

eval-triage: ## Score the Triage Agent on labelled findings with the model of organization ORG (default 1)
	$(COMPOSE) exec api python -m app.services.agents.triage_eval --org $(or $(ORG),1)

test-cov: ## Run tests with coverage
	cd backend && $(BACKEND_PY) -m pytest tests/ -v --tb=short --cov=app --cov-report=term-missing

lint: ## Lint backend (ruff) + frontend (eslint)
	@printf "$(YELLOW)→ Linting backend…$(RESET)\n"
	cd backend && $(BACKEND_PY) -m ruff check app tests alembic
	@printf "$(YELLOW)→ Linting frontend…$(RESET)\n"
	cd frontend && npx eslint src/ --max-warnings=50 2>/dev/null || true
	@printf "$(GREEN)✓ Linting complete$(RESET)\n"

fmt: ## Format backend code (ruff)
	cd backend && $(BACKEND_PY) -m ruff format app/

# ═══════════════════════════════════════════════════════════════
#  Shell Access
# ═══════════════════════════════════════════════════════════════
shell-api: ## Open Python shell in API container
	$(COMPOSE) exec api python

shell-db: ## Open psql shell
	$(COMPOSE) exec postgres psql -U guardnous -d guardnous

shell-redis: ## Open redis-cli shell
	$(COMPOSE) exec redis redis-cli

# ═══════════════════════════════════════════════════════════════
#  Health & Verification
# ═══════════════════════════════════════════════════════════════
health: ## Check API health endpoint
	@curl -sf $(API_URL)/api/health | python3 -m json.tool

check: ## Full system check (health + login + dashboard)
	@printf "$(YELLOW)→ Health check…$(RESET)\n"
	@curl -sf $(API_URL)/api/health | python3 -c 'import sys,json;d=json.load(sys.stdin);print("  API:", d["status"], " DB:", d["db"], " Redis:", d["redis"])' || { echo "  ✗ API unreachable"; exit 1; }
	@printf "$(YELLOW)→ Auth check…$(RESET)\n"
	@$(ADMIN_TOKEN); \
	echo "  ✓ Login OK ($(ADMIN_EMAIL))"; \
	printf "$(YELLOW)→ Dashboard check…$(RESET)\n"; \
	curl -sf $(API_URL)/api/v1/dashboard -H "Authorization: Bearer $$TOKEN" \
		| python3 -c 'import sys,json;d=json.load(sys.stdin);print("  ✓ Dashboard OK — Score:", d["risk_score"]["overall"], " Findings:", d.get("total_findings", 0), " Scans:", d.get("total_scans", 0))' || { echo "  ✗ Dashboard failed"; exit 1; }
	@printf "$(GREEN)✓ System check complete$(RESET)\n"

# ═══════════════════════════════════════════════════════════════
#  Cleanup
# ═══════════════════════════════════════════════════════════════
clean: ## Stop services & remove volumes (DESTRUCTIVE)
	@printf "$(YELLOW)⚠  This will destroy all data. Continue? [y/N] $(RESET)" && read ans && [ "$$ans" = "y" ]
	$(COMPOSE) down -v --remove-orphans
	@printf "$(GREEN)✓ Cleaned$(RESET)\n"

reset: ## Full reset: clean + rebuild + migrate + seed
	$(MAKE) clean
	$(MAKE) up
	@printf "$(YELLOW)→ Waiting for services…$(RESET)\n"
	@sleep 15
	$(MAKE) seed
	@printf "$(GREEN)✓ Reset complete$(RESET)\n"

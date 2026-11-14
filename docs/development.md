# Development

[← Back to the README](../README.md) · See also [CONTRIBUTING.md](../CONTRIBUTING.md)

```bash
# Quick start (Docker)
./scripts/dev.sh infra      # Start Postgres + Redis
./scripts/dev.sh backend    # Start API with hot reload
./scripts/dev.sh frontend   # Start Next.js dev server

# Manual (needs a root .env first: run ./scripts/setup.sh once, or copy .env.example and set the two keys)
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install poetry==1.8.2 && poetry install --no-root
pip install -r requirements-cloud.txt      # cloud SDKs; the AWS tests need them
python -m app.core.migrations              # creates or upgrades the schema
uvicorn app.main:app --reload --port 7002

cd frontend && npm install && npm run dev -- -p 7003
```

Every setting in `.env` reaches the API and worker containers (`scripts/check-env-passthrough.sh` verifies this). The database and Redis addresses inside containers are fixed by `docker-compose.yml` and are not taken from `.env`.

### Useful Scripts

| Script | Purpose |
|---|---|
| `scripts/setup.sh` | One-command setup (prereqs → secrets → build → start → health check) |
| `scripts/dev.sh` | Local dev with hot reload |
| `scripts/reset.sh` | Wipe data and restart fresh |
| `scripts/healthcheck.sh` | Verify all services |

### Testing

```bash
# Backend unit tests
cd backend
pytest                                     # All tests
pytest tests/unit/                         # Unit tests
pytest --cov=app --cov-report=term-missing # Coverage

# End-to-end tests (14 suites, about 200 tests; needs the running stack)
cd e2e
npx playwright install chromium
export E2E_EMAIL=e2e@example.test E2E_PASSWORD='<a password of your choice>'
npx playwright test                        # all suites; the user is registered on first run
npx playwright test --list                 # list the tests without running them
npx playwright test tests/01-auth.spec.ts  # one suite
```

The 14 suites, in `e2e/tests/`: sign-in, navigation, dashboard, reports, CVEs, assessments, findings, AI Copilot, administration, plugins and settings, API health, forms, edge cases and buttons. There are no credentials in the test files; they come from `E2E_EMAIL` and `E2E_PASSWORD`.

The backend suite (`pytest`, 560+ tests) runs on SQLite and needs no running services.

---


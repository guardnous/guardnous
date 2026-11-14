# Contributing to GuardNous

Thank you for your interest in contributing! This guide covers how to set up the development environment, write code, and submit changes.

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker & Docker Compose v2+
- Git

### Option A: Full Docker Setup (quickest)

```bash
git clone https://github.com/guardnous/guardnous.git
cd guardnous
./scripts/setup.sh
```

The script writes `.env` with generated keys, starts the six services and prints the first administrator's password once. Running `docker compose up -d` without a `.env` does not work: the API refuses to start without `SECRET_KEY` and `ENCRYPTION_KEY`.

### Option B: Local Development (recommended for code changes)

**Start infrastructure services:**

```bash
docker compose up -d postgres redis
```

**Backend:**

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install poetry==1.8.2
poetry install --no-root
pip install -r requirements-cloud.txt   # cloud SDKs; the AWS tests need them

cp .env.example .env                    # then set SECRET_KEY and ENCRYPTION_KEY (commands are in the file)
python -m app.core.migrations           # creates or upgrades the schema

uvicorn app.main:app --reload --port 7002
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

**Celery workers (separate terminal):**

```bash
cd backend && source .venv/bin/activate
celery -A app.tasks.celery_app worker --loglevel=info
celery -A app.tasks.celery_app beat --loglevel=info
```

---

## Code Style

### Python (Backend)

- Follow PEP 8 conventions
- Use type hints for function signatures
- Use `async def` for database-touching endpoints
- Lint with `ruff` (`make lint`). The rules are in `backend/pyproject.toml` and the code passes them with no findings; keep it that way
- Pydantic v2 for all schemas

### TypeScript (Frontend)

- Use TypeScript strict mode
- Prefer functional components with hooks
- Use TanStack React Query for API calls — no manual `fetch` + `useEffect`
- TailwindCSS for styling — no inline `style` props
- Every page must be readable in **both themes**: give each colour a `dark:` counterpart and check text contrast in light and dark
- Type-check before you push: `npx tsc --noEmit -p .`

---

## Project Structure

Key directories to know:

```
backend/
├── app/api/v1/       # 25+ API route handlers (auth, 2FA, scans, findings, agents,
│                     #   scan-schedules, agent-audit, report-schedules, etc.)
├── app/models/        # 35+ SQLAlchemy models (User, Finding, AgentAuditEntry,
│                     #   ScanSchedule, ReportSchedule, UserInvitation, etc.)
├── app/schemas/       # Pydantic schemas — match API contracts
├── app/services/      # Business logic — scanners, CVE, risk, prompt registry, and:
│   ├── agents/        #   agent runtime, tools, fix PRs, chat attachments, PDF export
│   ├── cloud_connectors/  # AWS / Azure / GCP resource discovery
│   ├── cloud_posture/ #   posture rules, evaluation engine, fixes with rollback
│   └── federation/    #   OIDC issuer and keyless AWS connection
├── app/tasks/         # Celery tasks — scans, cloud sync, agent runs, CVE sync, reports, email
├── app/core/          # Config, security (JWT + TOTP), email, RBAC, encryption, logging
├── alembic/           # Database migrations (numbered, one per change; applied at startup)
└── tests/             # Test suite (unit + integration)

frontend/
├── src/app/           # Next.js pages (App Router) — login with 3-panel MFA flow,
│                     #   settings with SecurityTab for 2FA management
├── src/components/    # Reusable React components
└── src/lib/           # API client, auth hooks (with MFA state), utilities
```

---

## Writing Tests

We use **pytest** with **pytest-asyncio** for async test support.

### Running Tests

```bash
cd backend
pytest                                    # All tests (SQLite; no services needed)
pytest tests/test_findings.py             # One file
pytest tests/integration/                 # API tests only
pytest --cov=app --cov-report=term-missing # With coverage
```

### Test Organization

```
tests/
├── conftest.py                      # Test database and client fixtures
├── aws_model.py                     # Fake AWS session checked against botocore's models
├── test_agent_runtime.py            # Agent runs, approvals (and the ScriptedLLM helper)
├── test_cloud_posture.py            # Posture rules
├── test_findings.py                 # One file per area, at this level
├── ...
└── integration/
    ├── test_api.py                  # API endpoint tests
    └── test_admin_api.py            # Admin API tests
```

### Guidelines

- **Unit tests** should not require database, Redis, or external services
- **Integration tests** use the test database fixture defined in `conftest.py`
- Name tests descriptively: `test_scan_detects_public_s3_bucket`
- Each scanner rule should have at least one positive and one negative test case
- Mock external API calls (NVD, GitHub, etc.)
- **AWS code** is tested with the fake session in `tests/aws_model.py`. It validates every call and response against botocore's own service models, so a misspelled operation or parameter fails the test. Do not hand-roll a looser fake
- **Agent behaviour** is tested with `ScriptedLLM` (`tests/test_agent_runtime.py`): script the model's tool calls and answers, then assert on what was executed and what was stored
- A test must fail without your change. Do not add tests that only restate constants

---

## Making Changes

### Branch Naming

```
feature/short-description    # New features
fix/issue-or-description     # Bug fixes
docs/what-you-documented     # Documentation only
test/what-you-tested         # Test additions
```

### Commit Messages

Use conventional commits:

```
feat: add Kubernetes scanner support
fix: handle empty CVE response from NVD
docs: add architecture diagram
test: add risk scorer edge case tests
chore: update FastAPI to 0.110
```

### Pull Request Process

1. Fork the repo and create your branch from `main`
2. Make your changes with tests
3. Run the full test suite: `pytest`
4. Run lint checks: `make lint` (ruff + eslint) and `npx tsc --noEmit -p .` in `frontend/`
5. Update documentation if your change affects the API or architecture, and add a line to `CHANGELOG.md` under `[Unreleased]`
6. Open a PR with a clear description of what and why

### PR Checklist

- [ ] Tests pass locally
- [ ] New code has tests
- [ ] No hardcoded secrets or credentials
- [ ] API changes are reflected in schemas
- [ ] Every query is scoped to the caller's `organization_id`
- [ ] A tool that changes anything is listed in `TOOL_RISK`
- [ ] UI checked in light and dark theme
- [ ] Documentation and `CHANGELOG.md` updated (if applicable)

---

## Adding a New Scanner

1. Create one file in `backend/app/services/plugins/adapters/`, for example `your_scanner.py`
2. Define a `PluginAdapter` subclass with `metadata()`, `health()` and `scan()`. [docs/plugins.md](docs/plugins.md) has a complete working example
3. Restart the API and the workers. Adapters in that directory are found at startup; no registration step is needed. A file that fails to load is listed on the Plugins page and at `GET /api/v1/plugins/load-errors`
4. Add tests in `backend/tests/test_your_scanner.py`

---

## Adding an Agent Tool

1. Write the executor: `async def my_tool(ctx, ...) -> dict`. Use `ctx.db` and filter every query by `ctx.organization_id`
2. Add its schema to `TOOL_SCHEMAS` and its executor to the resolver in `backend/app/services/agents/tools.py`
3. **Classify what it changes.** A tool not listed in `TOOL_RISK` is treated as read-only and can run in chat without approval:
   - `INTERNAL_WRITE` — changes GuardNous data. The requester may approve
   - `EXTERNAL_WRITE` — changes something outside GuardNous (a repository, Slack, a cloud account). A different person with `agents:manage` must approve
4. For a write tool, implement the "prepare" step so the approver sees the exact change (see `prepare_action` in `runtime.py`). What runs after approval is the prepared change, not new model output
5. If the tool needs a permission beyond running agents, add it to `TOOL_PERMISSION`
6. Return real data or say it is missing. A tool that has no data returns `not_connected(...)`; it never invents a score or a result
7. Add tests with `ScriptedLLM`: the read path, and for write tools that nothing happens before approval or after a rejection

## Adding a Cloud Posture Rule

1. Make sure the collector reads the setting (`backend/app/services/cloud_connectors/aws_connector.py`, `aws_extra.py`). If a call can be denied, record it under `config["_unreadable"]` instead of guessing a value
2. Add the rule to `backend/app/services/cloud_posture/rules.py` with a `GN-AWS-<AREA>-<NNN>` id, severity, remediation text and, where one exists, the CIS control number **checked against the published benchmark**
3. The rule returns pass or fail, or raises `Unknown` when the setting was unreadable. `Unknown` is shown as "not checked"; it must never become a pass or a finding
4. Add a passing and a failing case to `tests/test_cloud_posture.py`, and a collector case to `tests/test_aws_collectors_against_api_model.py`
5. To offer a fix, add an action to `ACTIONS` in `cloud_posture/remediation.py` with a plan (from live state), an apply step that re-checks the state, a verification read, and a rollback. Add the IAM actions it needs to the `AllowFixes` policy in `federation/aws.py`

## Adding a New API Endpoint

1. Create or edit a route file in `backend/app/api/v1/`
2. Add Pydantic schemas in `backend/app/schemas/`
3. Register the router in `backend/app/api/v1/__init__.py` if it's a new module (use a unique prefix — avoid sub-paths of existing routers to prevent FastAPI path conflicts, e.g. use `/scan-schedules` instead of `/scans/schedules`)
4. Add integration tests in `backend/tests/integration/`

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `pyotp` + `qrcode[pil]` | TOTP-based 2FA (QR code generation, RFC 6238) |
| `reportlab` | Branded PDF report generation |
| `croniter` | Cron expression evaluation for scan schedules |
| `aiosmtplib` | Async SMTP email delivery |
| `python-jose[cryptography]` | JWT authentication, OIDC token signing |
| `boto3` and the Azure / Google SDKs (`requirements-cloud.txt`) | Cloud account sync, posture and fixes |
| `pypdf` | Text extraction from PDFs attached in chat |
| `tesseract` (system program) | Reads the text in attached images and scanned PDFs. Installed in the backend image; optional for local runs (images are refused with a clear message without it) |

The agent framework is native code in `backend/app/services/agents/`; there is no LangChain, CrewAI or DSPy dependency. Word and Excel attachments are read with the standard library (`zipfile` + XML), so no extra package is needed for them.

## Important Import Paths

- `get_current_user` → `from app.core.security import get_current_user` (NOT `app.core.auth`)
- `Base` (SQLAlchemy) → `from app.core.database import Base` (NOT `app.models.base`)

## Multi-Tenancy Considerations

- `User.email` is unique **per organization** (`UNIQUE(email, organization_id)`), not globally. The same email can exist in different tenants.
- Login iterates all users with a matching email and checks passwords — this supports cross-tenant scenarios.
- Invitation duplicate checks must be scoped to `user.organization_id`.
- Every new tenant registration auto-creates `OrgSettings` with `setup_completed=False`.
- Gmail SMTP overrides the `From` header with the authenticated account — document this for users who configure custom sender addresses.

## Security Rules for Contributions

- **Secrets**: never log, return or commit credentials. Stored tokens are encrypted with `ENCRYPTION_KEY`. Prefer connections that need no secret at all (the keyless AWS flow is the model)
- **Uploaded files** are untrusted. Enforce size limits, never execute or render them, and pass their text to a model as quoted material, not as instructions (see `attachments.py`)
- **Model output is untrusted.** It may propose an action; it may not perform one. Anything that changes state goes through the approval flow
- **Tenant isolation**: a request for another organization's object returns 404, not 403, and has a test

## Testing Against a Real AWS Account

Keyless AWS needs AWS to reach this installation's public signing keys. Set `OIDC_ISSUER_URL` to a public HTTPS address that serves `/.well-known/openid-configuration` and `/.well-known/jwks.json` (only these two files need to be public). On a laptop, a tunnel works for a short test, but its address changes when it restarts and the CloudFormation stack must then be redeployed; a static site or bucket you control is more stable. Use a personal or sandbox account, and deploy the stack with `AllowFixes=false` unless you are testing fixes.

## Demo / Test Repositories

Two companion repos are provided for end-to-end testing and demos:

| Repo | Purpose |
|------|---------|
| `guardnous-demo-webapp` | Vulnerable web application (Python/Node.js) — OWASP Top 10, hardcoded secrets, insecure dependencies, bad Docker/K8s configs |
| `guardnous-demo-infra` | Vulnerable IaC — Terraform (AWS/Azure/GCP), CloudFormation, Kubernetes manifests, Bicep, Dockerfiles with real misconfigurations |

Use these to demonstrate: multi-repo onboarding, scanning, governance, compliance, policy enforcement, exemptions, agentic triage, auto-remediation, and PR creation.

---

## Reporting Issues

- Use GitHub Issues
- Include steps to reproduce, expected behavior, and actual behavior
- Attach logs or screenshots if possible
- Tag with appropriate labels (bug, enhancement, documentation)

---

## Questions?

Open a discussion on GitHub or reach out to the maintainers.

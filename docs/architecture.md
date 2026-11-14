# GuardNous — Architecture

## System Overview

GuardNous is a multi-tier web application composed of six services:

```
                        ┌──────────────────────────────────────────────┐
                        │            User's Browser                    │
                        └──────────────────┬───────────────────────────┘
                                           │ HTTPS
                        ┌──────────────────▼───────────────────────────┐
                        │          Frontend  (Next.js 14)              │
                        │  • React 18 SPA with server components       │
                        │  • TailwindCSS + Lucide icons                │
                        │  • TanStack React Query for data fetching    │
                        │  • Recharts for dashboards                   │
                        │  Port: 3000 (mapped → 7003)                  │
                        └──────────────────┬───────────────────────────┘
                                           │ REST /api/v1/*
                        ┌──────────────────▼───────────────────────────┐
                        │           Backend  (FastAPI)                  │
                        │  • Python 3.12 + asyncio                     │
                        │  • SQLAlchemy 2.0 (async) + Alembic          │
                        │  • JWT + TOTP 2FA authentication              │
                        │  • Pydantic v2 request/response schemas      │
                        │  Port: 8000 (mapped → 7002)                  │
                        └────┬────────────────┬──────────────┬─────────┘
                             │                │              │
                   ┌─────────▼──────┐  ┌──────▼─────┐  ┌────▼──────┐
                   │  PostgreSQL 16 │  │  Redis 7   │  │  Celery   │
                   │  • ORM models  │  │  • Cache   │  │  • Worker │
                   │  • Migrations  │  │  • Broker  │  │  • Beat   │
                   │  Port: 5432    │  │  • Results │  │           │
                   │  (mapped 7000) │  │  Port 6379 │  │           │
                   └────────────────┘  │  (map 7001)│  └───────────┘
                                       └────────────┘
```

## Service Descriptions

### Frontend — Next.js 14

The web interface is a Next.js 14 application using the App Router. It runs in a multi-stage Docker build (builder → runner with standalone output).

**Key pages:**

| Route               | Purpose                                        |
|----------------------|------------------------------------------------|
| `/dashboard`         | Risk score, severity breakdown, trend charts   |
| `/findings`          | Paginated findings table with filters          |
| `/cves`              | CVE database search                            |
| `/reports`           | Generate and download PDF reports              |
| `/settings`          | Organization and user settings                 |
| `/agents`            | AI Copilot chat interface                      |
| `/integrations`      | VCS connection management                      |
| `/onboard`           | Repo onboarding wizard                         |
| `/login`             | Authentication (3-panel MFA flow)              |
| `/admin/users`       | User management + invitation system            |

**State management:** TanStack React Query for server state. Auth is managed via a custom `useAuth` React hook backed by JWT stored in `localStorage`.

**Theming:** Dark mode by default with orange brand color (`#f97316`). Theme preference stored in `localStorage`. A `<script>` tag in `layout.tsx` prevents flash of wrong theme on load.

---

### Backend — FastAPI

The core API server built with FastAPI. Uses async request handling with `asyncpg` for database I/O.

#### Startup Lifecycle

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()   # Create tables + run Alembic migrations
    yield
```

#### API Router Structure

All routes are mounted under `/api/v1/` via a single router in `app/api/v1/__init__.py`:

| Prefix              | Module             | Purpose                              |
|----------------------|--------------------|--------------------------------------|
| `/auth`              | `auth.py`          | Register, login, 2FA setup/verify, profile |
| `/scans`             | `scans.py`         | Create and list scans                |
| `/findings`          | `findings.py`      | Query and filter findings            |
| `/cves`              | `cves.py`          | CVE database queries                 |
| `/dashboard`         | `dashboard.py`     | Dashboard statistics (summary)       |
| `/reports`           | `reports.py`       | Report generation + email delivery   |
| `/integrations`      | `integrations.py`  | VCS OAuth flows                      |
| `/webhooks`          | `webhooks.py`      | Webhook receivers (GitHub, etc.)     |
| `/agents`            | `agents.py`        | AI Copilot chat endpoint             |
| `/scan-schedules`    | `scan_schedules.py`| CRUD for cron/interval scan schedules|
| `/agent-audit`       | `agent_audit.py`   | Agent execution audit trail          |
| `/report-schedules`  | `report_schedules.py`| CRUD for scheduled report delivery |
| `/users`             | `users_mgmt.py`    | User invitation (single, bulk, CSV)  |

Admin routes are mounted separately under `/api/admin/`.

#### Authentication

JWT-based auth flow:
1. **Register** → Creates `Organization` + `User` (admin role) → Returns JWT
2. **Login** → Verifies bcrypt password hash → Returns JWT
3. **Protected routes** → `Depends(get_current_user)` extracts user from `Authorization: Bearer <token>` header

---

### Services Layer

#### IaC Scanners (`app/services/scanners/`)

All scanners inherit from `BaseScanner` and return `list[ScanResult]`:

```python
class BaseScanner(ABC):
    @abstractmethod
    def scan(self, content: str, file_name: str = "") -> list[ScanResult]: ...

    @abstractmethod
    def detect_cloud_provider(self, content: str) -> str: ...
```

| Scanner                  | File Types              | Checks                                         |
|--------------------------|-------------------------|-------------------------------------------------|
| `TerraformScanner`       | `.tf`, `.tfvars`        | S3 public access, SG open ports, encryption, logging, root volumes |
| `CloudFormationScanner`  | `.yaml`, `.json`, `.template` | IAM wildcards, encryption, public access, logging |
| `BicepScanner`           | `.bicep`                | HTTPS, storage encryption, network rules, TLS, admin accounts |

Each scanner also auto-detects the cloud provider (AWS, Azure, GCP) from the IaC content.

#### Secrets Scanner (`app/services/secrets/`)

Regex-based secrets detector that checks source code for:
- API keys (AWS, GCP, Azure, generic)
- Tokens (JWT, OAuth, personal access)
- Private keys (RSA, DSA, EC, PGP)
- Passwords in connection strings
- Environment variable leaks

#### CVE Service (`app/services/cve/`)

- Syncs with the NVD (National Vulnerability Database) REST API v2.0
- Stores CVE records in PostgreSQL
- Supports keyword and package-level search
- CVSS v3.1 severity scoring

#### Risk Scorer (`app/services/risk/`)

Computes a risk score (0–100) from the open findings:
- Each finding adds a weight for its severity
- Up to a total weight of 250 the score rises in a straight line to 50; beyond that it rises with the logarithm of the weight and reaches 100 at 25,000, so a large backlog still shows progress when findings are fixed
- A per-cloud-provider breakdown is returned with the total

#### AI Copilot / Agent Layer (`app/services/agents/`)

Bring-your-own-model architecture written as native code (no agent framework dependency). 20 agents share 72 tools; `AGENTS.md` and `SKILLS.md` describe them in full. The chat path looks like this:

```
User Message
     │
     ▼
┌─────────────────┐
│  Orchestrator    │ ← System prompt + context pack
│                  │
│  ┌────────────┐  │
│  │Skill Router│──┼──→ Deterministic skill match? → Execute skill
│  └────────────┘  │
│       │ No       │
│       ▼          │
│  ┌────────────┐  │
│  │ LLM Client │──┼──→ Model-driven reasoning (multi-step tool calls)
│  └────────────┘  │
│       │          │
│  ┌────────────┐  │
│  │   Tools    │──┼──→ list_findings, get_risk_score, search_cves, cloud_posture_summary, …
│  └────────────┘  │
└─────────────────┘
```

**Supported LLM Providers:**
- `mock` — deterministic, no API key needed (default)
- `openai` — OpenAI API
- `azure` — Azure OpenAI Service
- `anthropic` — Anthropic Claude
- `ollama` — Local Ollama instance

**Skills:** Typed, deterministic handlers for common queries (e.g., "show critical findings", "what's my risk score"). Faster and more reliable than LLM round-trips.

**Tools:** 72 functions the model can call. 67 only read the organization's data and return structured JSON. Five change something (`triage_finding`, `triage_findings`, `open_fix_pull_request`, `remediate_cloud_finding`, `send_slack_message`); the three that act outside GuardNous pause the run until a second person approves the exact change (`runtime.py`).

**Chat files:** attached files are reduced to text on upload (`attachments.py`); images and scanned PDFs are read with the local `tesseract` program, and credentials in the text are replaced with a marker before it is stored.

#### VCS Integrations (`app/services/vcs/`)

| Provider     | Auth Method                        | Features                                        |
|--------------|------------------------------------|-------------------------------------------------|
| GitHub       | GitHub App or personal access token | Clone, PR comments, webhooks, fix pull requests |
| GitLab       | Personal access token (gitlab.com or self-managed) | Clone, MR comments, webhooks, fix merge requests |
| Bitbucket    | App password (Bitbucket Cloud)      | Clone, PR comments, webhooks, fix pull requests |
| Azure DevOps | Personal access token               | Clone, PR comments, webhooks, fix pull requests |

Fix pull requests are written through `fix_writers.py` (GitLab, Bitbucket, Azure DevOps) and `github.py`, all behind the same six calls.

VCS tokens are encrypted at rest using Fernet (`app/core/encryption.py`).

---

### Database Layer

**ORM:** SQLAlchemy 2.0 with async session (`asyncpg` driver).

**Key Models:**

| Model              | Table                | Purpose                               |
|--------------------|----------------------|---------------------------------------|
| `User`             | `users`              | User accounts with hashed passwords, TOTP 2FA, email verification |
| `Organization`     | `organizations`      | Multi-tenant organization container (UI label: "Tenant") |
| `Scan`             | `scans`              | Scan records with status tracking     |
| `Finding`          | `findings`           | Individual security findings          |
| `CVE`              | `cves`               | CVE records from NVD                  |
| `Report`           | `reports`            | Generated PDF report metadata         |
| `Integration`      | `integrations`       | VCS OAuth tokens (encrypted)          |
| `AgentConversation`| `agent_conversations`| AI Copilot chat history               |
| `LLMConfig`        | `llm_configs`        | Per-org LLM provider settings         |
| `OnboardingToken`  | `onboarding_tokens`  | Repo onboarding flow tokens           |
| `Role`             | `roles`              | RBAC roles with agent/tool access     |
| `AgentAuditEntry`  | `agent_audit_entries`| Agent execution audit trail           |
| `ScanSchedule`     | `scan_schedules`     | Cron/interval scan schedule config    |
| `ReportSchedule`   | `report_schedules`   | Scheduled report email delivery       |
| `UserInvitation`   | `user_invitations`   | User invitation tokens + email status |

**Migrations:** Alembic with async PostgreSQL support. Migration files in `backend/alembic/`.

---

### Task Queue

**Celery** with Redis as broker and result backend:

| Component      | Redis DB | Purpose               |
|----------------|----------|-----------------------|
| Broker         | DB 1     | Task message queue    |
| Result backend | DB 2     | Task results storage  |
| Cache          | DB 0     | Application cache     |

**Scheduled Jobs (Celery Beat):**
- CVE database synchronization (daily)
- Scan schedule evaluation (hourly — triggers scans based on cron/interval config)
- Scheduled report generation and email delivery (runs per ReportSchedule entries)

#### Email Service (`app/core/email.py`)

SMTP-based email delivery using `aiosmtplib` with branded HTML templates:
- **Account verification** — JWT-signed verification links (24h expiry) sent on registration and invitation acceptance
- **Tenant creation** — Notification email sent to admin on new tenant creation
- **Scan reports** — severity breakdown, finding counts, risk score
- **Scheduled reports** — PDF attachments emailed to configured recipients
- **User invitations** — branded onboarding email with one-click registration link
- All templates use the GuardNous orange brand color (`#f97316`)

---

### Containerization

#### Docker Compose

Six services in a single `docker-compose.yml`:

```yaml
postgres  → Port 7000 (→ 5432)  # PostgreSQL 16 with health checks
redis     → Port 7001 (→ 6379)  # Redis 7 Alpine
api       → Port 7002 (→ 8000)  # FastAPI backend
celery-worker                    # Celery task executor
celery-beat                      # Celery scheduler
web       → Port 7003 (→ 3000)  # Next.js frontend
```

All backend services share the `.env` file and connect to the internal Docker network.

#### Kubernetes

The Helm chart in `helm/guardnous/` provides:
- API, worker, scheduler and web Deployments, with autoscaling for the API
- Schema migrations in an init container of the API pod, under a database lock
- A Secret for the keys and the database and Redis addresses
- Services and an Ingress

PostgreSQL and Redis are external: give their addresses in the values file. The chart is a preview: it has not yet been tested on a cluster, and Kubernetes becomes a supported deployment in a future release. Docker Compose is the supported deployment today.

---

## Data Flow: Scan Lifecycle

```
1. User triggers scan (POST /api/v1/scans/)
2. API creates Scan record (status: "pending")
3. Celery task is dispatched to worker queue
4. Worker:
   a. Clones repository via VCS service (or reads uploaded content)
   b. Identifies IaC files by extension
   c. Runs appropriate scanner(s)
   d. Matches findings against CVE database
   e. Computes risk score
   f. Stores findings in PostgreSQL
   g. Posts PR comments if VCS integration exists
5. Scan status → "completed"
6. Dashboard auto-refreshes via React Query polling
```

---

## Security Considerations

- JWT tokens expire after 60 minutes (configurable)
- All VCS tokens encrypted at rest with Fernet
- CORS is restricted to configured origins
- Non-root Docker containers
- No hardcoded secrets (all via environment variables)
- Webhook signature verification

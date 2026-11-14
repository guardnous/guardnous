# Getting started

[← Back to the README](../README.md)

### One-Command Setup (Docker)

```bash
git clone https://github.com/guardnous/guardnous.git
cd guardnous
./scripts/setup.sh
```

This checks prerequisites (Docker Compose 2.24 or newer), generates the secret keys, builds the images, runs migrations and starts all 6 services. The first build downloads the scanners and takes several minutes.

At the end the script prints the address (**http://localhost:7003**) and the administrator login: `admin@guardnous.com` and a **generated password, shown once**. It is also stored in `.env` as `INITIAL_ADMIN_PASSWORD`. Change it after the first login. There is no default password.

### Kubernetes (preview, planned for a future release)

Docker Compose is the supported way to run GuardNous today. A Helm chart and these scripts are included as a preview:

```bash
./scripts/setup-k8s.sh          # Wizard: DB, Redis, registry, domain, TLS
./scripts/build-images.sh -r ghcr.io/<your-org> -t v2.0.0 --api-url https://<your-host> -p
./scripts/deploy.sh -f helm/guardnous/values-generated.yaml
```

> **The Helm chart has not yet been tested on a cluster.** Kubernetes becomes a supported deployment in a future release, once the chart has been run and verified end to end. Until then, treat a deployment as a trial and expect to adjust values.

> Already have PostgreSQL and Redis deployed? The wizard asks — just provide endpoints and credentials.

### Prerequisites

| Tool | Required | Purpose |
|------|----------|---------|
| Docker + Compose | Yes (local dev) | Container runtime |
| Python 3.12 | Backend | FastAPI server |
| Node.js 18+ | Frontend | Next.js app |
| PostgreSQL 16 | Database | Can be external (RDS, Azure DB, Cloud SQL) |
| Redis 7 | Cache + broker | Can be external (ElastiCache, Memorystore) |
| Kubernetes 1.25+ | Optional | Helm chart (preview, not yet tested on a cluster) |

### Service Ports (Local Dev)

| Service | URL | Purpose |
|---|---|---|
| Dashboard | http://localhost:7003 | Web UI |
| API | http://localhost:7002 | REST API |
| API Docs | http://localhost:7002/docs | Swagger / OpenAPI. Served unless `ENVIRONMENT=production` |
| PostgreSQL | localhost:7000 | Database |
| Redis | localhost:7001 | Cache + message broker |

### 🖥️ Dashboard Pages

| Page | Nav Label | Description |
|------|-----------|-------------|
| `/dashboard` | Dashboard | Risk score, finding trends, severity breakdown |
| `/scans` | **Assessments** | IaC security assessments — trigger, schedule, review |
| `/jobs` | **Task Monitor** | Background task status — scans, syncs, imports |
| `/findings` | Findings | Triage, assign, bulk-update, investigate |
| `/cves` | CVEs | NVD/GHSA/EPSS vulnerability database with affected packages |
| `/reports` | Reports | Generate, download, and view PDF/CSV/HTML reports |
| `/integrations` | Integrations | Connect GitHub, GitLab, Bitbucket, Azure DevOps |
| `/governance` | Governance | Compliance frameworks — SOC 2, ISO 27001, PCI-DSS, HIPAA |
| `/cloud-accounts` | Cloud Connectors | One card per cloud (AWS, Azure, Google Cloud); connect, test, sync |
| `/cloud-posture` | Cloud Posture | Accounts grouped per cloud; each account opens its own findings, exposure and rules page |
| `/agents` | AI Copilot | Chat on live data, file attachments, PDF export |
| `/agent-runs` | Agent Runs | Background agent tasks, step-by-step log, approvals, token usage |
| `/plugins` | Plugins | Enable/disable scanner adapters |
| `/iam` | IAM | Rule-based IAM posture from synced cloud accounts (AWS users/roles, Azure role assignments, GCP bindings) |
| `/settings` | Settings | Tenant and profile configuration |
| `/setup` | Setup Wizard | First-login guided configuration (admin only) |
| `/verify-email` | Email Verification | JWT-based email address confirmation |
| `/admin/*` | Admin | Tenants → Users → Groups → Roles → Audit Logs → System Logs |

---


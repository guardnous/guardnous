<div align="center">

<img src="docs/images/logo.svg" alt="GuardNous Logo" width="120" height="120">

# GuardNous

### *Defend What Matters*

**AI Security Intelligence Platform**

**Code scanning · Cloud posture · 20 AI agents with human approval for every change**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Next.js 14](https://img.shields.io/badge/Next.js-14-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](docker-compose.yml)
[![Helm 3](https://img.shields.io/badge/Helm-3-0F1689?style=for-the-badge&logo=helm&logoColor=white)](https://helm.sh)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge)](CONTRIBUTING.md)

GuardNous is a self-hosted security platform that does three things:

1. **Code and IaC scanning.** It runs the scanners you already trust (Semgrep, Trivy, Checkov,
   tfsec, Gitleaks) on your repositories, normalizes their output, and gives your team one place
   to triage, assign and track findings.
2. **Cloud posture.** It connects to a live AWS account without access keys, reads its
   configuration, and checks it against 44 rules (19 mapped to CIS AWS Foundations v1.4.0).
   Azure and Google Cloud accounts can be connected and inventoried; posture rules are AWS-only today.
3. **AI agents that act, with approval.** 20 agents with 72 tools answer questions from real
   data, open fix pull requests, post to Slack and fix cloud misconfigurations. Anything that
   changes something stops and waits for a person to approve the exact change.

> **Not another scanner.** We don't re-invent static analysis. We unify the results, add cloud
> posture and an agent layer, and wrap it in enterprise workflow (RBAC, multi-tenancy, SLA tracking,
> SBOM export, compliance mapping, 2FA, PDF reports, policy-as-code) under the Apache 2.0 license.

[**Quickstart**](#-quickstart) · [**Why GuardNous**](#-why-guardnous) · [**Features**](#-features) · [**Architecture**](#-architecture) · [**Production Deploy**](#-production-deployment) · [**Plugin Ecosystem**](#-plugin-ecosystem) · [**API**](#-api-reference) · [**Contributing**](CONTRIBUTING.md)

<br/>

<img src="docs/screenshots/02-dashboard.png" alt="GuardNous Dashboard" width="100%" />

</div>

---

## 📸 Screenshots

<details>
<summary><b>Click to expand — 22 screens of the GuardNous UI</b></summary>

| | |
|---|---|
| **1. Login** | **2. Dashboard** |
| ![Login](docs/screenshots/01-login.png) | ![Dashboard](docs/screenshots/02-dashboard.png) |
| **3. VCS Integrations** | **4. Assessments** |
| ![Integrations](docs/screenshots/03-integrations.png) | ![Assessments](docs/screenshots/04-assessments.png) |
| **5. Task Monitor** | **6. Findings** |
| ![Task Monitor](docs/screenshots/05-task-monitor.png) | ![Findings](docs/screenshots/06-findings.png) |
| **7. CVEs** | **8. Reports** |
| ![CVEs](docs/screenshots/07-cves.png) | ![Reports](docs/screenshots/08-reports.png) |
| **9. Cloud Connectors** | **10. Connect AWS without access keys** |
| ![Cloud Connectors](docs/screenshots/09-cloud-connectors.png) | ![Connect AWS](docs/screenshots/10-connect-aws-without-keys.png) |
| **11. Cloud Posture — accounts per cloud** | **12. Cloud Posture — one account** |
| ![Cloud Posture](docs/screenshots/11-cloud-posture.png) | ![Cloud Posture account](docs/screenshots/12-cloud-posture-account.png) |
| **13. Cloud posture assessment pipeline** | **14. Governance** |
| ![Posture pipeline](docs/screenshots/13-cloud-posture-pipeline.png) | ![Governance](docs/screenshots/14-governance.png) |
| **15. IAM** | **16. AI Copilot** |
| ![IAM](docs/screenshots/15-iam.png) | ![AI Copilot](docs/screenshots/16-ai-copilot.png) |
| **17. Agent Run — approval with the exact change** | **18. Plugins** |
| ![Agent run approval](docs/screenshots/17-agent-run-approval.png) | ![Plugins](docs/screenshots/18-plugins.png) |
| **19. Settings** | **20. Admin — Users** |
| ![Settings](docs/screenshots/19-settings.png) | ![Admin Users](docs/screenshots/20-admin-users.png) |
| **21. Admin — Roles** | **22. Admin — Audit Logs** |
| ![Admin Roles](docs/screenshots/21-admin-roles.png) | ![Audit Logs](docs/screenshots/22-admin-audit.png) |

Account numbers and user names in the screenshots are masked.

</details>

---

## 🎯 Why GuardNous?

Most security teams are stuck between two bad options:

| Option | Problem |
|--------|---------|
| **CLI scanners** (Trivy, Checkov, tfsec) | Great tools — zero platform. No dashboard, no triage, no governance, no RBAC. |
| **SaaS platforms** (Wiz, Snyk, Prisma) | $50K–$500K/year. Vendor lock-in. Your code leaves your network. |
| **OSS alternatives** (DefectDojo) | Finding aggregator with dated UX, no IaC-native scanning, no policy engine. |

**GuardNous fills the gap:** a production-grade platform layer that sits on top of the scanners you already trust, adds enterprise workflow, and costs nothing.

### How We're Different

| Capability | CLI Tools | SaaS ($$$) | DefectDojo | **GuardNous** |
|---|---|---|---|---|
| IaC scanning (TF, CF, Bicep) | ✅ | ✅ | ❌ | ✅ Native + 5 plugin adapters |
| Secrets detection | Partial | ✅ | ❌ | ✅ Gitleaks plus 18 built-in patterns |
| CVE tracking (NVD + GHSA + EPSS) | ❌ | ✅ | ✅ | ✅ Daily sync |
| Governance / compliance mapping | ❌ | ✅ | ❌ | ✅ 6 frameworks, 92 controls |
| Policy-as-code engine | ❌ | ✅ | ❌ | ✅ 21 built-in + custom policies |
| Findings triage workflow | ❌ | ✅ | Partial | ✅ Bulk ops, notes, SLA tracking |
| SBOM export (CycloneDX 1.5) | Partial | ✅ | ❌ | ✅ |
| Multi-tenant RBAC | ❌ | ✅ | Partial | ✅ 72 permissions, 7 roles, org switcher |
| Webhook-triggered PR scanning | ❌ | ✅ | ❌ | ✅ 4 VCS providers + PR comments |
| Scheduled/recurring scans | ❌ | ✅ | ✅ | ✅ Celery Beat + cron schedules |
| Cloud posture on live accounts (CSPM) | ❌ | ✅ | ❌ | ✅ AWS: 44 rules, 19 mapped to CIS v1.4.0 |
| Cloud connection without access keys | ❌ | ✅ | ❌ | ✅ AWS via OIDC federation + one CloudFormation stack |
| Cloud fixes with approval and rollback | ❌ | Partial | ❌ | ✅ 5 AWS fixes, second-person approval |
| AI security copilot (BYOM) | ❌ | ❌ | ❌ | ✅ OpenAI / Azure OpenAI / Azure AI Foundry / Anthropic / Ollama |
| Chat with file attachments and PDF export | ❌ | Partial | ❌ | ✅ PDF, Word, Excel, CSV, JSON, text |
| AI fix pull requests | ❌ | Partial | ❌ | ✅ Diff shown before approval (GitHub, GitLab, Bitbucket, Azure DevOps) |
| Human approval for every agent action | ❌ | Partial | ❌ | ✅ Exact change shown; no self-approval for external changes |
| Multi-agent delegation protocol | ❌ | ❌ | ❌ | ✅ Depth-tracked orchestration |
| Prompt registry (13 built-in) | ❌ | ❌ | ❌ | ✅ Per-org customizable |
| Enhanced guardrails (PII/injection/output) | ❌ | Partial | ❌ | ✅ 55 patterns |
| Agent audit trail | ❌ | ❌ | ❌ | ✅ Full execution logging |
| Scanner attribution on findings | ❌ | ✅ | Partial | ✅ Per-finding scanner tag |
| Two-factor authentication (TOTP) | ❌ | ✅ | ❌ | ✅ QR-code + backup codes |
| Email verification (JWT-signed links) | ❌ | ✅ | ❌ | ✅ 24h token, auto-send |
| Multi-tenant isolation | ❌ | ✅ | ❌ | ✅ One database; every row belongs to a tenant and organization and every query is filtered by them |
| Organization switcher (multi-org users) | ❌ | ✅ | ❌ | ✅ Sidebar switcher, JWT re-issue |
| First-login setup wizard | ❌ | ✅ | ❌ | ✅ 5-step guided config |
| Branded PDF reports + email delivery | ❌ | ✅ | Partial | ✅ Scheduled + on-demand |
| User invitation with email onboarding | ❌ | ✅ | Partial | ✅ Auto-send branded emails |
| Self-hosted / air-gapped | ✅ | ❌ | ✅ | ✅ |
| **Price** | Free | $50K+/yr | Free | **Free (Apache 2.0)** |

### Who Is This For?

- **Platform/DevOps teams** who run Checkov and Trivy in CI but have nowhere to track findings
- **Regulated companies** (fintech, healthcare) that need compliance dashboards for audits
- **MSSPs** managing security for multiple clients — one dashboard, tenant-isolated
- **Startups** who need Wiz-level visibility but can't justify $100K in SaaS spend

---

## 🚀 Quickstart

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

## ✨ Features

### 🔌 Plugin-Based Scanner Aggregation

GuardNous doesn't try to replace your scanners — it orchestrates them. The plugin system fans out scans across all enabled adapters in parallel (`ThreadPoolExecutor`, max 6 workers), deduplicates results by `(rule_id, file_path, line_number, resource_name)`, and normalizes everything into a unified finding format.

| Adapter | Type | What It Does |
|---------|------|--------------|
| **Checkov** | External | Runs real `checkov` binary, parses JSON output. 1000+ checks for TF/CF/K8s. |
| **Trivy** | External | Runs real `trivy` binary. IaC misconfig + vulnerability detection. |
| **Semgrep** | External | Runs real `semgrep` binary with `--config auto`. Language-aware SAST. |
| **tfsec** | External | Runs real `tfsec` binary, parses JSON. Terraform-specific deep checks. |
| **Gitleaks** | External | Runs real `gitleaks` binary. Git-aware secrets detection. |
| **Terraform Scanner** | Native | 41 checks. AWS/Azure/GCP misconfiguration rules. |
| **CloudFormation Scanner** | Native | AWS-specific resource analysis. |
| **Bicep Scanner** | Native | 943 lines. Azure ARM template analysis. |
| **Secrets Scanner** | Native | 18 regex patterns. API keys, tokens, private keys, connection strings. |

> Adapters auto-disable if their binary isn't on `PATH` — no crashes, just graceful degradation.

### 🛡️ Policy-as-Code Engine

21 built-in policies with **structured rule matching** (not just regex). Policies match by real scanner rule IDs (`CKV_AWS_*`, `AVD-AWS-*`, `SD-SEC-*`), resource types, severity thresholds, and categories.

- **Policy exceptions/waivers** with expiry dates — temporarily suppress false positives
- **Dual matching**: structured `rule_id` prefix matching (high confidence) + regex fallback
- **Categories**: encryption, networking, iam, logging, storage, secrets, kubernetes
- Add your own policies in code or via API

### 🔍 Findings Triage Workflow

Go beyond `is_fixed` / `is_ignored` — GuardNous provides a full triage lifecycle:

| Status | Meaning |
|--------|---------|
| `open` | New finding, unreviewed |
| `triaged` | Reviewed, confirmed real issue |
| `in_progress` | Fix underway, assignee set |
| `resolved` | Fixed, timestamp recorded |
| `false_positive` | Not a real issue, reason documented |

- **Bulk operations** — update status/assignee for up to 500 findings at once
- **Investigation notes** — append timestamped notes with author tracking
- **Decisions last** — a finding marked false positive or triaged keeps that state on the next scan of the same repository
- **SLA deadlines** — each finding gets a remediation deadline from its severity (7 / 30 / 90 / 180 days for Critical / High / Medium / Low; set with `SLA_DAYS_*`). The clock starts when the finding is first seen and is not reset by rescans. Findings show on track, due soon or overdue, can be filtered by it, and a summary reports overdue counts and the share resolved in time over the last 90 days. The policy is per installation; there are no breach notifications yet
- **Assignee tracking** — route findings to the right engineer

### 📋 SBOM Export (CycloneDX 1.5)

A full repository assessment stores the dependencies declared in 9 manifest formats (`requirements.txt`, `Pipfile`, `package.json`, `go.mod`, `pom.xml`, `build.gradle`, `Gemfile`, `Cargo.toml`, `composer.json`). The assessment page then offers **Download SBOM (CycloneDX 1.5)**, also available at `GET /api/v1/sbom/scans/{id}`:

- A Package URL (purl) for every component, with dev/prod scope
- Vulnerability cross-references from the CVE database (NVD and GHSA, with known-exploited and EPSS data). Matches are by package name and version range and are marked "in triage", not confirmed
- **Licences, optional** (`DEPENDENCY_LICENSE_LOOKUP=true`): licences are looked up at [deps.dev](https://deps.dev) for npm, PyPI, Go, Maven, Cargo and RubyGems, and strong-copyleft or restrictive licences in production dependencies are flagged for review. It is off by default because it sends your dependency names and versions to a public service

Limits: only the dependencies a manifest declares are listed (lock files are not parsed, so transitive dependencies are missing); versions are the declared ones; Composer packages have no licence data; assessments run before this feature, and quick scans, have no SBOM until they are run again; there is no SPDX output and no licence policy editor.

### 📊 Governance & Compliance

6 compliance frameworks with 92 controls, each mapped to real finding categories:

| Framework | Controls | Use Case |
|-----------|----------|----------|
| SOC 2 Type II | 16 | SaaS companies, annual audits |
| ISO 27001 | 15 | International standard, ISMS |
| PCI-DSS v4.0 | 12 | Payment card processing |
| HIPAA | 11 | Healthcare data protection |
| CIS Benchmarks | 18 | Cloud hardening baseline |
| NIST 800-53 | 20 | US federal / FedRAMP |

Score = `passing / (passing + failing) × 100`, counted over assessed controls only.
A control passes or fails based on open findings in its security domain; it is
**Not assessed** until a scan has covered that domain, and controls that need
human evidence (policies, training, physical security) are marked **Manual**.
A framework has no score until at least one control has been assessed.

### ☁️ Cloud Posture (AWS)

GuardNous reads the configuration of a connected AWS account and checks it against fixed rules. No agent or model is involved in deciding what is a finding.

- **44 rules** (`GN-AWS-*`): root MFA, password policy, access key age, public S3 buckets, open SSH/RDP, unencrypted RDS and EBS, CloudTrail, VPC flow logs, KMS rotation, GuardDuty, AWS Config, EKS public endpoints, load balancers without WAF, expiring certificates, retired Lambda runtimes and more. 19 are mapped to **CIS AWS Foundations v1.4.0** control numbers.
- **What is read**: IAM, S3, EC2, RDS, Lambda, VPC, CloudTrail, KMS, ELB/WAF, ACM, EKS, ECR, Secrets Manager, Route 53, GuardDuty and Config. By default every region enabled in the account is read, several at a time, plus the global services. A region list set on the account narrows this. If the role may not list regions, four are read (`us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`). Only one sync of an account runs at a time.
- **Honest about gaps**: when a setting could not be read, the check is reported as "not checked". It is never reported as passing and never invented as a finding.
- **Findings follow the cloud**: a finding opens when a resource fails a rule, resolves when it passes again, and reopens if it regresses. Findings marked false positive are left alone.
- **Internet exposure view**: instances with a public address behind open ports, public databases, public Kubernetes endpoints, buckets without a public access block.
- **Per-account pages**: `/cloud-posture` groups accounts per cloud; each account has its own page.
- **Its own pipeline**: a posture assessment shows "Reading the cloud account → Checking rules → Updating findings" with real timings, not the repository scan pipeline.

Azure and Google Cloud accounts can be connected and their resources inventoried. Posture rules for them are not written yet.

### 🔑 Connect AWS Without Access Keys

Enter the 12-digit account ID, deploy one CloudFormation stack, and the account connects by itself. No access key is created, copied or stored.

- GuardNous is an **OIDC identity provider**. The stack creates an IAM role that trusts tokens signed by your GuardNous installation, for one subject (`guardnous:org:<org>:aws:<account>:<nonce>`) and one audience (`sts.amazonaws.com`).
- GuardNous signs a short-lived token and exchanges it with `AssumeRoleWithWebIdentity` for temporary credentials each time it syncs.
- The role gets the AWS managed **SecurityAudit** policy (read-only). The stack parameter `AllowFixes=true` adds only the write actions the built-in fixes need.
- **Requirement**: AWS must be able to fetch the public signing keys, so `OIDC_ISSUER_URL` must be a public HTTPS address serving `/.well-known/openid-configuration` and `/.well-known/jwks.json`. Only those two public files need to be reachable; the rest of GuardNous can stay private.

An IAM role ARN or access keys are still accepted for installations that cannot expose the two files.

### 🔧 Cloud Fixes with Approval and Rollback

Five AWS misconfigurations can be fixed from GuardNous:

| Rule | Fix |
|------|-----|
| `GN-AWS-S3-001` | Block public access on the S3 bucket |
| `GN-AWS-SG-001` / `SG-002` | Remove the internet-wide SSH / RDP rule from a security group |
| `GN-AWS-REGION-001` | Turn on EBS encryption by default |
| `GN-AWS-KMS-001` | Turn on KMS key rotation |

A fix is planned from the live state of the resource, shown to an approver as the exact change, and applied only after a **second person** approves it. If the resource changed between planning and approval, the fix is refused. Every change is recorded with the previous state and can be **rolled back** from the account's posture page.

### 🤖 AI Security Copilot and Agent Runs (BYOM)

Bring Your Own Model: OpenAI, Azure OpenAI, Azure AI Foundry (including Claude models), Anthropic, or a local Ollama instance.

**Chat (`/agents`)**
- Answers come from tools that read your real findings, scans, cloud inventory and posture. A tool that has no data says "not connected" instead of making up a score.
- **Attach files**: PDF, Word (`.docx`), Excel (`.xlsx`), CSV, JSON, YAML, Markdown, text, logs, source files and images (PNG, JPEG, GIF, WebP, BMP, TIFF); up to 5 files of 15 MB per message. Text is extracted on upload and the file itself is not stored. For images and scanned PDFs the text in them is read on the server with Tesseract; the picture itself is not interpreted. Old Office formats (`.doc`, `.xls`) and HEIC are refused with a reason.
- **Secrets in attachments are hidden**: access keys, tokens, passwords, private keys, connection strings, card and social security numbers are replaced with a marker before the text is stored or sent to a model. IP addresses, e-mail addresses and account IDs are kept, because they are usually what the question is about.
- **PDF export**: ask for a PDF and the reply carries a download; every answer also has a "PDF" action.
- **Plain answers**: no "Thought / Observation" scaffolding, no emoji, no narration of the process.
- **Chat cannot change anything.** A tool that writes is refused in chat and the user is pointed to Agent Runs.

**Agent Runs (`/agent-runs`)**
- Give an agent a task; a worker runs it in the background. Every model call and tool call is stored as a step, with token usage.
- A tool that changes something **pauses the run** and asks for approval, showing the exact change (for a fix pull request: the diff).
- Changes to GuardNous data (triaging a finding) may be approved by the requester. Changes outside GuardNous (a pull request, a Slack message, a cloud change) need a **different person** with `agents:manage`.
- What is executed is the approved change, not whatever the model says next.
- Runs survive restarts, have a step and token budget, and a sweep fails runs whose worker died.

| Action | Tool | Approval |
|--------|------|----------|
| Triage a finding | `triage_finding` | Requester or a manager |
| Open a fix pull request (GitHub, GitLab, Bitbucket Cloud, Azure DevOps) | `open_fix_pull_request` | A second person |
| Post to Slack | `send_slack_message` | A second person |
| Fix a cloud misconfiguration | `remediate_cloud_finding` | A second person |

**Three-Layer AI Triage Pipeline:**
1. **Heuristic pre-scoring** — instant, deterministic severity + exposure + resource-value analysis
2. **False-positive detection** — pattern-based noise reduction (test files, docs, example code, non-prod resources)
3. **AI contextual analysis** — LLM-powered real-world exploitability, blast radius, and scanner-reliability assessment with confidence scoring

**Fix pull requests:**
- The agent reads the file from the repository, generates the fix, and the approver sees the **diff** before anything is pushed
- After approval GuardNous creates a branch, commits the change and opens the pull request on GitHub, Bitbucket Cloud or Azure DevOps, or the merge request on GitLab (gitlab.com or self-managed). The connection's token needs write access to code and pull requests
- The GitHub path has been run against a real repository. The GitLab, Bitbucket and Azure DevOps paths are covered by tests of the requests they send and have not yet been run against the real services
- Every finding is tagged with the scanner that found it (`detected_by`: Checkov, Trivy, Semgrep, tfsec, Gitleaks, `guardnous-cspm`)

```
Finding → agent prepares the fix (file + diff)
       → run pauses → a second person approves the diff
       → branch → commit → pull request
```

Runs in **mock mode** by default, with no API key, for development. Mock mode answers from the same tools but cannot run agent tasks that need a model's judgement; connect an LLM for those.

### 🔄 VCS Integration & Webhook Scanning

| Provider | OAuth | Webhooks | PR Comments | Commit Status |
|----------|-------|----------|-------------|---------------|
| GitHub | ✅ | ✅ push + PR | ✅ | ✅ |
| GitLab | ✅ | ✅ push + MR | ✅ | ✅ |
| Bitbucket | ✅ | ✅ push + PR | ✅ | ✅ |
| Azure DevOps | ✅ | ✅ push + PR | ✅ | ✅ |

Webhook handlers trigger automatic scans on push/PR events, post findings as PR comments, and set commit status checks.

### ⏰ Scheduled / Recurring Scans & Report Delivery

**Scan Schedules:** Create cron-based or interval-based scan schedules via the `/scan-schedules` API. Celery Beat evaluates schedules and auto-triggers scans — ensuring continuous visibility without manual triggers.

**Report Schedules:** Schedule branded PDF reports to be generated and emailed automatically (daily, weekly, monthly). Recipients receive personalized emails with the report attached. On-demand reports can also be emailed instantly via the `/reports/email` endpoint.

**Email Delivery:** All emails use the GuardNous orange-branded HTML template, including:
- **Account verification** — JWT-signed verification links (24h expiry) sent on registration and invitation acceptance
- **Tenant creation** — Notification email sent to the admin who created the tenant
- Scan completion reports with severity breakdowns
- Scheduled report attachments (PDF)
- User invitation onboarding emails with one-click registration links

### 🔐 Two-Factor Authentication (TOTP)

Tenant-wide 2FA enforcement with TOTP (RFC 6238):
- **Admin toggle** — Enable/disable org-wide 2FA enforcement from Settings → Security
- **QR code setup** — Compatible with Google Authenticator, Authy, 1Password, and any TOTP app
- **Backup codes** — 10 one-time recovery codes generated during setup, hashed with bcrypt
- **3-way login flow** — Normal (no 2FA) → MFA challenge (if enabled) → MFA setup required (if org enforces but user hasn't configured)
- **Per-user control** — Users can optionally enable 2FA even if the org doesn't mandate it

### 📧 Email Verification

JWT-based email verification for all user accounts:
- **Auto-send on registration** — When a user registers or accepts an invitation, a verification email with a signed link is sent automatically
- **Tenant creation notification** — Admin receives a branded email when a new tenant is created
- **24-hour token expiry** — Verification links are JWT-signed with a `purpose: email_verify` claim
- **Resend endpoint** — Authenticated users can request a new verification email via `POST /auth/resend-verification`
- **Graceful degradation** — If SMTP is not configured, verification is skipped without blocking the user

### 🧙 First-Login Setup Wizard

Guided 5-step configuration wizard enforced for admins on first login:
1. **Platform Identity** — Set platform name and branding
2. **Date & Time** — Configure timezone and date format
3. **AI Provider** — Select and configure LLM provider (OpenAI, Anthropic, Ollama, etc.)
4. **Notifications** — Set notification preferences
5. **SMTP** — Configure email delivery (optional)

Once completed, `setup_completed` is marked `true` and the admin is never redirected again. Non-admin users bypass the wizard entirely.

### 🧠 Purely Agentic Architecture — Native Agent Framework

GuardNous is built on a **native agentic framework** — no LangChain, no CrewAI, no vendor dependencies. Every component is purpose-built for security operations with zero abstraction tax.

**20 Specialized AI Agents:**

The tool count is what each agent can actually call, including the five cloud inventory tools every agent gets. Counts come from the agent registry.

| # | Agent | Role | Tools |
|---|-------|------|-------|
| 1 | Security Copilot | General-purpose security assistant for any query | all (72 in chat, 71 in runs) |
| 2 | Security Analyst | Vulnerability assessment, risk analysis, posture evaluation | 17 |
| 3 | Compliance Advisor | Compliance mapping, gap analysis, audit preparation | 11 |
| 4 | DevSecOps Coach | Shift-left security, IaC fixes, CI/CD hardening | 15 |
| 5 | Threat Intelligence | Threat modeling, MITRE ATT&CK mapping, attack paths | 16 |
| 6 | Triage Agent | Reads the triage queue with its evidence and proposes one list of decisions for a person to approve | 15 |
| 7 | Remediation Agent | Fix generation, fix pull requests, cloud fixes | 13 |
| 8 | Investigation Agent | Deep-dive investigation across clouds and services | 34 |
| 9 | Incident Commander | Incident timeline, blast radius, containment, root cause | 13 |
| 10 | Cloud Security Architect | Cloud architecture and posture review | 19 |
| 11 | Vulnerability Manager | CVE lifecycle: prioritize, track, SLA, patch verification | 15 |
| 12 | Policy Engineer | Security policy creation, validation and enforcement | 12 |
| 13 | Secrets Detective | Leaked credentials, rotation audit, vault hygiene | 12 |
| 14 | Supply Chain Guardian | SCA, SBOM, dependency risk, typosquatting | 12 |
| 15 | Pentest Advisor | Attack simulation and exploitation-path guidance | 14 |
| 16 | SOC Analyst | Alert triage, correlation, false-positive tuning | 15 |
| 17 | Data Protection Officer | PII/PHI classification, data flows, privacy compliance | 12 |
| 18 | Security Cost Optimizer | Security cost analysis and waste detection | 11 |
| 19 | Executive Briefer | Board-ready summaries, risk narratives, trends | 12 |
| 20 | Automation Engineer | Webhooks, scheduled workflows, alert routing | 14 |

**72 tools.** 67 only read data. Five change something and run only inside an approved agent run: `triage_finding`, `triage_findings` (a reviewed list of decisions), `open_fix_pull_request`, `send_slack_message`, `remediate_cloud_finding`. Every agent also gets the cloud inventory tools (`cloud_inventory_summary`, `list_cloud_resources`, `get_cloud_resource`, `cloud_posture_summary`, `internet_exposure`), which read the synced cloud accounts.

**Agentic Primitives (all native, zero vendor lock-in):**

| Component | What It Does |
|-----------|-------------|
| **Agent Bus** (`bus.py`) | Async inter-agent messaging — point-to-point, broadcast, SSE drain for real-time UI |
| **Agent State Machine** (`agent_state.py`) | Redis-backed state tracking: `idle → thinking → tool_calling → delegating → complete` |
| **Supervisor** (`supervisor.py`) | Meta-agent that decomposes complex queries into multi-agent execution plans |
| **DAG Executor** (`executor.py`) | Dependency-aware parallel execution of agent tasks. Present in the code but not used by chat today: the supervisor runs plan steps one after another |
| **Planner** (`planner.py`) | Generates DAG execution plans with dependency edges between agent tasks |
| **Delegate** (`delegate.py`) | Structured agent-to-agent handoff with context transfer and depth tracking |
| **Cross-Turn Context** (`context.py`) | Persistent memory across conversation turns — agents remember prior interactions |
| **Audit Trail** (`audit.py`) | Every agent action logged: tool calls, inputs/outputs, duration, tokens, success/failure |
| **Run Runtime** (`runtime.py`) | Durable background runs: stored steps, risk class per tool, approvals, budgets, recovery after a worker dies |
| **Fix PRs** (`fix_pr.py`) | Prepares a code fix and its diff before approval; commits and opens the pull request after |
| **Cloud Tools** (`cloud_skills.py`) | Tools that answer from the synced cloud inventory and posture findings |
| **Chat Files** (`attachments.py`, `pdf_export.py`) | Text extraction from attached files; Markdown-to-PDF for downloads |

**How multi-agent orchestration works:**
```
User query
    │
    ▼
┌─────────────────┐     simple query      ┌──────────────┐
│   Orchestrator   │─────────────────────▶│ Single Agent  │──▶ Response
│                  │                       │ + Tools       │
│  Routing logic:  │     complex query     └──────────────┘
│  long message    │──────────────────┐
│  + "comprehensive"│                 ▼
│  + "compare"      │    ┌─────────────────┐
│  + "deep dive"    │    │   Supervisor     │
└─────────────────┘     │                  │
                        │ 1. Plan steps    │
                        │ 2. Order them    │
                        │ 3. Run in order  │
                        │ 4. Combine       │
                        └────────┬─────────┘
                                 │ hands each step to a specialist
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │ Agent A   │ │ Agent B   │ │ Agent C   │
              │ step 1    │ │ step 2    │ │ step 3    │
              └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
                    │             │              │
                    └─────────────┴──────────────┘
                                  │
                                  ▼
                          One combined answer
                          (output filter, then SSE)
```

What this does and does not do today:
- A multi-agent answer needs a long message (over 80 characters and 25 words) containing a phrase such as "comprehensive", "compare" or "deep dive", and a plan of at least two steps. Otherwise one agent answers.
- Steps run **one after another**, in dependency order. Each step is one model call by a specialist agent; the specialists do not call tools in this mode and do not hand work to each other. Only the supervisor hands out work.
- A question with an attached file, or one asking for a PDF, always goes to a single agent.

- **Prompt registry** — 13 built-in prompts for the background agents and the router. A row in `prompt_templates` replaces a built-in for one organization, with versions; there is no screen or API for editing them yet (see `PROMPTS.md`)
- **Enhanced guardrails** — 55 patterns: 25 injection blockers and 11 PII detectors on what the user types; 9 secret and 10 internal-path patterns on output
- **Agent audit trail** — Every execution logged with: agent used, tools called, input/output, duration, token usage, success/failure

### 🔐 Plugin Supply Chain Security

Scanner binaries are attack surface. GuardNous treats plugin versions as first-class security concerns:

- **Scanner integrity gate** — every external scanner binary is checked against a pinned SHA-256 immediately before each execution. The image records a read-only baseline at build time; a binary that no longer matches is not run, the scan log says why, and an installation administrator must approve the new binary (Plugins page) or rebuild the image. `PLUGIN_INTEGRITY_MODE` = `enforce` (default), `warn` or `off`. For pip-installed scanners (semgrep, checkov) the pinned file is the launcher script, not the Python packages behind it
- **Version Manager** — Multi-version binary cache
- **Health Monitor** — Autonomous Celery agent polls GitHub Advisory Database for CVEs affecting installed scanner versions (full check every 6h, integrity check every 1h)
- **Auto-Rollback** — If a scanner version is flagged as vulnerable, automatically rolls back to the last known-safe version
- **Admin Version Pinning** — Admins can pin, upgrade, or downgrade scanner versions from the Plugins page UI
- **Supply Chain Dashboard** — Real-time banner showing plugin health status, CVE alerts, and integrity verification results

### 🎨 Glassmorphic Agent UI

For answers produced by several agents, the chat shows what is happening, not just a chat bubble. These appear only for multi-agent answers (see the conditions above), in the light and the dark theme:

- **Plan Visualization** — the supervisor's plan as a layered graph: one card per step with the agent, its task and its state (waiting, running, done, failed), and arrows from each step to the steps that wait for it. It collapses to a one-line summary when the answer is complete
- **Handoff Visualization** — each handoff from the supervisor to a specialist agent, with the task that was handed over
- **Orchestration Header** — single or multi-agent mode, number of agents, progress
- **Agent Activity Panel** and **Agent Cards** — which agents took part, their state and how long each step took

The plan and handoffs are shown while the answer is produced and are not restored after a page reload. The model's reasoning is not streamed: answers contain only the answer.

### 🏢 Enterprise Multi-Tenancy & RBAC

- **3-level hierarchy: Tenant → Organization → User** with many-to-many user-org assignment
- **User-Organization junction table** — Users belong to a tenant and can be assigned to multiple organizations within it; switching orgs re-issues the JWT
- **Org switcher** — Sidebar dropdown for users with multiple org memberships; seamless context switching without re-login
- **Editable domain** — Domain auto-extracted from admin email during registration but fully editable; stored on the tenant record
- **Cross-tenant user assignment** — Superadmins can assign users across tenants; same email can exist in different tenants
- **Per-tenant email uniqueness** — `UNIQUE(email, tenant_id)` composite constraint; same email can register in different tenants but not within the same tenant
- **72 granular permissions** across 7 built-in roles (Platform Admin, Organization Admin, Team Admin, Security Engineer, DevOps Engineer, Auditor, Viewer)
- **RBAC-enforced agent access** — Roles can restrict which AI agents and tools users can invoke (`allowed_agents`, `allowed_tools` columns on the Role model)
- **Tenant isolation by row** — one database; every row carries its tenant and organization and every query is filtered by them. There is no separate database or schema per tenant
- **Settings are protected** — organization settings (e-mail server, AI provider and key, notifications) and the agents' knowledge base need `settings:*` / `agents:*` permissions; a signed-in user without them gets "permission denied"
- Audit logging for all state-changing operations
- **User invitation system** — Invite users via email with branded onboarding links; supports single and bulk (CSV) invitations
- **Email verification** — JWT-signed verification emails sent on registration and invitation acceptance
- **First-login setup wizard** — 5-step guided configuration for admins on first login
- **Repository management** — Admins can remove onboarded repositories from scanning via the Integrations page

> **📌 Gmail SMTP Note:** When using Gmail's SMTP server, Gmail overrides the `From` address with the authenticated account — this is Gmail's anti-spoofing policy. Use a transactional email service (SendGrid, Mailgun, AWS SES) or add the desired sender as a Gmail "Send mail as" alias for custom sender addresses.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      🖥️  FRONTEND — Next.js 14                          │
│   41 pages · TailwindCSS · shadcn/ui · Org Switcher · Light + Dark     │
│   Cloud Connectors · Cloud Posture · Agent Runs + Approvals            │
│   Streaming AI Chat with attachments · Real-time Logs · E2E Tests      │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ REST API + SSE (JWT + TOTP 2FA)
┌────────────────────────────────▼─────────────────────────────────────────┐
│                       ⚙️  BACKEND — FastAPI                              │
│                                                                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │
│  │ 🔐 Auth &    │ │ 🔌 Plugin    │ │ 📜 Policy    │ │ 🛡️ CVE Sync  │    │
│  │ Multi-Tenant │ │ Orchestrator │ │ Engine       │ │ NVD+GHSA     │    │
│  │ 72 perms     │ │ 9 adapters   │ │ 21 policies  │ │ +EPSS        │    │
│  │ 7 roles      │ │ parallel exec│ │ struct match │ │ daily sync   │    │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘    │
│                                                                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │
│  │ 📦 SBOM      │ │ 📋 Compliance│ │ 🔗 VCS       │ │ 📊 Risk      │    │
│  │ CycloneDX1.5 │ │ 6 frameworks │ │ GitHub,GitLab│ │ Scorer       │    │
│  │ 9 manifests  │ │ 92 controls  │ │ BB, AzDO     │ │ 0-100        │    │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘    │
│                                                                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │
│  │ Cloud        │ │ Cloud Posture│ │ Cloud Fixes  │ │ OIDC Issuer  │    │
│  │ Connectors   │ │ 44 AWS rules │ │ approval +   │ │ keyless AWS  │    │
│  │ AWS·Azure·GCP│ │ 19 CIS-mapped│ │ rollback     │ │ no stored key│    │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘    │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │          🤖 AGENTIC AI LAYER — Native Framework (Zero Deps)        │  │
│  │                                                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────┐   │  │
│  │  │                    SUPERVISOR                                │   │  │
│  │  │  Decomposes complex queries → plan → runs steps in order    │   │  │
│  │  └─────────────────────────┬───────────────────────────────────┘   │  │
│  │                            │                                       │  │
│  │  ┌─────────────┐ ┌────────▼────────┐ ┌─────────────────────────┐  │  │
│  │  │ PLANNER     │ │   EXECUTOR      │ │     AGENT BUS           │  │  │
│  │  │ DAG deps    │ │   Parallel DAG  │ │  Async messaging        │  │  │
│  │  │ strategy    │ │   scheduler     │ │  Broadcast + SSE drain  │  │  │
│  │  └─────────────┘ └─────────────────┘ └─────────────────────────┘  │  │
│  │                                                                    │  │
│  │  ┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐┌──────────┐  │  │
│  │  │Security││Triage  ││Remediat││Incident││Cloud   ││18 more   │  │  │
│  │  │Analyst ││Agent   ││Agent   ││Cmdr    ││Arch    ││agents... │  │  │
│  │  └────┬───┘└────┬───┘└────┬───┘└────┬───┘└────┬───┘└──────────┘  │  │
│  │       └─────────┴─────────┴─────────┴─────────┘                   │  │
│  │                    72 TOOLS                                        │  │
│  │  66 read-only · 4 that change something (approval required)       │  │
│  │                                                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────┐   │  │
│  │  │  AGENT RUNS · durable steps · risk class per tool · budgets │   │  │
│  │  │  write tool → exact change prepared → person approves → run │   │  │
│  │  └─────────────────────────────────────────────────────────────┘   │  │
│  │                                                                    │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐     │  │
│  │  │ Delegate   │ │ Audit Trail│ │ Guardrails │ │ Cross-Turn │     │  │
│  │  │ Handoff    │ │ Full trace │ │ 55 patterns│ │ Context    │     │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘     │  │
│  │                                                                    │  │
│  │  BYOM: OpenAI · Azure OpenAI · AI Foundry · Anthropic · Ollama     │  │
│  │  Chat: file attachments (PDF, Word, Excel, CSV) · PDF export       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │            🔐 PLUGIN SUPPLY CHAIN SECURITY                       │    │
│  │  Version Manager · SHA-256 Verification · CVE Health Monitor     │    │
│  │  Auto-Rollback · Admin Version Pinning · Integrity Checks (1h)  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└────────┬──────────────────────┬─────────────────────┬────────────────────┘
         │                      │                     │
┌────────▼──────────┐ ┌────────▼─────────┐ ┌────────▼──────────┐
│ 🐘 PostgreSQL 16  │ │ ⚡ Redis 7       │ │ ⏰ Celery         │
│ 40+ models        │ │ Cache + Broker   │ │ Worker + Beat     │
│ 33 migrations     │ │ Agent State      │ │ Scans, cloud sync │
│ Per-tenant isoln  │ │ Cross-turn ctx   │ │ Agent runs        │
│ Agent run steps   │ │ Audit trail      │ │ Reports, health   │
│ Cloud inventory   │ │ Agent Bus queues │ │ 6 background agts │
└───────────────────┘ └──────────────────┘ └───────────────────┘

        Outside GuardNous (reached only through the paths below)
┌───────────────────┐ ┌──────────────────┐ ┌───────────────────┐
│ Cloud accounts    │ │ Git providers    │ │ Your LLM provider │
│ AWS: short-lived  │ │ Scans, webhooks, │ │ Chat and agent    │
│ role via OIDC     │ │ PR comments,     │ │ runs; tool calls  │
│ Azure, GCP: SDK   │ │ fix PRs (4 VCS)  │ │ execute locally   │
└───────────────────┘ └──────────────────┘ └───────────────────┘
```

### How a cloud account is checked

```
 Cloud Connectors page                AWS account                     GuardNous
 ─────────────────────                ───────────                     ─────────
 1. enter account ID  ───────────────────────────────────────────▶  prepares role name + subject
 2. deploy the CloudFormation stack ─▶ creates OIDC provider
                                       + IAM role (SecurityAudit)
 3.                                    AssumeRoleWithWebIdentity ◀──  signs a short-lived token
                                       returns temporary creds   ──▶  (no key is stored)
 4.                                    read-only API calls       ◀──  sync: read configuration
 5.                                                                   check 44 rules
                                                                      open / resolve / reopen findings
```

### How an agent action is approved

```
 task ──▶ agent run (worker) ──▶ read tools run freely
                 │
                 │ the agent asks for a tool that changes something
                 ▼
        prepare the exact change  ──▶ cannot be prepared: error step, nobody is asked
                 │                     (diff, Slack text, cloud plan from live state)
                 ▼
          run pauses: awaiting approval
                 │
      ┌──────────┴───────────┐
      ▼                      ▼
   approved               rejected
   by an allowed person   the agent is told; nothing runs
      │
      ▼
   the stored, approved change is executed (not new model output)
      │
      ▼
   result recorded as a step ──▶ run continues ──▶ completed
```

### Multi-Tenancy Data Model

```
┌──────────────────────────────────────────────────────────────────┐
│                        TENANT                                     │
│  (Company-level isolation: name, domain, plan, settings)         │
│                                                                   │
│  ┌─────────────────┐   ┌─────────────────┐   ┌───────────────┐  │
│  │  Organization A  │   │  Organization B  │   │  Org C ...    │  │
│  │  (team/division) │   │  (team/division) │   │               │  │
│  └────────┬─────────┘   └────────┬─────────┘   └───────────────┘  │
│           │                      │                                 │
│  ┌────────┴──────────────────────┴─────────┐                      │
│  │         user_organizations               │                      │
│  │    (many-to-many junction table)         │                      │
│  │    user_id · org_id · role_in_org        │                      │
│  └────────┬─────────────────────────────────┘                      │
│           │                                                        │
│  ┌────────┴─────────────────────────────────┐                      │
│  │              USERS                        │                      │
│  │  UNIQUE(email, tenant_id)                 │                      │
│  │  Same email OK across tenants             │                      │
│  │  User switches orgs via sidebar dropdown  │                      │
│  └───────────────────────────────────────────┘                      │
└──────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, React 18, TypeScript, TailwindCSS, shadcn/ui, Recharts, react-markdown, 41 pages, light and dark theme |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Pydantic v2, Celery 5.3 |
| Database | PostgreSQL 16 (50+ models, 33 migrations, rows isolated by tenant and organization) |
| Cache / Broker | Redis 7 (cache, Celery broker, agent state machine, cross-turn context, audit trail, agent bus queues) |
| Auth | JWT (python-jose + bcrypt), TOTP 2FA (pyotp + qrcode), JWT email verification, password reset tokens, Fernet encryption for VCS tokens |
| AI / Agents | **Native agentic framework** (20 agents, 72 tools, durable runs with approvals, supervisor, DAG executor, agent bus, delegate protocol) — zero vendor dependencies |
| Cloud | AWS posture rules and fixes (boto3), keyless connection through a built-in OIDC issuer; Azure and Google Cloud inventory |
| LLM Providers | OpenAI, Azure OpenAI, Azure Foundry (Anthropic via Azure), Anthropic native, Ollama (local), Mock (no API key needed) |
| Plugin Security | Version manager (SHA-256), health monitor (GitHub Advisory API), auto-rollback, admin version pinning |
| Reporting | reportlab (branded PDF), SMTP email delivery with HTML templates |
| Containerization | Docker Compose (6 services); Helm 3 chart in preview |

---

## ☸️ Production Deployment

### Helm Chart (preview)

Kubernetes support is planned for a future release; the chart is included now so it can be tried and reviewed. The `helm/guardnous/` chart is written to deploy all components:

| Component | K8s Resource | Autoscaling |
|---|---|---|
| API Server | Deployment | HPA 3–10 replicas |
| Web Frontend | Deployment | HPA 2–8 replicas |
| Celery Workers | Deployment | HPA 3–15 replicas |
| Celery Beat | Deployment | 1 replica (leader) |

### Bring Your Own Database

GuardNous does **not** force you to run PostgreSQL or Redis inside the cluster. The setup wizard and Helm values support external endpoints:

```yaml
# values-production.yaml
database:
  externalUrl: "postgresql://user:pass@your-rds-host:5432/guardnous?sslmode=require"
redis:
  externalUrl: "redis://your-elasticache-host:6379"
secrets:
  secretKey: "<openssl rand -hex 32>"
  encryptionKey: "<openssl rand -base64 32 | tr '+/' '-_'>"
ingress:
  host: guardnous.example.com
```

The chart derives the async and sync database URLs and the Celery broker and result URLs from these two addresses, and refuses to render if the database, Redis or either key is missing. Schema migrations run once, in an init container of the API pod, under a database lock. The web image has the API address compiled in, so build it with `--api-url`. The chart has not yet been tested on a cluster.

### CI-Agnostic Build & Deploy

We don't lock you into GitHub Actions or any CI system. The scripts work anywhere:

| Script | What It Does |
|--------|--------------|
| `scripts/build-images.sh` | Builds API + Web container images, tags, pushes to any registry |
| `scripts/deploy.sh` | Validates config, runs `helm upgrade --install`, fails fast on missing values |
| `scripts/setup-k8s.sh` | Interactive wizard — generates `values-generated.yaml` from your answers |

---

## 🔌 Plugin Ecosystem

### Adding a New Scanner

Put one Python file in `backend/app/services/plugins/adapters/` and restart the API and the workers. Every concrete `PluginAdapter` subclass defined in that file is registered, and it is enabled if its `health()` reports it available. A file that fails to load is skipped, the other scanners keep working, and the failure is shown on the Plugins page.

An adapter implements three methods. This one is complete and works as written:

```python
"""Flags plain-HTTP URLs in Terraform files."""
from __future__ import annotations

import re
from typing import Any

from app.services.plugins.base import PluginAdapter, PluginCapability, PluginHealth, PluginMetadata
from app.services.scanners.base import ScanResult

_HTTP_URL = re.compile(r"http://[^\s\"']+")


class PlainHttpAdapter(PluginAdapter):
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="plain_http",                 # unique id
            display_name="Plain HTTP URLs",
            version="1.0.0",
            description="Reports URLs that use http:// instead of https://.",
            homepage="https://example.com/plain-http",
            icon="Link",                       # lucide-react icon name
            capabilities=[PluginCapability.IAC_TERRAFORM],
            is_native=True,                    # runs in-process
            default_config={"severity": "MEDIUM"},
        )

    def health(self) -> PluginHealth:
        return PluginHealth(available=True, version="1.0.0")

    def scan(self, content: str, file_name: str = "", config: dict[str, Any] | None = None) -> list[ScanResult]:
        cfg = {**self.metadata().default_config, **(config or {})}
        results = []
        for number, line in enumerate(content.splitlines(), start=1):
            for url in _HTTP_URL.findall(line):
                results.append(ScanResult(
                    rule_id="PLAIN-HTTP-001",
                    title="Unencrypted HTTP URL",
                    description=f"{url} is fetched without TLS.",
                    severity=cfg["severity"],  # CRITICAL, HIGH, MEDIUM, LOW or INFO
                    category="iac",
                    file_path=file_name,
                    line_number=number,
                    code_snippet=line.strip(),
                    remediation="Use https://.",
                    metadata={"source": "plain_http"},
                ))
        return results
```

For a command-line tool, set `_binary = "<tool>"` on the class and `requires_binary=True` in the metadata, and have `health()` return `PluginHealth(available=False, message=...)` when `shutil.which` does not find it. The binary integrity check then applies to it as it does to the shipped scanners.

An adapter is code that runs inside the API and the workers, with their access. Only the packaged adapters directory is searched and that cannot be changed by a setting. Review an adapter as you would review any code you deploy.

### Scanner Trust Model

All 5 external adapters shell out to **real CLI binaries** installed on the host or container. We parse their structured output (JSON/SARIF) — we don't re-implement their detection logic. If you trust Checkov and Trivy individually, you can trust GuardNous's output from them.

---

## 📥 Universal SARIF Import

GuardNous accepts **SARIF v2.1.0** (Static Analysis Results Interchange Format) — the industry standard output from 100+ security tools. Import results from any scanner without writing a custom adapter.

### Supported Scanners (via SARIF)

Any tool that produces SARIF v2.1.0, including: **SonarQube**, **CodeQL**, **ESLint**, **Bandit**, **Gosec**, **Grype**, **KICS**, **Terrascan**, **Prowler**, **ScoutSuite**, **Snyk CLI**, **Fortify**, **Veracode**, **Checkmarx**, **Anchore**, and more.

### Import API

```bash
# JSON body
curl -X POST http://localhost:7002/api/v1/imports/sarif \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sarif_data": <sarif-json>, "scan_name": "SonarQube weekly"}'

# File upload
curl -X POST http://localhost:7002/api/v1/imports/sarif/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@results.sarif" -F "scan_name=CodeQL nightly"

# List imports
curl http://localhost:7002/api/v1/imports/ -H "Authorization: Bearer $TOKEN"

# Supported formats
curl http://localhost:7002/api/v1/imports/formats
```

### What Happens on Import

1. **Parse** — Multi-run SARIF is flattened; each result becomes a finding
2. **Normalize severity** — 5-layer resolution: custom properties → CVSS score → level → rule config → fallback
3. **Attribute scanner** — Each finding is tagged with the originating tool name
4. **Extract CVEs** — Pulled from rule IDs, properties, and tags
5. **Infer category & cloud** — Keyword matching against rule metadata for automatic classification
6. **Deduplicate** — SARIF fingerprints are preserved; identical re-imports are idempotent
7. **Apply policies** — Imported findings run through the policy-as-code engine like any native scan

---

## 📡 API Reference

Full interactive docs at `/docs` (Swagger) and `/redoc` when the server is running.

### Key Endpoints

| Method | Endpoint | Description |
|---|---|---|
| **Auth & 2FA** | | |
| `POST` | `/api/v1/auth/login` | JWT token (form data: `username` + `password`); returns MFA challenge if 2FA enabled |
| `POST` | `/api/v1/auth/register` | Register user + org |
| `POST` | `/api/v1/auth/2fa/setup` | Generate TOTP secret + QR code URI |
| `POST` | `/api/v1/auth/2fa/confirm` | Verify TOTP code and enable 2FA |
| `POST` | `/api/v1/auth/verify-2fa` | Verify TOTP code during MFA login challenge |
| `POST` | `/api/v1/auth/2fa/disable` | Disable 2FA for the current user |
| `GET` | `/api/v1/auth/2fa/backup-codes` | Retrieve backup recovery codes |
| **Email Verification** | | |
| `GET` | `/api/v1/auth/verify-email?token=` | Verify email address via JWT token |
| `POST` | `/api/v1/auth/resend-verification` | Resend verification email (authenticated) |
| **Setup Wizard** | | |
| `GET` | `/api/v1/settings/setup-status` | Check if first-login setup is completed |
| `POST` | `/api/v1/settings/complete-setup` | Complete the 5-step setup wizard |
| **Dashboard** | | |
| `GET` | `/api/v1/dashboard/summary` | Dashboard statistics and risk score |
| **Scans & Findings** | | |
| `POST` | `/api/v1/scans/` | Trigger scan |
| `GET` | `/api/v1/findings` | List findings (filter by severity, status, assignee) |
| `POST` | `/api/v1/findings/bulk-update` | Bulk triage (up to 500) |
| `POST` | `/api/v1/findings/{id}/triage` | Set status + reason |
| `POST` | `/api/v1/findings/{id}/notes` | Add investigation note |
| **Scan Schedules** | | |
| `GET` | `/api/v1/scan-schedules` | List scan schedules |
| `POST` | `/api/v1/scan-schedules` | Create a scan schedule (cron or interval) |
| `PUT` | `/api/v1/scan-schedules/{id}` | Update a scan schedule |
| `DELETE` | `/api/v1/scan-schedules/{id}` | Delete a scan schedule |
| **Reports & Email** | | |
| `GET` | `/api/v1/reports` | List reports |
| `POST` | `/api/v1/reports/{id}/email` | Email a branded PDF report to specified recipients |
| **Report Schedules** | | |
| `GET` | `/api/v1/report-schedules` | List report schedules |
| `POST` | `/api/v1/report-schedules` | Create a scheduled report (cron-based email delivery) |
| `PUT` | `/api/v1/report-schedules/{id}` | Update a report schedule |
| `DELETE` | `/api/v1/report-schedules/{id}` | Delete a report schedule |
| **CVEs & Compliance** | | |
| `GET` | `/api/v1/cves` | Search CVE database |
| `GET` | `/api/v1/governance/frameworks` | List compliance frameworks |
| `GET` | `/api/v1/governance/frameworks/{id}/controls` | Controls of one framework |
| `POST` | `/api/v1/governance/evaluate` | Evaluate compliance |
| **Integrations** | | |
| `POST` | `/api/v1/integrations/connect` | Connect GitHub, GitLab, Bitbucket or Azure DevOps with a token |
| `POST` | `/api/v1/webhooks/github/{org_id}` (also `gitlab`, `bitbucket`, `azure-devops`) | Webhook receiver (auto-scan). Signed with the organization's secret from `GET /api/v1/integrations/webhook-config`; unsigned requests are rejected |
| **SARIF Import** | | |
| `POST` | `/api/v1/imports/sarif` | Import SARIF JSON |
| `POST` | `/api/v1/imports/sarif/upload` | Import SARIF file upload |
| `GET` | `/api/v1/imports/` | List imports |
| `GET` | `/api/v1/imports/formats` | Supported import formats |
| **AI Copilot** | | |
| `POST` | `/api/v1/agents/chat` | AI Copilot (streaming SSE — single or multi-agent) |
| `POST` | `/api/v1/agents/autofix` | Generate code fix for a finding |
| `POST` | `/api/v1/agents/auto-triage` | AI-powered triage with confidence scores |
| `GET` | `/api/v1/agents/knowledge/stats` | Fix pattern knowledge store statistics |
| `GET` | `/api/v1/agents/manifest` | Full agent manifest (20 agents, 72 tools, capabilities) |
| **AI Copilot Chat** | | |
| `POST` | `/api/v1/agents/chat/stream` | Send a message (optional `attachment_ids`); the reply streams as server-sent events |
| `POST` | `/api/v1/agents/chat/files` | Attach a file to the next message (multipart); returns its id |
| `GET` | `/api/v1/agents/chat/files/{id}/download` | Download a file the assistant produced |
| `GET` | `/api/v1/agents/messages/{id}/pdf` | Any answer as a PDF |
| **Agent Runs & Approvals** | | |
| `POST` | `/api/v1/agents/runs` | Start a background agent task |
| `GET` | `/api/v1/agents/runs` · `/runs/{id}` | List runs; one run with its steps |
| `POST` | `/api/v1/agents/runs/{id}/cancel` | Cancel a run |
| `GET` | `/api/v1/agents/approvals` | Actions waiting for a decision |
| `POST` | `/api/v1/agents/approvals/{id}/decision` | Approve or reject an action |
| `GET` | `/api/v1/agents/usage` | Token usage of agent runs |
| **Cloud Accounts & Posture** | | |
| `POST` | `/api/v1/cloud-accounts/aws/federated` | Start a keyless AWS connection for an account ID |
| `GET` | `/api/v1/cloud-accounts/{id}/aws-template` | CloudFormation template for that connection |
| `GET` | `/api/v1/cloud-posture` | Posture of all accounts, or one with `?account_id=` |
| `POST` | `/api/v1/cloud-posture/evaluate` | Run the rules again on already synced data |
| `POST` | `/api/v1/cloud-posture/changes/{id}/rollback` | Undo a change GuardNous made in the cloud |
| `GET` | `/.well-known/openid-configuration` · `/.well-known/jwks.json` | Public OIDC discovery and signing keys (no auth) |
| **Agent Audit** | | |
| `GET` | `/api/v1/agent-audit/recent` | Recent agent executions with tool traces |
| `GET` | `/api/v1/agent-audit/conversation/{id}` | Audit entries for one conversation |
| **Plugin Version Management** | | |
| `GET` | `/api/v1/plugins/{name}/versions` | List available versions for a plugin |
| `POST` | `/api/v1/plugins/{name}/versions/install` | Install a specific plugin version |
| `POST` | `/api/v1/plugins/{name}/versions/activate` | Make an installed version the active one |
| `GET` / `PUT` | `/api/v1/plugins/{name}/versions/policy` | Read or set the version policy (pin or follow updates) |
| `POST` | `/api/v1/plugins/{name}/versions/rollback` | Roll back to the previous version |
| `GET` | `/api/v1/plugins/{name}/health` | Health of one plugin |
| `GET` | `/api/v1/plugins/supply-chain/health` | Supply chain overview for all plugins (CVEs, integrity, last check) |
| `GET` | `/api/v1/plugins/integrity` | Recorded checksums of scanner binaries |
| **Password Reset** | | |
| `POST` | `/api/v1/auth/forgot-password` | Send password reset email |
| `POST` | `/api/v1/auth/reset-password` | Reset password with token |
| **Organization Management** | | |
| `POST` | `/api/v1/org/switch/{org_id}` | Switch active organization (re-issues JWT) |
| `GET` | `/api/v1/org/users/search?q=` | Search users within tenant |
| `POST` | `/api/v1/org/assign-user` | Assign user to an organization |
| `DELETE` | `/api/v1/org/remove-user` | Remove user from an organization |
| `GET` | `/api/v1/org/user-memberships/{id}` | List user's org memberships |
| **Integrations** | | |
| `DELETE` | `/api/v1/integrations/repos/{full_name}` | Remove onboarded repository from scanning |
| **Admin** | | |
| `POST` | `/api/v1/users/invite` | Invite user (auto-sends branded email) |
| `POST` | `/api/v1/users/invite/bulk` | Bulk invite users |
| `POST` | `/api/v1/users/invite/csv` | Bulk invite from CSV upload |

---

## ⚙️ Configuration

All config via environment variables. See [`.env.example`](.env.example) for the full list (80+ vars).

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | JWT signing — `openssl rand -hex 32` |
| `ENCRYPTION_KEY` | Yes | Key that encrypts stored credentials (repository tokens, cloud credentials, model API keys) — `openssl rand -base64 32 \| tr '+/' '-_'` |
| `INITIAL_ADMIN_PASSWORD` | No | Password given to `admin@guardnous.com` when that account is first created (`GUARDNOUS_SEED_ADMIN=true`). `scripts/setup.sh` generates one. If empty, a random one is generated and written once to the API log. Never applied to an existing account |
| `SLA_DAYS_CRITICAL`, `_HIGH`, `_MEDIUM`, `_LOW`, `_INFO` | No | Days allowed to fix a finding, by severity. Defaults 7, 30, 90, 180, 0 (0 = no deadline) |
| `DEPENDENCY_LICENSE_LOOKUP` | No | `false` (default). `true` looks up dependency licences at deps.dev for SBOMs; this sends dependency names and versions to that public service |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `LLM_PROVIDER` | No | `mock` (default), `openai`, `azure`, `azure_foundry`, `anthropic`, `ollama`. Each organization can also set its own in the UI |
| `OIDC_ISSUER_URL` | For keyless AWS | Public HTTPS address of this installation. AWS fetches the signing keys from it |
| `AWS_ONBOARDING_TEMPLATE_URL` | No | S3 URL of the hosted onboarding template; enables a one-click "Launch stack" link |
| `AGENT_AUTO_TRIAGE_AFTER_SCAN` | No | `false` (default). `true` starts a Triage Agent run after every repository scan or cloud assessment that leaves open findings. The run belongs to nobody: it can only propose triage decisions, and someone with `agents:manage` approves the list. One such run per organization is open at a time. Each run uses your LLM provider |
| `AGENT_ALLOW_SELF_APPROVAL` | No | `false` (default). `true` lets a requester approve their own external actions; for single-user test installations only |
| `AGENT_RUN_MAX_STEPS` | No | Model calls an agent run may make before it must conclude (default `12`) |
| `RATE_LIMIT_ENABLED` | No | `true` (default). The limiter is per process; put a shared limiter in front for multi-worker deployments |
| `TRUSTED_PROXY_COUNT` | No | Number of reverse proxies in front of the API (default `0`); controls how `X-Forwarded-For` is trusted |
| `DEMO_DATA_ENABLED` | No | `false` (default). When `true`, sample cloud resources and simulated connector data are allowed — never enable in production |

Cloud account sync and IAM posture need the cloud SDKs in
[`backend/requirements-cloud.txt`](backend/requirements-cloud.txt) (installed by the
backend Docker image). Without them, connecting an account returns an error.
| `GITHUB_CLIENT_ID` | No | GitHub OAuth app |
| `GITLAB_CLIENT_ID` | No | GitLab OAuth app |

---

## 🛠️ Development

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

## 📁 Project Structure

```
guardnous/
├── backend/
│   ├── app/
│   │   ├── api/v1/              # 35 REST endpoint modules (auth, 2FA, scans, findings, agents,
│   │   │                        #   scan-schedules, agent-audit, report-schedules, reports,
│   │   │                        #   org-management, plugins, governance, etc.)
│   │   ├── core/                # Config, security (JWT + TOTP 2FA + email verification + password reset),
│   │   │                        #   RBAC, email, encryption, logging, tenant isolation
│   │   ├── models/              # 40+ SQLAlchemy models (incl. AgentAuditEntry, ScanSchedule,
│   │   │                        #   ReportSchedule, UserInvitation, UserOrganization, Organization, KG models)
│   │   ├── schemas/             # Pydantic request/response schemas (incl. plugin version management)
│   │   ├── services/
│   │   │   ├── plugins/         # Plugin registry + 9 adapters
│   │   │   │   ├── adapters/    #   Semgrep, Trivy, Checkov, tfsec, Gitleaks + 4 native
│   │   │   │   ├── version_manager.py  # Multi-version binary cache, SHA-256 verification
│   │   │   │   └── health_monitor.py   # Autonomous CVE checker (GitHub Advisory API)
│   │   │   ├── security/        # Policy engine, compliance mapper, dependency analyzer
│   │   │   ├── scanners/        # Native IaC scanners (TF, CF, Bicep)
│   │   │   ├── vcs/             # VCS integrations + PR commenting
│   │   │   ├── agents/          # 🤖 NATIVE AGENTIC FRAMEWORK
│   │   │   │   ├── orchestrator.py     # Primary execution engine (single + supervised routing)
│   │   │   │   ├── supervisor.py       # Plans steps, runs them in order, combines the answer
│   │   │   │   ├── executor.py         # DAG-aware parallel scheduler (not used by chat yet)
│   │   │   │   ├── planner.py          # DAG plan generation with dependency edges
│   │   │   │   ├── bus.py              # Inter-agent async messaging + SSE drain
│   │   │   │   ├── agent_state.py      # Redis-backed agent state machine
│   │   │   │   ├── delegate.py         # Structured agent-to-agent handoff
│   │   │   │   ├── context.py          # Cross-turn persistent memory
│   │   │   │   ├── audit.py            # Full execution audit trail (Redis-backed)
│   │   │   │   ├── registry.py         # 20 agent definitions + system prompts
│   │   │   │   ├── runtime.py          # Durable agent runs, approvals, budgets
│   │   │   │   ├── fix_pr.py           # Fix pull requests (diff before approval)
│   │   │   │   ├── cloud_skills.py     # Tools on the synced cloud inventory
│   │   │   │   ├── attachments.py      # Text extraction from files attached in chat
│   │   │   │   ├── pdf_export.py       # Markdown → PDF for chat downloads
│   │   │   │   ├── tools.py            # 72 tool schemas, risk class and permission per tool
│   │   │   │   ├── expanded_skills.py  # Skill executor functions  
│   │   │   │   ├── autonomous.py       # 5 scheduled background agents
│   │   │   │   ├── prompts.py          # AEGIS persona + prompt registry
│   │   │   │   ├── guardrails.py       # 55 patterns (PII, injection, output)
│   │   │   │   ├── llm.py             # Multi-provider LLM client (BYOM)
│   │   │   │   └── ...                 # autofix, triage, knowledge, PR creator
│   │   │   ├── cloud_connectors/ # AWS, Azure, GCP resource discovery
│   │   │   ├── cloud_posture/   # 44 AWS rules, evaluation engine, fixes with rollback
│   │   │   ├── federation/      # OIDC issuer + keyless AWS connection (CloudFormation template)
│   │   │   └── cve/             # CVE sync (NVD + GHSA + EPSS)
│   │   └── tasks/               # Celery jobs (scans, cloud sync, agent runs, CVE sync, reports, health monitor)
│   ├── alembic/                 # 33 database migrations, applied at startup
│   └── tests/                   # 52 test files, 560+ tests (AWS calls checked against botocore's API models)
├── frontend/
│   ├── src/app/                 # Next.js 14 (41 pages, light and dark theme)
│   ├── src/components/
│   │   └── agents/              # Multi-agent chat components
│   │       ├── OrchestrationHeader.tsx  # Mode indicator + progress bar
│   │       ├── PlanVisualization.tsx    # The plan as a graph of steps
│   │       ├── HandoffVisualization.tsx # Supervisor-to-agent handoffs
│   │       ├── AgentActivityPanel.tsx   # Agent status panel
│   │       ├── AgentCard.tsx            # Agent status card
│   │       └── GlassmorphicCard.tsx     # Reusable card component
│   └── src/lib/                 # API client, auth context, utilities
├── e2e/                         # Playwright end-to-end tests (14 suites, about 200 tests)
├── helm/guardnous/              # Helm chart, preview (not yet tested on a cluster)
├── scripts/                     # Setup, build, deploy, health check
├── docker-compose.yml           # 6 services (api, web, postgres, redis, celery-worker, celery-beat)
└── .env.example                 # All config documented (80+ vars)
```

---

## 🗺️ Roadmap

| Milestone | Status |
|---|---|
| **Core Security** | |
| IaC Scanning (TF, CF, Bicep — 40+ native rules) | ✅ |
| Plugin System (Checkov, Trivy, Semgrep, tfsec, Gitleaks) | ✅ |
| Secrets Detection (18 native patterns, plus Gitleaks) | ✅ |
| CVE Database (NVD + GHSA + EPSS daily sync) | ✅ |
| Policy-as-Code Engine (21 policies, structured matching) | ✅ |
| Findings Triage Workflow (status, notes, bulk ops, SLA) | ✅ |
| SBOM Export (CycloneDX 1.5) | ✅ |
| Governance & Compliance (6 frameworks, 92 controls) | ✅ |
| Risk Scoring (0–100; rises in a straight line to 50, then with the logarithm of the backlog, so fixing findings always moves it) | ✅ |
| Scanner Attribution (findings tagged with source scanner) | ✅ |
| Universal SARIF Import (100+ scanners) | ✅ |
| **Cloud Posture** | |
| AWS posture rules (44 rules, 19 mapped to CIS AWS Foundations v1.4.0) | ✅ |
| Keyless AWS connection (OIDC federation + CloudFormation stack) | ✅ |
| Cloud fixes with second-person approval and rollback (5 AWS fixes) | ✅ |
| Per-account posture pages, internet exposure view | ✅ |
| Azure and Google Cloud: connect and inventory | ✅ |
| Azure and Google Cloud posture rules | 🔜 Planned |
| All-region AWS scanning by default | 🔜 Planned |
| **Agentic AI** | |
| Native Agent Framework (20 agents, 72 tools — zero vendor deps) | ✅ |
| Triage that lasts: decisions kept across rescans, a triage queue with evidence, one approval for a reviewed list of decisions | ✅ |
| Agent Runs (durable background tasks, stored steps, token budgets) | ✅ |
| Human approval for every agent action (exact change shown) | ✅ |
| Fix pull requests with diff preview (GitHub, GitLab, Bitbucket Cloud, Azure DevOps) | ✅ |
| Chat attachments: images and scanned PDFs (text read with OCR), secrets hidden on upload | ✅ |
| AWS posture across every enabled region, regions read in parallel | ✅ |
| Slack messages from agents (approved text) | ✅ |
| Chat attachments (PDF, Word, Excel, CSV, JSON, text) and PDF export | ✅ |
| AI Security Copilot (BYOM — OpenAI, Anthropic, Azure, Ollama) | ✅ |
| AI Agentic Triage (3-layer: heuristic + FP detection + LLM) | ✅ |
| AI code fixes (real patches, not markdown advice) | ✅ |
| Multi-Agent Supervisor (plans steps, runs them in order, combines the answer) | ✅ |
| Inter-Agent Communication Bus (async messaging, broadcast, SSE) | ✅ |
| Parallel execution of plan steps (executor exists, chat runs steps in order) | 🔜 Planned |
| SBOM stored per assessment, optional licence checks (deps.dev) | ✅ |
| Remediation SLA deadlines by severity, overdue filter and summary | ✅ |
| Plan and handoff views in chat for multi-agent answers | ✅ |
| Agent State Machine (Redis-backed: idle → thinking → complete) | ✅ |
| Cross-Turn Context (persistent memory across conversations) | ✅ |
| Multi-Agent Delegation Protocol (structured handoff, depth-tracked) | ✅ |
| Prompt Registry (13 built-in, per-org customizable) | ✅ |
| Enhanced AI Guardrails (55 patterns: PII, injection, output) | ✅ |
| Agent Audit Trail (full execution logging with tool traces) | ✅ |
| Knowledge Store (fix pattern learning + reuse) | ✅ |
| Glassmorphic Agent UI (orchestration header, plan viz, thinking stream) | ✅ |
| 6 Autonomous Background Agents (Celery-based, always-on) | ✅ |
| **Plugin Supply Chain Security** | |
| Plugin Version Manager (multi-version binary cache) | ✅ |
| SHA-256 scanner integrity check before every scan | ✅ |
| Scan and report schedules (`/schedules`) | ✅ |
| Plugin Health Monitor (GitHub Advisory API CVE checks) | ✅ |
| Auto-Rollback to Last Safe Version | ✅ |
| Admin Version Pinning UI | ✅ |
| Supply Chain Security Dashboard | ✅ |
| **Enterprise** | |
| Multi-Tenant RBAC (72 permissions, 7 roles, agent access control) | ✅ |
| Multi-Org User Assignment (junction table, org switcher, cross-tenant) | ✅ |
| Editable Domain Registration (auto-fill + manual override) | ✅ |
| Repository Management (admin delete/remove onboarded repos) | ✅ |
| VCS Integration (GitHub, GitLab, Bitbucket, Azure DevOps) | ✅ |
| Webhook-Triggered Scanning + PR Comments | ✅ |
| Scheduled / Recurring Scans (cron-based + interval) | ✅ |
| Scheduled Report Delivery (PDF email, cron-based) | ✅ |
| Branded PDF Reports + Email Delivery | ✅ |
| Two-Factor Authentication (TOTP with QR + backup codes) | ✅ |
| Password Reset Flow (email-based, JWT token) | ✅ |
| User Invitation System (auto-send branded emails) | ✅ |
| Email Verification (JWT-signed, 24h expiry) | ✅ |
| First-Login Setup Wizard (5-step guided config) | ✅ |
| Tenant Creation Notification Email | ✅ |
| Multi-Tenant Email Isolation (per-tenant uniqueness, cross-tenant OK) | ✅ |
| Kubernetes Deployment with Helm (chart included as a preview; supported once tested on a cluster) | 🔜 Planned |
| Policies Admin Page (view, toggle, search security policies) | ✅ |
| Knowledge Base (20 curated security articles) | ✅ |
| **Coming Next** | |
| Kubernetes Manifest Scanning | 🔜 Next |
| Cloud posture rules for Azure and GCP (accounts connect today; rules exist for AWS only) | 🔜 Planned |
| Teams notification channel | 🔜 Planned |
| Editing prompt templates from the UI or API | 🔜 Planned |
| Scored evaluation of the Triage Agent (`make eval-triage`, results in `docs/evals/triage.md`) | ✅ |
| Automatic triage run after an assessment (`AGENT_AUTO_TRIAGE_AFTER_SCAN`, proposals only) | ✅ |
| Evaluations for the other agents | 🔜 Planned |
| LDAP / SAML SSO | 🔜 Planned |
| Knowledge Graph Visualization | 🔜 Planned |
| Agent Marketplace (community-contributed agents + tools) | 🔜 Planned |
| Agent triggers from outside events (webhooks) | 🔜 Planned |

---

## 📝 License

[Apache License 2.0](LICENSE) — free for personal and commercial use, with a patent grant from every contributor. By contributing you agree your contribution is licensed under the same terms.

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and PR process.

**Quick wins:**
- Add a new scanner adapter (implement `PluginAdapter`, drop in `adapters/`)
- Add compliance controls to existing frameworks
- Improve native scanner rules
- Write tests

---

<div align="center">

**GuardNous — Code Scanning, Cloud Posture and Approval-Gated AI Agents**

20 AI Agents · 72 Tools · 44 AWS Posture Rules · Keyless AWS · Native Framework (Zero Vendor Deps) · Multi-Tenant · Self-hosted · Apache 2.0 Licensed

[Report Bug](https://github.com/guardnous/guardnous/issues) · [Request Feature](https://github.com/guardnous/guardnous/issues) · [Discussions](https://github.com/guardnous/guardnous/discussions) · [Website](https://guardnous.github.io)

</div>

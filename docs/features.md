# Features

[← Back to the README](../README.md)

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

- **Prompt registry** — 13 built-in prompts for the background agents and the router. A row in `prompt_templates` replaces a built-in for one organization, with versions; there is no screen or API for editing them yet (see [`PROMPTS.md`](../PROMPTS.md))
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


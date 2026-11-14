# Changelog

All notable changes to GuardNous are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) + [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Removed
- The `k8s/` manifests and the `setup/` scripts. Both were out of date and could not start the product (no encryption key, no migrations). Use `scripts/setup.sh` for Docker Compose. Kubernetes support with the Helm chart is planned for a future release; the chart is included as a preview.

### Security
- **Organization settings need permission.** Changing organization settings, the e-mail server, the AI provider and its key, or notification settings now needs `settings:update`; reading the e-mail and notification settings needs `settings:read`; finishing setup needs `settings:manage`. Before, any signed-in user could do all of these.
- **Knowledge base needs permission.** Reading needs `agents:read`, writing `agents:update`, deleting and seeding `agents:manage`.
- **No default administrator password.** The first administrator gets `INITIAL_ADMIN_PASSWORD`, or a random password written once to the API log. The old fixed password is removed from the code, scripts and tests.
- Revoking invitations, listing a user's memberships, searching users, creating a CI API key and reading scan logs now check permissions.
- Streamed chat answers, including answers combined from several agents, pass the output filter (secrets, internal paths) before they are sent.

### Added
- **SBOM per assessment.** A full repository assessment stores its declared dependencies; `GET /api/v1/sbom/scans/{id}` and the assessment page export CycloneDX 1.5 with known vulnerabilities. Optional licence lookup at deps.dev (`DEPENDENCY_LICENSE_LOOKUP`, off by default) flags copyleft and restrictive licences. Direct dependencies only; no SPDX.
- **Remediation deadlines.** Each finding gets a deadline from its severity (`SLA_DAYS_*`), counted from when it was first seen and kept across rescans. Findings can be filtered and sorted by it; `GET /api/v1/findings/sla/summary` and the dashboard show overdue counts. No breach notifications.
- **Scanner adapters are discovered.** A `PluginAdapter` subclass in `plugins/adapters/` is registered at startup; load failures are shown on the Plugins page and at `GET /api/v1/plugins/load-errors`.
- **Plan and handoff views** in chat for multi-agent answers, and light-theme colours for the agent panels.
- `scripts/check-env-passthrough.sh`; `build-images.sh --api-url`.

### Fixed
- `scripts/setup.sh` generated an invalid encryption key; it now generates and verifies a valid one.
- Settings in `.env` did not reach the containers; `docker-compose.yml` now loads `.env` into the API, worker and scheduler.
- `/docs` returned 404; it is served unless `ENVIRONMENT=production`.
- Helm chart rewritten: it could not start (missing addresses, migrations never run). Not yet tested on a cluster.
- CI installs the cloud SDKs; end-to-end tests take their user from `E2E_EMAIL` / `E2E_PASSWORD`.
- Documentation: multi-agent steps run in order, not in parallel; tenant isolation is by row, not by database; counts corrected.

### Added (triage)
- **Triage decisions are kept.** A finding marked false positive, triaged or in progress keeps that state when the repository is scanned again, matched by rule, file and resource (not line number). A finding marked resolved that is found again is reopened with a note. A decision made now is also applied to the same finding in older scans of that repository. Applies to decisions made in the UI, through the API and by agents.
- **Triage queue for agents** (`list_triage_queue`): open findings from the latest assessment of each target only, most severe first, each with evidence (known-exploited CVE, exploit probability, how long it has existed, whether the path looks like test code).
- **One approval for a list of triage decisions** (`triage_findings`): the Triage Agent proposes up to 400 decisions, and findings with one cause can share a decision and its reason; the approver sees them as one list, with anything that would hide a finding first and a reason on every line. Hiding a finding needs a specific reason. Findings changed by someone else in the meantime are skipped.
- **Automatic triage after an assessment** (`AGENT_AUTO_TRIAGE_AFTER_SCAN`, off by default): a repository scan or cloud assessment that leaves open findings starts a Triage Agent run. The run belongs to nobody, so it can only read findings and propose triage decisions, it never gets a tool that acts outside GuardNous, and its list waits for someone with `agents:manage`. One such run per organization is open at a time.
- **Scored evaluation of the Triage Agent** (`make eval-triage`, `docs/evals/triage.md`): 22 labelled findings, including four real findings disguised as noise, run through the agent with the configured model in a temporary organization. Fails if any real finding would be hidden. First result: 18 of 18 scored cases correct with claude-opus-4-6.
- **Internet exposure in the triage queue**: each cloud finding says whether its resource is reachable from the internet and why (a public instance, a public database, an open security group that a public instance uses, or one that nothing uses).
- The Triage Agent gets a larger budget (20 model calls, 8,192 output tokens per call) and reads up to 100 queue rows per page, so one run can cover a few hundred findings. `AGENT_RUN_STEP_CEILING` (24) caps what any agent may ask for.
- **"Triage with AI" on the Findings page** starts a Triage Agent run. Findings also get Mark Triaged, False Positive and Reopen actions.
- **Fix pull requests on GitLab, Bitbucket Cloud and Azure DevOps** (`services/vcs/fix_writers.py`), in addition to GitHub. Same flow: diff first, second-person approval, then branch, commit and pull request (merge request on GitLab). GitHub App connections now get a fresh installation token for the fix instead of failing. The three new providers are tested against the requests they send, not yet against the real services.
- **Images and scanned PDFs as chat attachments**: the text in them is read on the server with Tesseract (now in the backend image). The picture itself is not interpreted. HEIC is refused with a reason.
- **Secrets in attached files are hidden** before the text is stored or sent to a model: access keys, tokens, passwords, private keys, connection strings, card and social security numbers. The upload reply reports how many were hidden. IP addresses, e-mail addresses and account IDs are kept.
- **AWS sync reads every enabled region**, several at a time, when no region list is set on the account. Falls back to four regions if the role may not list regions.
- Lint configuration for the backend (`[tool.ruff]` in `backend/pyproject.toml`); `make lint` now fails on findings and the code passes with none.
- **Attach files in AI Copilot chat**: a paperclip button (or drag and drop) takes PDF, Word (.docx), Excel (.xlsx), CSV, JSON, YAML, Markdown, text, logs and source files, up to 5 files of 15 MB per message. The text is extracted on upload and the file itself is not stored. Attached text is given to the model as quoted material, separately from what the user typed, so message-length limits do not apply to it. Old Office formats (.doc, .xls) and images are refused with a reason.
- **PDF from chat**: ask for a PDF and the assistant attaches one to its reply (`export_pdf_report`). Every answer also has a "PDF" action next to "Copy".
- **Cloud Connectors**: one card per cloud (AWS, Azure, Google Cloud) with the provider's logo; a card opens that cloud's connection dialog. AWS opens on the no-access-keys flow, with the role ARN / access key form one click away. Connected accounts are grouped per cloud in collapsible sections; a cloud with no account has no section.
- **Cloud Posture per account**: the overview groups accounts per cloud; an account opens its own page (`/cloud-posture/{id}`) with its findings, exposure, rules and changes. `GET /api/v1/cloud-posture?account_id=` returns one account.
- **Cloud posture assessments have their own pipeline** on the scan page: reading the cloud account, checking rules, updating findings. Each stage shows its real duration and what it did. Previously the page showed the repository pipeline (clone, secrets, IaC) with nothing in it. Task Monitor's "Repository" column is now "Target" and names the cloud account.
- **Agent runs** (`/agent-runs`, `POST /api/v1/agents/runs`): give an agent a task that a worker executes in the background. Every model call and tool call is stored as a step; a run survives restarts and can be stopped.
- **Approvals for agent actions**: a tool that changes data pauses the run until a person decides. Changes to GuardNous data may be confirmed by the requester; changes to external systems need a different person with `agents:manage`. Rejected actions are never executed. Undecided requests expire after `AGENT_APPROVAL_TTL_HOURS`.
- **Fix pull requests from agents** (`open_fix_pull_request`, GitHub): the agent reads the file, generates the fix, and the approver sees the exact diff. Only that approved content is committed, on a new branch, and only if the file has not changed since. The base branch is never written to.
- **Slack messages from agents** (`send_slack_message`): posts to the organization's Slack webhook after the exact text is approved.
- **Cloud posture for AWS**: sync now also reads account settings, CloudTrail, KMS, VPC flow logs, load balancers and WAF association, ACM certificates, EKS, ECR, Secrets Manager metadata, Route 53, GuardDuty, AWS Config and EBS default encryption. 44 fixed rules (`GN-AWS-*`) run after every sync and open, resolve and reopen findings as the cloud changes. A setting that cannot be read is reported as not checked, never as a finding. Built-in policies cover the matching cloud rules.
- **Connect AWS without access keys** (Cloud Connectors): enter the account ID, deploy one CloudFormation stack, and GuardNous connects by itself. GuardNous is an OIDC issuer (`/.well-known/openid-configuration`); the stack makes AWS trust it and creates a read-only role (SecurityAudit) that only this connection's tokens can assume. No key is created or stored; credentials last one hour. Optional switch grants the specific write actions for approved fixes. Needs `OIDC_ISSUER_URL` (a public https address).
- **Cloud Posture page** (`/cloud-posture`, `GET /api/v1/cloud-posture`): findings by severity, what is reachable from the internet, every rule with passing / failing / not-checked counts and its CIS AWS v1.4.0 number, and the list of changes GuardNous made in the cloud.
- **Fixing cloud findings in AWS** (`remediate_cloud_finding`): block public access on a bucket, remove SSH/RDP open to the internet from a security group, turn on EBS default encryption, turn on KMS key rotation. The change is planned from the live resource, shown to a second person for approval, refused if the resource changed in between, read back to confirm, and recorded with the previous settings. **Roll back** restores them (`POST /cloud-posture/changes/{id}/rollback`). Needs credentials that allow the change; read-only accounts get a clear refusal.
- **Agent tools on real cloud data**: `cloud_inventory_summary`, `list_cloud_resources`, `get_cloud_resource`, `cloud_posture_summary`, `internet_exposure` (joins instances to their security groups), available to every agent.
- Native tool calling and token usage for Anthropic (direct and through Azure Foundry). Per-run and monthly token totals, optional monthly budget (`AGENT_MONTHLY_TOKEN_BUDGET`) and cost estimate (`LLM_*_PRICE_PER_MTOK`).

### Security
- **AI Copilot chats are private to the person who had them.** Conversations were filtered by organization only, so every user in an organization could list, read, continue, rename and delete every other user's chats. All chat endpoints now also require the conversation to be the caller's own; administrators are not an exception.
- Agent audit entries (`/api/v1/agent-audit`) were readable by any signed-in user of the organization. Users now see only their own; seeing everyone's needs `audit_logs:read`.
- Session endpoints accept only access tokens. Password-reset, 2FA and other purpose tokens are rejected. **All existing sessions are invalidated; users sign in again.**
- Tenant isolation enforced on groups, roles, users, invitations, organizations, logs and tenant management. `X-Organization-Id` is honoured only for installation superusers.
- Role changes and invitations cannot grant a role above the actor's own. Self-registered users are admins of their own tenant, not installation superusers.
- Admin API (`/api/admin`) authorizes by role, no longer by matching the `SUPER_ADMIN_EMAIL` address.
- Webhooks fail closed: every organization has its own secret and unsigned or unverifiable requests get 401. **Existing webhooks must be re-registered with the secret from `GET /api/v1/integrations/webhook-config`.**
- `/setup/initialize` is refused once any user exists.
- CI scans require an onboarded repository and fail when an enforced policy is violated.

### Changed
- **Risk score formula.** The score rose in a straight line and stopped at 100, so 50 and 5,000 critical findings scored the same. It now rises in a straight line to 50 (weight 250) and then with the logarithm of the weight, reaching 100 at 25,000. Scores of existing scans change only when they are scanned again.
- Only one sync of a cloud account runs at a time (a 30-minute lock); a second request while one is running is skipped.
- Mode prompts and built-in agent prompts no longer ask for emoji, and the fix mode describes the approval flow instead of a removed `dry_run` switch.
- `quarantine_resource` is described as what it is: a plan. It never changed anything, but its text suggested it could.
- Docs: `SKILLS.md` and `PROMPTS.md` rewritten from the code; `SECURITY.md`, `docs/architecture.md` and `docs/TESTING_AND_ONBOARDING.md` corrected; 22 API rows in `README.md` that pointed at endpoints that do not exist now point at the real ones; planning documents carry a note that they are historical.
- **Assistant answers contain only the answer.** The chat prompt used to instruct the model to write "Thought / Action / Observation / Reflection"; it now tells it to work silently and answer directly, without emoji or process narration. Any reasoning label a model still writes before its answer is removed.

### Fixed
- **Rule-based auto-triage no longer hides findings.** `POST /agents/auto-triage` marked anything on a path containing `test`, `example`, `demo`, `sample` or `docs/` as a false positive and hid it. Such findings now stay open and are reported as "possible false positive" for a person to confirm.
- The "Suppress" button on the Findings page sent a status the API rejects, so it never worked. It is now "False Positive" and uses the triage endpoint.
- Reopening a finding that had been marked false positive left it hidden. Reopening now makes it visible again.
- The Triage Agent's prompt described statuses and abilities that do not exist ("accepted risk", confidence scores, SLA awareness). It now describes the queue, the evidence and the approval step.
- Removed `POST /findings/auto-triage`, a stub that always answered "not yet configured".
- Dead code that returned an invented verdict for an indicator of compromise is gone; `enrich_ioc` and `check_reputation` report that no threat-intelligence source is connected.
- 266 lint findings: unused imports and variables, duplicate definitions, names used in type hints without an import.
- VCS Integrations showed hand-drawn single-colour icons for GitHub, GitLab, Bitbucket and Azure DevOps; it now shows each provider's own logo.
- Two agents (Security Analyst, Triage Agent) listed a tool, `search_findings`, that does not exist.
- **Dashboard numbers and charts.** "Check Pass Rate" divided fixed findings by open findings, so it showed 0% while checks had passed; it now counts policy and cloud rule checks that passed and failed in the latest assessment of each repository and cloud account. The two donuts start at 12 o'clock and run clockwise in legend order, small slices are no longer hidden behind a thick outline, every category has its own colour, and the ring and its legend show the same slices. Categories that differ only in case are merged. The score label under a low score reads "At risk" instead of "Critical".
- AI Copilot chat answered every message with "An error occurred. Please try again." The background task that produces the reply referred to a variable that did not exist there. The chat endpoint now has a test.
- New findings were saved without `organization_id` and did not appear in the Findings list. They now inherit it from their scan; existing rows are back-filled at startup.
- Specialist agent chat crashed (`filter_tools_for_agent` called without the tool list).
- Repository scans crashed in the policy stage (`cloud`, `org_id`, `created_findings` undefined).
- `POST /governance/policies/evaluate` returned 500.
- The agent `triage_finding` tool wrote to a field that does not exist, so agent triage never changed a finding; `POST /agents/auto-triage` returned 500 for the same reason. Notes added to a finding were not always saved.
- Ten endpoints required permissions named `execute` or `write`, which do not exist, so only administrators could use chat, skills, triage, remediation, auto-triage and scan cancel. They now map to `create` and `update`.
- The ticket-drafting agent tool could read a finding from another organization by ID.
- Delegation between agents in chat crashed on a wrong argument; agents allowed to delegate were never offered the tool.
- Checkov findings were titled `CKV_AWS_20: FAILED`, all MEDIUM, with no resource type. They now carry Checkov's check name, the resource type, and the severity of the built-in policy that covers the check (MEDIUM otherwise, since open-source Checkov reports none).
- Twenty frontend calls pointed at routes that do not exist (users, org management, settings, onboarding).

### Changed
- Agent tools that change data run only inside an approved agent run. In chat they are refused with a pointer to Agent Runs.
- Agent tools for exposed ports, IAM, encryption, backups, WAF, DNS and TLS answer from the synced cloud inventory instead of keyword-matching scan findings. Endpoint security, cost anomalies, IOC enrichment and reputation report that no data source is connected instead of computing a score.
- `create_jira_ticket` is now `draft_ticket` (it only ever drafted text) and `notify_slack_channel` is now `send_slack_message`.
- `auto_fix_finding` and `POST /agents/autofix` preview a real fix from the repository file and never write.
- Role limits on agents and tools (`allowed_agents`, `allowed_tools`) are taken from the user's own roles; before, the first role in the database was used for everyone.
- Compliance is evidence-based: controls are passed, failed, **not assessed** or **manual**. No scans means no score, not 100%.
- Policies need rules that can match findings; risk exceptions need a scope, cannot be self-approved, and actually exempt matching violations. Built-in policies load as not enforced.
- IAM scan analyses IAM resources synced from connected cloud accounts with fixed rules. Randomly generated identities, threats and attack paths are gone.
- Cloud connectors return an error when the provider SDK is missing or credentials fail, instead of simulated success. "Test connection" calls the provider.
- Repository scans read Bitbucket and Azure DevOps as well as GitHub and GitLab, and fail with the reason when a repository cannot be read. Demo files are no longer scanned as a fallback.
- Scan notifications follow the organization's saved preferences (Slack, Teams, realtime email, in-app).
- The four autonomous agents and two plugin supply-chain checks are registered with Celery and scheduled. CVE Watchdog uses the synced CVE table (severity, EPSS, CISA KEV).
- Sample governance resources are created only when `DEMO_DATA_ENABLED=true`.

### Added
- **Schedules page** (`/schedules`): recurring repository scans and emailed reports, with "Run now" and the outcome of the last run. A scan schedule must target an enabled repository of the organization. A report schedule builds a new report on every run; if SMTP is not configured the report is saved and the schedule says it was not emailed. Schedules are checked every 5 minutes.
- **Scanner integrity gate**: SHA-256 of each external scanner is verified before every execution against a baseline recorded when the image is built. `PLUGIN_INTEGRITY_MODE`, `GET /plugins/integrity`, `POST /plugins/{name}/integrity/approve` (installation administrators only).
- `python -m app.core.migrations` builds an empty database from the models and stamps it, or runs `alembic upgrade head` on a versioned one. The Alembic chain alone could not create a database from scratch, and startup silently fell back to `create_all` when it failed.
- Migration 023 (missing indexes, `agent_insights.finding_id` cascade) and 024 (schedule run status).
- `backend/seed_test_data.py --reset`: development data set (two tenants, seven users across roles, real scans of the bundled sample files).
- Requesting a risk exception needs `findings:update`; approving or rejecting needs `findings:manage` (previously the other way round, so analysts could approve but not request).
- `RATE_LIMIT_ENABLED`, `TRUSTED_PROXY_COUNT`, `DEMO_DATA_ENABLED` settings; `backend/requirements-cloud.txt`.
- `POST /cloud-accounts/test-credentials`, `GET /integrations/webhook-config`, `POST /integrations/repos/sync`, `GET /groups/{id}`.

## [2.0.0] — 2026-10-30

### 🚀 Major Release — AI-Native Security Platform

GuardNous 2.0 represents a major evolution from a scan aggregation tool to a full **AI-native security intelligence and autonomous operations platform**. This release consolidates all features from the 1.x line, adds streaming AI copilot, dark theme, investigation mode, comprehensive logging, and production hardening.

### 🤖 Agentic AI Transformation — 20 Agents · 62 Tools
- **20 autonomous AI agents** deployed — orchestrator, triage, remediation, PR creator, knowledge retrieval, CVE analyst, compliance mapper, blast radius, root cause, timeline reconstruction, and more
- **62 registered tools/skills** — vulnerability lookup, code search, fix generation, PR creation, policy evaluation, risk scoring, knowledge store queries, SBOM analysis, etc.
- **Multi-agent delegation** — orchestrator agent routes tasks to specialist agents with context passing
- **Plugin version management system** — track, compare, and upgrade scanner plugin versions via API (`GET/POST /api/v1/plugins/versions/`)
- **GuardNous Bot user** — `guardnous-bot` service account for automated PR comments, scan result summaries, and auto-fix PRs
- **Bot-authored auto-fix PRs** — `create_auto_fix_pr()` creates branch, commits fixes, and opens PR with bot identity
- **Scanner marketing name reconciliation** — consistent professional names across all adapters (Semgrep SAST, Aqua Trivy, Bridgecrew Checkov, Gitleaks Secret Scanner, Aqua tfsec)
- **Multi-scanner parallel execution** — improved orchestration for running 5+ scanners concurrently
- **Prompt registry** — centralized prompt management with versioning and A/B testing support
- **BYOM (Bring Your Own Model)** — supports OpenAI, Azure OpenAI, Anthropic Claude, Ollama (local), and mock mode
- **46 guardrail patterns** — input validation, PII detection, prompt injection prevention, output sanitization

### 🤖 AI Copilot — Streaming & Investigation Mode
- **Server-Sent Events (SSE) streaming** — real-time token-by-token AI responses via `POST /agents/chat/stream`
- **Investigation mode** — deep-dive analysis with investigation-specific skills (root cause analysis, blast radius, timeline reconstruction)
- **Enhanced guardrails** — input validation (PII, prompt injection) + output sanitization wired into the streaming pipeline
- **Tool trace badges** — frontend renders which skills the AI agent invoked for full transparency
- **Stop button** — cancel in-progress AI streaming from the frontend
- **Markdown DSL** — rich rendering of AI responses with tables, code blocks, severity badges

### 🧠 Organization Knowledge Base
- **Per-org knowledge store** — organizations can upload contextual documents (runbooks, architecture diagrams, threat models)
- **Knowledge-augmented responses** — AI copilot retrieves relevant org knowledge before answering
- **API endpoints** — `GET/POST/DELETE /api/v1/knowledge-base/`

### 🌙 Comprehensive Dark Theme
- Full dark theme support across all 26 pages (agents, governance, admin, settings, findings, etc.)
- Consistent color palette using CSS variables and Tailwind dark mode
- Dark-aware charts, tables, modals, slide-out panels, and code blocks

### 📊 Logging & Observability
- **Structured logging service** — all backend operations logged with severity, category, and metadata
- **Database-persisted logs** — queryable via `GET /api/v1/logs/` with filtering by level, category, date range
- **SSE log streaming** — real-time log tailing for admin users via `GET /api/v1/logs/stream`
- **Admin System Logs page** — live log viewer with search, filter, and auto-scroll
- **Rate limit tuning** — configurable per-endpoint rate limits

### 🏢 Admin Enhancements
- **User detail slide-out panel** — view full user profile, role, org memberships, last login, and 2FA status
- **Makefile** — `make dev`, `make test`, `make build`, `make clean` for streamlined development
- **`/api/v1/dashboard/summary` endpoint** — consolidated dashboard statistics and risk score
- **Audit logging across all mutative endpoints** — every create/update/delete is recorded
- **In-app notification system** — bell icon dropdown with unread count and notification preferences

### 🏢 Multi-Tenancy & Organization Management
- **Organization-scoped data isolation** — all queries (findings, scans, repos, users) automatically filtered by `organization_id`
- **Plan tiers with limits** — `free` (10 users, 5 repos), `pro`, `enterprise` with configurable caps
- **Org management API** — `GET/PUT /organizations/current`, `/current/stats`, `/current/members`, suspend/reactivate
- **User-org management** — invite users, assign roles, bulk invite with email notifications
- **JWT org claims** — `org_id` and `org_name` embedded in tokens for stateless tenant resolution
- **Plan limit enforcement** — 403 on exceeding user/repo caps per plan tier
- **Registration flow** — creates org + admin user atomically with free tier defaults
- **Organization settings UI** — plan badge, usage meters, member management in settings page
- **DB migration 019** — `organization_id` FK on Finding, Notification, AuditLog; plan columns on Organization

### 🔒 Security Hardening
- **CORS middleware reordering** — CORSMiddleware now wraps all responses including error handlers
- **Encryption hardening** — Fernet key validation on startup, encrypted VCS token storage
- **Environment variable validation** — required secrets (`SECRET_KEY`, `ENCRYPTION_KEY`) fail fast on missing
- **PDF report security** — sanitized inputs, no path traversal in report generation
- **SMTP password handling** — masked in logs, validated before use

### 🐛 Bug Fixes
- Fixed login crash caused by wrong kwarg (`extra` → `metadata`) in structured logging
- Fixed org registration redirect loop — now redirects to `/login?registered=true`
- Fixed governance frontend type mismatches with backend schemas
- Fixed report download button — now uses API endpoint instead of missing `file_url`
- Fixed IAM threats 500 error and duplicate demo data
- Fixed invite link, AI config fields, integrations UI redesign
- Fixed CVE expand crash, report view, dashboard NaN values
- Fixed admin users page crash and error boundary UI
- Fixed Celery task registration so scans and jobs actually execute

### 🏗️ Infrastructure
- Docker Compose hardened with resource limits, health checks, and volume persistence
- Database indexes added for frequently queried columns
- Backend DELETE endpoints added for resource cleanup
- Pagination support across all list endpoints

---

## [1.2.0] — 2026-10-25

### 📧 Email Verification
- JWT-signed email verification links (24h token expiry) sent on registration and invitation acceptance
- `GET /auth/verify-email?token=` endpoint — validates token, sets `email_verified = true`
- `POST /auth/resend-verification` endpoint — resend verification email for authenticated users
- Branded verify-email frontend page with loading/verified/already-verified/error states
- Tenant creation notification emails sent to the admin who creates a tenant
- Graceful SMTP degradation — verification skipped if SMTP not configured

### 🧙 First-Login Setup Wizard
- 5-step guided configuration wizard enforced for admin users on first login
- Steps: Platform Identity → Date/Time → AI Provider → Notifications → SMTP
- `GET /settings/setup-status` and `POST /settings/complete-setup` backend endpoints
- Auto-redirect via `layout.tsx` — non-admin users bypass the wizard entirely
- `setup_completed` flag on OrgSettings prevents re-triggering

### 🏢 Administration Sidebar Reorganization
- Renamed "Organizations" → "Tenants" throughout UI and API
- Final sidebar order: Tenants → Users → Groups → Roles → Audit Logs → System Logs
- Dropped "Teams" navigation item (deferred to v2)
- Renamed "Application Logs" → "System Logs"

### 🏗️ Multi-Tenancy Isolation (Critical Fix)
- **Email uniqueness per tenant** — `User.email` changed from global `UNIQUE` to composite `UNIQUE(email, organization_id)`, allowing the same email address to exist in different tenants
- **Login with multi-tenant email** — Login now iterates all matching users to find the one whose password matches, supporting same-email-different-tenant scenarios
- **Invite duplicate check scoped** — User invitation duplicate check now scoped to the same organization (was blocking cross-tenant invites)
- **Setup wizard enforcement** — `OrgSettings` row with `setup_completed=False` is now auto-created during tenant registration, ensuring first-login wizard is enforced for every new tenant admin
- **Admin role check broadened** — Layout redirect logic now checks `["admin", "super_admin", "superadmin", "owner", "platform_admin"]` for setup wizard enforcement
- New Alembic migration 012: drops old global email constraint, adds composite unique, backfills OrgSettings for existing orgs

### 🐛 Bug Fixes
- Fixed org registration auto-login — now redirects to `/login?registered=true` with success message
- Fixed sidebar rendering on `/register` page when stale token exists in localStorage
- Welcome email replaced with verification email on org registration
- Removed broken "Accept Invite" button from login page (linked to `/invite` → 404)
- Changed "Create Organization" → "Create Tenant" on login page
- Fixed dual-head Alembic migration conflict (011 → 011b rename + merge migration 012)

### 📝 Known Limitations
- **Gmail SMTP sender override** — When using Gmail SMTP (`smtp.gmail.com`), Gmail forces the `From` address to match the authenticated account regardless of the configured `SMTP_FROM_EMAIL`. This is Gmail's anti-spoofing policy, not a bug. Use a transactional email service (SendGrid, Mailgun, AWS SES) or configure the desired address as a Gmail "Send mail as" alias to use a custom sender address.

---

## [1.1.0] — 2025-07-12

### 🔐 Two-Factor Authentication (TOTP)
- TOTP-based 2FA (RFC 6238) — compatible with Google Authenticator, Authy, 1Password
- Organization-wide 2FA enforcement toggle (admin setting)
- QR code generation for easy setup
- 10 one-time backup recovery codes (bcrypt-hashed)
- 3-way login flow: normal → MFA challenge → MFA setup required
- Settings → Security tab for per-user 2FA management

### 📊 Scheduled Scans & Report Delivery
- Cron-based and interval-based scan schedules via `/scan-schedules` API
- Scheduled branded PDF report generation and email delivery (daily/weekly/monthly)
- On-demand report emailing via `/reports/{id}/email` endpoint
- GuardNous orange-branded HTML email templates for all communications

### 🧠 AI Agent Enhancements
- **Prompt Registry** — 13 built-in prompt templates (triage, remediation, compliance, risk, attack surface, comparison, greeting), customizable per-organization
- **Enhanced Guardrails** — 46 security patterns: 11 PII detectors, 25 injection blockers, 10 output sanitizers
- **Multi-Agent Delegation Protocol** — Depth-tracked sub-task delegation between specialized agents with infinite-loop prevention
- **Agent Audit Trail** — Full execution logging: agent used, tools called, input/output, duration, token usage, success/failure
- **RBAC Agent Access Control** — Roles can restrict which agents and tools users are allowed to invoke

### ✉️ User Invitation System
- Branded invitation emails auto-sent on user invite
- Single invite, bulk invite, and CSV bulk invite support
- One-click registration link in email
- Frontend email status tracking (sent/failed)

### 🎨 UI/UX Improvements
- Full orange-brand rebranding across all auth pages (login, register, invite)
- Integrations page rebranded and select-all/deselect-all bug fixed
- AI Configuration test connection bug fixed (correct URL, payload, response handling)

### 🏗️ Infrastructure
- New database migration (011) for 2FA columns, RBAC agent columns, agent_audit_entries, scan_schedules, report_schedules tables
- Added dependencies: `pyotp`, `qrcode[pil]`, `reportlab`
- All 6 Docker containers rebuilt and verified healthy
- Regenerated `poetry.lock` for Python 3.12 compatibility

### 📝 Documentation
- Comprehensive README update: new features, updated API reference, tech stack, roadmap
- Architecture documentation updated with new models, services, and Celery tasks
- AGENTS.md updated with guardrails, delegation, audit, and prompt registry
- CHANGELOG v1.1.0 entry

---

## [1.0.0] — 2026-10-17

### 🎉 Initial Open-Source Release

#### Core Platform
- FastAPI backend with async SQLAlchemy ORM
- Next.js 14 frontend with shadcn/ui component library
- PostgreSQL 16 + Redis 7 + Celery task queue
- Docker Compose for local development
- Helm chart for production Kubernetes deployment

#### Security Scanning
- 4 native scanners: Terraform, CloudFormation, Bicep, Secrets
- 5 plugin adapters: Checkov, Trivy, Semgrep, Gitleaks, tfsec
- Universal SARIF v2.1.0 import (100+ scanners via standard format)
- SBOM generation (CycloneDX 1.5)

#### AI-Powered Security
- Three-layer AI triage (rule → ML → LLM) with confidence scores
- Autofix engine: generates code patches for findings
- VCS write operations: auto-create PRs with fixes
- AI Security Copilot chat interface
- Fix pattern knowledge store (learns from accepted fixes)

#### Enterprise Features
- Multi-tenancy: Organization → Team → User hierarchy
- RBAC: 7 roles, 72 granular permissions
- Audit logging for all state-changing operations
- Policy-as-code engine (20 built-in policies)
- Compliance frameworks: SOC 2, HIPAA, PCI-DSS, CIS, NIST

#### Integrations
- VCS: GitHub, GitLab, Bitbucket, Azure DevOps (OAuth + webhook)
- GitHub App support (enterprise)
- CI/CD pipeline integration with OIDC + API key auth
- CVE database sync from NVD
- IAM threat intelligence module

#### DevOps
- Interactive setup wizard (`setup/install.sh`)
- Environment validation (`setup/validate-env.sh`)
- CI-agnostic image builder (`setup/build-images.sh`)
- GitHub Actions CI/CD pipeline
- Helm chart with HPA, probes, ingress, external DB/Redis support

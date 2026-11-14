# Roadmap

[← Back to the README](../README.md)

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


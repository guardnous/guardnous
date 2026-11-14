# Why GuardNous, and how it compares

[← Back to the README](../README.md)

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


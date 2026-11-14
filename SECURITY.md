# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Active support  |
| 1.x     | ⚠️ Security fixes only |
| < 1.0   | ❌ Not supported   |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report them responsibly via one of these channels:

1. **GitHub Security Advisories** — [Open a private advisory](../../security/advisories/new)
2. **Email** — Send details to **harsh.khajgiwale@gmail.com**

### What to Include

- Description of the vulnerability
- Steps to reproduce (or a proof-of-concept)
- Affected version(s)
- Impact assessment (what an attacker could achieve)

### Response Timeline

| Stage | SLA |
|-------|-----|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix + advisory (critical) | 7 days |
| Fix + advisory (high) | 14 days |
| Fix + advisory (medium/low) | 30 days |

### Disclosure Policy

- We follow **coordinated disclosure** — we'll work with you on timing.
- Credit is given to reporters in the advisory (unless you prefer anonymity).
- We will never take legal action against good-faith security researchers.

## Built-in Security Features

- **Two-Factor Authentication (TOTP)** — RFC 6238 compatible (Google Authenticator, Authy, 1Password). Org-wide enforcement toggle available for admins. 10 backup recovery codes per user.
- **Tenant isolation** — Every query is filtered by organization. Roles carry 72 permissions across 7 built-in roles.
- **AI guardrails** — 55 patterns: prompt-injection blocking (25) and personal-data replacement (11) on what the user types; secret (9) and internal-path (10) removal on model output.
- **Approval before any outside change** — An agent cannot open a pull request, change a cloud resource or post to Slack on its own. The run stops, shows the exact change, and a second person with `agents:manage` must approve. The person who started the run cannot approve it.
- **RBAC agent access** — Roles can restrict which AI agents and tools a user may invoke.
- **Agent audit trail** — Every agent run is logged: tools called, inputs and outputs, duration, token usage, who approved.
- **Chat attachments** — Files are reduced to text on upload and the original file is not kept. Access keys, tokens, passwords, private keys, connection strings, card and social security numbers in the text are replaced with a marker before it is stored or sent to a model. Images and scanned PDFs are read on the server (Tesseract); nothing is sent to an outside OCR service. Uploaded content is never executed.
- **Keyless AWS access** — AWS accounts connect through OpenID Connect and an IAM role with a read-only policy. No AWS access keys are stored. Fixes are possible only if the customer deploys the role with fixes allowed.
- **Stored credentials** — Repository tokens, cloud credentials and LLM API keys are encrypted at rest with Fernet (`ENCRYPTION_KEY`). GitHub App connections store no token; a one-hour token is issued per use.
- **JWT authentication** — Configurable expiry (default 60 minutes). Login is rate limited.

## What Leaves Your Deployment

- **Your LLM provider** receives the chat message, the tool results the agent used, and the text of attached files after secrets are replaced. With the `mock` or a local `ollama` provider nothing leaves.
- **Your repository host and cloud accounts** are called with the credentials you connected.
- **NVD** is queried for CVE data, and scanner download sites are contacted when you install or update a scanner plugin.
- **Slack**, if connected, receives the messages a second person approved.
- GuardNous itself sends no telemetry.

## Security Best Practices for Deployments

- Always generate unique `SECRET_KEY` and `ENCRYPTION_KEY` values
- Enable 2FA enforcement for all users via Admin → Settings → Security
- Use TLS termination at the ingress layer
- Run PostgreSQL and Redis with authentication enabled
- Keep scanner binaries (Trivy, Checkov, etc.) updated
- Configure SMTP settings for invitation emails and report delivery
- There is no default administrator password. `scripts/setup.sh` generates one and prints it once; otherwise set `INITIAL_ADMIN_PASSWORD`, or read the generated one from the API log on first start. Change it after the first sign-in
- Organization settings (e-mail server, AI provider and key, notifications) and the agents' knowledge base can be changed only by roles holding `settings:update` / `agents:update`. Give those roles to few people
- The interactive API documentation (`/docs`) is served unless `ENVIRONMENT=production`. Set that in production
- Install with [`scripts/setup.sh`](scripts/setup.sh), which generates the keys and the first administrator's password

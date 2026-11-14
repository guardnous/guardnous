# Configuration

[← Back to the README](../README.md)

All config via environment variables. See [`.env.example`](../.env.example) for the full list (80+ vars).

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
[`backend/requirements-cloud.txt`](../backend/requirements-cloud.txt) (installed by the
backend Docker image). Without them, connecting an account returns an error.
| `GITHUB_CLIENT_ID` | No | GitHub OAuth app |
| `GITLAB_CLIENT_ID` | No | GitLab OAuth app |

---


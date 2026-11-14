# GuardNous — Testing & Onboarding Guide

> Complete guide for developers, evaluators, and enterprise teams to test, onboard, and validate GuardNous.

---

## Table of Contents

1. [Quick Start (5 minutes)](#1-quick-start-5-minutes)
2. [Manual Scan Testing (No VCS Needed)](#2-manual-scan-testing-no-vcs-needed)
3. [VCS Integration Testing](#3-vcs-integration-testing)
4. [Plugin System Testing](#4-plugin-system-testing)
5. [Running the Test Suite](#5-running-the-test-suite)
6. [Enterprise Evaluation Playbook](#6-enterprise-evaluation-playbook)
7. [Troubleshooting](#7-troubleshooting)
8. [Architecture Quick Reference](#8-architecture-quick-reference)

---

## 1. Quick Start (5 minutes)

### Prerequisites

| Requirement      | Minimum | Recommended |
|------------------|---------|-------------|
| Docker           | v20+    | v24+        |
| Docker Compose   | v2.0+   | v2.20+      |
| RAM              | 4 GB    | 8 GB        |
| Disk             | 2 GB    | 5 GB        |
| OS               | Linux, macOS, Windows (WSL2) | Ubuntu 22.04+ |

### Step 1: Clone & Start

```bash
git clone https://github.com/guardnous/guardnous.git
cd guardnous

# Write .env with generated keys, build and start everything.
# The first administrator's password is printed once at the end.
./scripts/setup.sh

# Watch startup (wait ~60s for all services to be healthy)
docker compose ps
docker compose logs -f api --tail=50
```

### Step 2: Verify Services Are Running

```bash
# Health check
curl -s http://localhost:7002/api/health | python3 -m json.tool
# Expected: {"status": "healthy", "service": "GuardNous", "version": "2.0.0"}

# Check all containers
docker compose ps
# All 6 services should be "healthy" or "running":
#   postgres, redis, api, celery-worker, celery-beat, web
```

### Step 3: Create Your Account

```bash
# Register via API (or use the web UI at http://localhost:7003)
curl -s -X POST http://localhost:7002/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePass123!",
    "full_name": "Admin User",
    "organization_name": "My Company"
  }' | python3 -m json.tool

# Login to get your JWT token (the login endpoint takes form fields, not JSON)
TOKEN=$(curl -s -X POST http://localhost:7002/api/v1/auth/login \
  --data-urlencode 'username=admin@example.com' \
  --data-urlencode 'password=SecurePass123!' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Your token: $TOKEN"
```

### Step 4: Open the Dashboard

Open **http://localhost:7003** → Login with `admin@example.com` / `SecurePass123!`

You should see the GuardNous dashboard with the hero section, risk gauge, and empty state cards.

---

## 2. Manual Scan Testing (No VCS Needed)

You don't need to connect a repo to test scanning. The API accepts raw file content directly.

### 2a. Scan a Terraform File

The repo includes intentionally insecure sample files in `backend/sample_files/`.

```bash
# Read the sample insecure Terraform file and scan it
curl -s -X POST http://localhost:7002/api/v1/scans/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "terraform",
    "source": "resource \"aws_security_group\" \"web\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n\nresource \"aws_s3_bucket\" \"data\" {\n  bucket = \"my-data-bucket\"\n  acl = \"public-read\"\n}\n\nresource \"aws_db_instance\" \"main\" {\n  identifier = \"main-db\"\n  engine = \"mysql\"\n  instance_class = \"db.t3.micro\"\n  username = \"admin\"\n  password = \"SuperSecret123!\"\n  publicly_accessible = true\n}",
    "file_name": "main.tf"
  }' | python3 -m json.tool
```

**Expected output**: A scan result with multiple findings:
- 🔴 CRITICAL: SSH port open to 0.0.0.0/0
- 🔴 CRITICAL: S3 bucket publicly accessible
- 🔴 CRITICAL: RDS publicly accessible
- 🔴 CRITICAL: Hardcoded database password
- 🟠 HIGH: S3 bucket without encryption
- etc.

### 2b. Scan a CloudFormation Template

```bash
curl -s -X POST http://localhost:7002/api/v1/scans/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "cloudformation",
    "source": "AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: my-public-bucket\n      AccessControl: PublicRead\n  MyDB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      DBInstanceClass: db.t3.micro\n      Engine: mysql\n      MasterUsername: admin\n      MasterUserPassword: HardcodedPass123!\n      PubliclyAccessible: true\n      StorageEncrypted: false",
    "file_name": "template.yaml"
  }' | python3 -m json.tool
```

### 2c. Scan a Bicep File

```bash
curl -s -X POST http://localhost:7002/api/v1/scans/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "bicep",
    "source": "resource storageAccount '\''Microsoft.Storage/storageAccounts@2022-09-01'\'' = {\n  name: '\''mystorageacct'\''\n  location: resourceGroup().location\n  kind: '\''StorageV2'\''\n  sku: { name: '\''Standard_LRS'\'' }\n  properties: {\n    supportsHttpsTrafficOnly: false\n    minimumTlsVersion: '\''TLS1_0'\''\n  }\n}",
    "file_name": "main.bicep"
  }' | python3 -m json.tool
```

### 2d. Run a Secrets Scan

```bash
curl -s -X POST http://localhost:7002/api/v1/scans/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "secrets",
    "source": "# Config\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDATABASE_URL=postgres://admin:password123@db.example.com:5432/prod\nGITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nSLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "file_name": ".env.production"
  }' | python3 -m json.tool
```

### 2e. View Your Findings

```bash
# List all findings
curl -s http://localhost:7002/api/v1/findings/ \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Filter by severity
curl -s "http://localhost:7002/api/v1/findings/?severity=critical" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Dashboard summary
curl -s http://localhost:7002/api/v1/dashboard/summary \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### 2f. Generate a PDF Report

```bash
# Create the report; the reply is JSON with the report's id
REPORT_ID=$(curl -s -X POST http://localhost:7002/api/v1/reports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Security report", "format": "pdf"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

# Download it
curl -s http://localhost:7002/api/v1/reports/$REPORT_ID/download \
  -H "Authorization: Bearer $TOKEN" --output security_report.pdf

echo "Report saved to security_report.pdf"
```

---

## 3. VCS Integration Testing

### 3a. GitHub (GitHub App — Recommended)

**Setup**:
1. Go to https://github.com/settings/apps → "New GitHub App"
2. Set:
   - Homepage URL: `http://localhost:7003`
   - Callback URL: `http://localhost:7003/integrations/callback`
   - Webhook URL: `http://YOUR_PUBLIC_URL:7002/api/v1/webhooks/github/{org_id}` (use ngrok for local dev; the exact URL and signing secret are shown by `GET /api/v1/integrations/webhook-config`)
   - Permissions: Contents (Read), Pull Requests (Read & Write), Commit Statuses (Read & Write), Webhooks (Read & Write)
3. Generate a private key (.pem file)
4. Add to your environment:

```bash
# In .env or docker-compose environment:
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="$(cat your-app.pem)"
GITHUB_APP_SLUG=guardnous
GITHUB_CLIENT_ID=Iv1.abc123
GITHUB_CLIENT_SECRET=your_client_secret
GITHUB_CALLBACK_URL=http://localhost:7003/integrations/callback
```

**Test**:
1. Go to http://localhost:7003 → Integrations → GitHub → "Install GitHub App"
2. Select your org/repos
3. Push a `.tf` file → webhook fires → scan runs → findings appear

### 3b. GitHub (PAT — Quick Test)

If you just want to test quickly without the App setup:

```bash
# Connect using a Personal Access Token
curl -s -X POST http://localhost:7002/api/v1/integrations/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vcs_type": "github",
    "token": "ghp_YOUR_GITHUB_PAT_HERE"
  }' | python3 -m json.tool

# List your repos
curl -s http://localhost:7002/api/v1/integrations/repos \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### 3c. GitLab

```bash
# Connect GitLab (gitlab.com)
curl -s -X POST http://localhost:7002/api/v1/integrations/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vcs_type": "gitlab",
    "token": "glpat-YOUR_GITLAB_PAT_HERE"
  }' | python3 -m json.tool

# For self-hosted GitLab, add base_url:
curl -s -X POST http://localhost:7002/api/v1/integrations/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vcs_type": "gitlab",
    "token": "glpat-YOUR_TOKEN",
    "base_url": "https://gitlab.yourcompany.com"
  }' | python3 -m json.tool
```

**Create a GitLab PAT**: GitLab → User Settings → Access Tokens → Scopes: `read_api`, `read_repository`. For fix merge requests the token needs the `api` scope instead.

### 3d. Bitbucket

```bash
# Connect Bitbucket Cloud
curl -s -X POST http://localhost:7002/api/v1/integrations/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vcs_type": "bitbucket",
    "token": "YOUR_APP_PASSWORD",
    "username": "your_bitbucket_username"
  }' | python3 -m json.tool
```

**Create a Bitbucket App Password**: Bitbucket → Personal Settings → App Passwords → Permissions: Repositories (Read), Webhooks (Read and write). For fix pull requests also grant Repositories (Write) and Pull requests (Write).

### 3e. Azure DevOps

```bash
# Connect Azure DevOps
curl -s -X POST http://localhost:7002/api/v1/integrations/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vcs_type": "azure_devops",
    "token": "YOUR_AZURE_DEVOPS_PAT",
    "base_url": "https://dev.azure.com/your-organization"
  }' | python3 -m json.tool
```

**Create an Azure DevOps PAT**: Azure DevOps → User Settings → Personal Access Tokens → Scopes: Code (Read), Build (Read & Execute), Project & Team (Read).

### 3f. Testing Webhooks Locally

Webhooks require a publicly accessible URL. Use **ngrok** for local testing:

```bash
# Install ngrok
# https://ngrok.com/download

# Expose your API
ngrok http 7002

# Copy the https:// URL (e.g. https://abc123.ngrok-free.app)
# Use as webhook URL: https://abc123.ngrok-free.app/api/v1/webhooks/github/{org_id}
```

Then push a `.tf` or `.yaml` file to your connected repo. You should see:
1. Webhook received in API logs: `docker compose logs -f api`
2. Scan triggered automatically
3. Findings appear in the dashboard
4. PR comment posted (if push was part of a PR)

---

## 4. Plugin System Testing

### 4a. View Plugin Status

```bash
# List all plugins (native + external)
curl -s http://localhost:7002/api/v1/plugins/ \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

You'll see:
- ✅ **Native plugins** (always enabled): `native_terraform`, `native_cloudformation`, `native_bicep`, `native_secrets`
- ⚠️ **External plugins** (auto-disabled if binary not found): `checkov`, `trivy`, `gitleaks`, `semgrep`, `tfsec`

### 4b. Enable External Plugins

External plugins require their CLIs installed in the Docker container (or on the host for local dev):

```bash
# Install external scanners (inside the API container)
docker compose exec api pip install checkov
docker compose exec api apt-get update && apt-get install -y wget
docker compose exec api wget -qO /usr/local/bin/trivy https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-64bit && chmod +x /usr/local/bin/trivy

# Or for local development:
pip install checkov
brew install aquasecurity/trivy/trivy  # macOS
brew install gitleaks
pip install semgrep
```

After installing, restart the API to trigger auto-discovery:

```bash
docker compose restart api

# Verify plugin is now enabled
curl -s http://localhost:7002/api/v1/plugins/ \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys, json
plugins = json.load(sys.stdin)
for p in plugins:
    status = '✅' if p['enabled'] else '⚠️'
    print(f\"{status} {p['name']:25s} v{p.get('version','?'):10s} {p.get('description','')[:60]}\")
"
```

### 4c. Toggle Plugins

```bash
# Disable a native plugin
curl -s -X POST http://localhost:7002/api/v1/plugins/native_terraform/toggle \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}' | python3 -m json.tool

# Re-enable
curl -s -X POST http://localhost:7002/api/v1/plugins/native_terraform/toggle \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}' | python3 -m json.tool
```

### 4d. Health Check All Plugins

```bash
curl -s http://localhost:7002/api/v1/plugins/supply-chain/health \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## 5. Running the Test Suite

### 5a. Unit Tests

```bash
# From the backend directory
cd backend

# Create venv and install deps
python3 -m venv .venv
source .venv/bin/activate
pip install poetry==1.8.2
poetry install

# Run all tests
pytest -v

# Run with coverage
pytest --cov=app --cov-report=term-missing --cov-report=html

# Run specific test suites
pytest tests/unit/test_terraform_scanner.py -v       # Terraform scanner rules
pytest tests/unit/test_cloudformation_scanner.py -v   # CloudFormation scanner rules
pytest tests/unit/test_bicep_scanner.py -v            # Bicep scanner rules
pytest tests/unit/test_secrets_scanner.py -v          # Secrets detection
pytest tests/unit/test_risk_scorer.py -v              # Risk scoring
pytest tests/unit/test_gitlab_service.py -v           # GitLab VCS
pytest tests/unit/test_bitbucket_service.py -v        # Bitbucket VCS
pytest tests/unit/test_pr_comment.py -v               # PR comment formatting
pytest tests/unit/test_agent_skills.py -v             # AI agent skills
pytest tests/unit/test_agent_tools.py -v              # AI agent tools

# Run integration tests (requires running PostgreSQL + Redis)
pytest tests/integration/ -v
```

### 5b. Test Inside Docker

```bash
# Run tests inside the API container (has all deps)
docker compose exec api pytest -v
docker compose exec api pytest --cov=app --cov-report=term-missing
```

### 5c. Frontend Tests

```bash
cd frontend
npm install
npm run build    # Type-check + build (catches all TS errors)
# npm test       # If test runner is configured
```

---

## 6. Enterprise Evaluation Playbook

This section is for **security teams evaluating GuardNous** for their organization.

### Phase 1: Deploy & Validate (Day 1)

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | `docker compose up -d --build` | All 6 containers healthy |
| 2 | Register admin account | JWT token returned |
| 3 | Run Terraform scan with `insecure.tf` | 8+ findings across CRITICAL/HIGH/MEDIUM |
| 4 | Run CloudFormation scan with `insecure.yaml` | 5+ findings |
| 5 | Run Bicep scan with `insecure.bicep` | 4+ findings |
| 6 | Run Secrets scan with test `.env` file | AWS keys, DB passwords, tokens detected |
| 7 | Check `/api/v1/dashboard/summary` | Risk score > 0, severity breakdown populated |
| 8 | Generate PDF report | PDF with findings, severity charts, remediation |

### Phase 2: Connect Your Repos (Day 2-3)

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Connect your VCS (GitHub/GitLab/Bitbucket/Azure DevOps) | Repos listed |
| 2 | Enable scan-on-push for a test repo | Webhook created |
| 3 | Push an insecure `.tf` file to a branch | Automatic scan triggers |
| 4 | Open a PR with the insecure file | PR comment with findings posted |
| 5 | Check commit status on the PR | Status check shows pass/fail |
| 6 | Fix the finding and push again | Finding count decreases, status updates |

### Phase 3: Scale & Integrate (Week 2)

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Connect 5+ repositories | All repos scanning correctly |
| 2 | Install external plugins (Checkov, Trivy) | Enhanced findings from multiple engines |
| 3 | Enable AI Copilot (set `LLM_PROVIDER` + key) | AI chat provides remediation guidance |
| 4 | Set up scheduled scans (Celery Beat) | Daily scan results in dashboard |
| 5 | Create org-level report | Executive PDF with trend analysis |
| 6 | Test multi-user access (register 2nd user) | Both users see same org data |

### Phase 4: Production Readiness Checklist

- [ ] **Security**: Change `SECRET_KEY` to a cryptographically random value
- [ ] **Security**: Set `ENCRYPTION_KEY` (Fernet) for VCS token encryption
- [ ] **Security**: Enable HTTPS (reverse proxy with nginx/Caddy/Traefik)
- [ ] **Security**: Restrict CORS_ORIGINS to your actual domain
- [ ] **Database**: Use managed PostgreSQL (RDS, Cloud SQL, Azure DB)
- [ ] **Database**: Enable automated backups
- [ ] **Monitoring**: Set up log aggregation (API + Celery worker logs)
- [ ] **Monitoring**: Add health check monitoring on `/api/health`
- [ ] **Scaling**: Increase Celery worker concurrency for large scan loads
- [ ] **Scaling**: Consider Redis Cluster for high-throughput webhook processing
- [ ] **AI**: Set `LLM_PROVIDER=openai` (or azure/anthropic/ollama) with your API key
- [ ] **Webhooks**: Configure a public-facing URL for VCS webhooks (not ngrok)
- [ ] **SSO**: Plan SAML/OIDC integration for enterprise authentication (roadmap v0.5)

---

## 7. Troubleshooting

### Container Won't Start

```bash
# Check logs for the failing container
docker compose logs api --tail=100
docker compose logs postgres --tail=50

# Common fix: database not initialized
docker compose down -v   # WARNING: deletes data
docker compose up -d --build
```

### Database Migration Issues

```bash
# Run migrations manually
docker compose exec api python -m app.core.migrations

# Check current migration version
docker compose exec api alembic current
```

### API Returns 401 Unauthorized

```bash
# Your token may have expired. Re-login:
TOKEN=$(curl -s -X POST http://localhost:7002/api/v1/auth/login \
  --data-urlencode 'username=admin@example.com' \
  --data-urlencode 'password=SecurePass123!' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### Scan Returns Empty Findings

- Check that `scan_type` matches the file content (`terraform` for `.tf`, `cloudformation` for `.yaml`, etc.)
- Ensure the file content is actually insecure (use sample files from `backend/sample_files/`)
- Check API logs: `docker compose logs -f api`

### Webhook Not Firing

1. Verify ngrok tunnel is running and URL matches webhook config
2. Check VCS provider webhook delivery logs (GitHub → Settings → Webhooks → Recent Deliveries)
3. Check API logs for incoming webhook: `docker compose logs -f api | grep webhook`

### Celery Worker Not Processing

```bash
# Check worker status
docker compose logs celery-worker --tail=50

# Restart worker
docker compose restart celery-worker

# Check Redis connectivity
docker compose exec redis redis-cli ping
# Expected: PONG
```

### Port Conflicts

If ports 7000-7003 are in use, edit `docker-compose.yml`:

```yaml
ports:
  - "17000:5432"   # PostgreSQL
  - "17001:6379"   # Redis
  - "17002:8000"   # API
  - "17003:3000"   # Frontend
```

Update `NEXT_PUBLIC_API_URL` and `CORS_ORIGINS` to match.

---

## 8. Architecture Quick Reference

### Service Map

```
┌─────────────────────────────────────────────────────────┐
│  http://localhost:7003   — Next.js 14 Dashboard         │
│  (Register, Login, Dashboard, Findings, Scans,          │
│   Integrations, Plugins, Reports, Settings, AI Chat)    │
└──────────────────────────┬──────────────────────────────┘
                           │  REST API calls
┌──────────────────────────▼──────────────────────────────┐
│  http://localhost:7002   — FastAPI Backend               │
│  ┌────────────────────────────────────────────────────┐ │
│  │  /api/v1/auth/*          — JWT auth, register       │ │
│  │  /api/v1/scans/*         — Trigger & list scans     │ │
│  │  /api/v1/findings/*      — Browse findings          │ │
│  │  /api/v1/dashboard/*     — Stats & risk scores      │ │
│  │  /api/v1/reports/*       — PDF report generation    │ │
│  │  /api/v1/cves/*          — CVE database search      │ │
│  │  /api/v1/integrations/*  — VCS connect/repos        │ │
│  │  /api/v1/webhooks/*      — GitHub/GL/BB/ADO hooks   │ │
│  │  /api/v1/plugins/*       — Plugin management        │ │
│  │  /api/v1/agents/*        — AI Copilot chat          │ │
│  │  /api/health             — Health check             │ │
│  │  /docs                   — Swagger UI               │ │
│  └────────────────────────────────────────────────────┘ │
└───────┬──────────────┬──────────────┬───────────────────┘
        │              │              │
   ┌────▼────┐   ┌─────▼────┐   ┌────▼─────────────────┐
   │ Postgres │   │  Redis   │   │  Celery Workers      │
   │  :7000   │   │  :7001   │   │  (async scans,       │
   │          │   │          │   │   CVE sync, reports)  │
   └──────────┘   └──────────┘   └──────────────────────┘
```

### Scanner Coverage

| Scanner | Languages/Formats | Rule Count | Checks |
|---------|-------------------|------------|--------|
| Terraform | `.tf`, `.tfvars` | 20+ | SG rules, S3 encryption, RDS exposure, IAM wildcards, VPC flow logs, EBS/EFS encryption, ECR scanning, SQS encryption, ElastiCache auth, hardcoded secrets |
| CloudFormation | `.yaml`, `.json`, `.template` | 10+ | S3 public access, RDS encryption, SG open ports, IAM wildcards, CloudTrail, EBS encryption |
| Bicep | `.bicep` | 10+ | Storage HTTPS, TLS version, network access, SQL auditing, Key Vault soft delete, NSG rules |
| Secrets | All files | 15+ | AWS keys, GCP keys, Azure keys, GitHub tokens, Slack webhooks, private keys, JWTs, generic passwords, connection strings |

### API Quick Reference

```bash
# Auth
POST /api/v1/auth/register     — Create account + org
POST /api/v1/auth/login         — Get JWT token
GET  /api/v1/auth/me            — Current user

# Scanning
POST /api/v1/scans/             — Run a scan (source + scan_type)
GET  /api/v1/scans/             — List scans
GET  /api/v1/scans/{id}         — Scan details

# Findings
GET  /api/v1/findings/          — List (filter: severity, scan_id, category)
GET  /api/v1/findings/{id}      — Finding detail

# Dashboard
GET  /api/v1/dashboard/summary  — Risk score, severity counts, trends

# VCS
POST /api/v1/integrations/connect      — Connect via PAT
GET  /api/v1/integrations/repos        — List connected repos
POST /api/v1/webhooks/github/{org_id}  — GitHub webhook
POST /api/v1/webhooks/gitlab/{org_id}  — GitLab webhook
POST /api/v1/webhooks/bitbucket/{org_id} — Bitbucket webhook
POST /api/v1/webhooks/azure-devops/{org_id} — Azure DevOps webhook

# Plugins
GET  /api/v1/plugins/           — List all plugins
POST /api/v1/plugins/{id}/toggle — Enable/disable
GET  /api/v1/plugins/supply-chain/health — Health check all

# Reports
POST /api/v1/reports/           — Generate PDF report

# AI Copilot
POST /api/v1/agents/chat        — Chat with AI assistant
```

---

## Appendix: Sample Insecure Files for Testing

These are included in `backend/sample_files/` but here are minimal examples you can paste directly:

### Terraform (`insecure.tf`)
```hcl
resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "totally-public-bucket"
  acl    = "public-read-write"
}

resource "aws_db_instance" "exposed" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  password            = "admin123"
  publicly_accessible = true
}
```

### CloudFormation (`insecure.yaml`)
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  OpenBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
  ExposedDB:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      DBInstanceClass: db.t3.micro
      MasterUsername: admin
      MasterUserPassword: password123
      PubliclyAccessible: true
      StorageEncrypted: false
```

### Bicep (`insecure.bicep`)
```bicep
resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'insecurestorage'
  location: resourceGroup().location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}
```

### Secrets (`.env.leaked`)
```
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12
DATABASE_URL=postgres://root:s3cret@prod-db.internal:5432/app
STRIPE_SECRET_KEY=sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
```

# Project structure

[← Back to the README](../README.md)

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


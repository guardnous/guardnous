from fastapi import APIRouter
from app.api.v1 import (
    auth, scans, findings, cves, reports, dashboard, integrations,
    webhooks, agents, plugins, onboarding, ci, imports,
    tenants, roles, groups, users_mgmt, setup, audit,
    jobs, iam, governance, org_management, notifications,
    org_settings,
    logs,
    knowledge_base,
    scan_schedules,
    agent_audit,
    agent_runs,
    report_schedules,
    service_accounts,
    sbom,
    cloud_accounts,
    cloud_posture,
)

router = APIRouter(prefix="/api/v1")

# ─── Core ─────────────────────────────────────────────────
router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(scans.router, prefix="/scans", tags=["Scans"])
router.include_router(findings.router, prefix="/findings", tags=["Findings"])
router.include_router(cves.router, prefix="/cves", tags=["CVEs"])
router.include_router(reports.router, prefix="/reports", tags=["Reports"])
router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
router.include_router(integrations.router, prefix="/integrations", tags=["VCS Integrations"])
router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
router.include_router(agents.router, prefix="/agents", tags=["AI Copilot & Agents"])
router.include_router(agent_runs.router, prefix="/agents", tags=["Agent Runs"])
router.include_router(plugins.router, prefix="/plugins", tags=["Plugins"])
router.include_router(onboarding.router, prefix="/onboarding", tags=["Onboarding"])
router.include_router(ci.router, prefix="/ci", tags=["CI/CD Pipeline Integration"])
router.include_router(imports.router, prefix="/imports", tags=["SARIF Import"])

# ─── Enterprise: Multi-Tenancy, RBAC, User Management ────
router.include_router(setup.router, prefix="/setup", tags=["Setup Wizard"])
router.include_router(tenants.router, prefix="/tenants", tags=["Tenants"])
router.include_router(roles.router, prefix="/roles", tags=["Roles & Permissions"])
router.include_router(groups.router, prefix="/groups", tags=["Groups"])
router.include_router(users_mgmt.router, prefix="/users", tags=["User Management"])
router.include_router(audit.router, prefix="/audit", tags=["Audit Logs"])

# ─── Jobs & Progress Tracking ────────────────────────────
router.include_router(jobs.router, prefix="/jobs", tags=["Jobs & Progress"])

# ─── IAM Threat Intelligence ─────────────────────────────
router.include_router(iam.router, prefix="/iam", tags=["IAM Threat Intelligence"])

# ─── Enterprise Governance ───────────────────────────────
router.include_router(governance.router, prefix="/governance", tags=["Enterprise Governance"])

# ─── Multi-Tenancy Management ───────────────────────────
router.include_router(org_management.router, prefix="/org", tags=["Organization Management"])

# ─── Notifications ───────────────────────────────────────
router.include_router(notifications.router, prefix="/notifications", tags=["Notifications"])

# ─── Organization Settings ───────────────────────────────
router.include_router(org_settings.router, prefix="/settings", tags=["Organization Settings"])

# ─── Application Logs ────────────────────────────────────
router.include_router(logs.router, prefix="/logs", tags=["Application Logs"])

# ─── Knowledge Base ──────────────────────────────────────
router.include_router(knowledge_base.router, prefix="/knowledge", tags=["Knowledge Base"])

# ─── Scan Schedules ──────────────────────────────────────
router.include_router(scan_schedules.router, tags=["Scan Schedules"])

# ─── Agent Audit Trail ──────────────────────────────────
router.include_router(agent_audit.router, tags=["Agent Audit"])

# ─── Report Schedules ───────────────────────────────────
router.include_router(report_schedules.router, prefix="/report-schedules", tags=["Report Schedules"])

# ─── Service Accounts (bot identities for auto-fix PRs) ──
router.include_router(service_accounts.router, tags=["Service Accounts"])

# ─── SBOM Capabilities ───────────────────────────────────
router.include_router(sbom.router, prefix="/sbom", tags=["SBOM"])

# ─── Cloud Accounts (real cloud connector integration) ───
router.include_router(cloud_accounts.router, prefix="/cloud-accounts", tags=["Cloud Accounts"])
router.include_router(cloud_posture.router, prefix="/cloud-posture", tags=["Cloud Posture"])

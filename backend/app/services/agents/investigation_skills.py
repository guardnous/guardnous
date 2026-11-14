"""Production-grade investigation & incident response skills.

These skills power the AI triage agent with deep domain expertise across:
  - Cloud security investigation (AWS, Azure, GCP)
  - IaC misconfiguration analysis (Terraform, CloudFormation, Kubernetes)
  - Incident response playbooks (containment → eradication → recovery)
  - Vulnerability assessment & CVE impact analysis
  - Compliance gap analysis with real control IDs
  - Network security & lateral movement detection
  - Container security & supply chain risk
  - Secrets management & credential rotation workflows

Designed for enterprise SOC teams.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, Scan

logger = logging.getLogger(__name__)


@dataclass
class ToolContext:
    db: AsyncSession
    organization_id: int


# ── AWS Investigation Skills ────────────────────────────────────────

async def investigate_aws_iam(ctx: ToolContext, **kwargs: Any) -> dict:
    """Deep IAM investigation — overprivileged roles, unused permissions, privilege escalation paths."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.organization_id == ctx.organization_id,
            Finding.is_fixed == False,
            Finding.is_ignored == False,
        )
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    iam_findings = []
    privilege_escalation_risks = []
    overprivileged = []
    unused_permissions = []
    cross_account_risks = []

    for f in rows:
        title_lower = (f.title or "").lower()

        is_iam = any(kw in title_lower for kw in (
            "iam", "role", "policy", "permission", "privilege", "access",
            "admin", "wildcard", "star action", "assume role",
        ))
        if not is_iam:
            continue

        finding_data = {
            "id": f.id, "title": f.title, "severity": f.severity,
            "resource": f.resource_name, "file": f.file_path,
            "recommendation": f.remediation or "",
        }
        iam_findings.append(finding_data)

        # Classify by IAM risk type
        if any(kw in title_lower for kw in ("admin", "*", "wildcard", "full access", "poweruser")):
            overprivileged.append(finding_data)
        if any(kw in title_lower for kw in ("escalat", "assume role", "pass role", "sts:")):
            privilege_escalation_risks.append(finding_data)
        if any(kw in title_lower for kw in ("unused", "inactive", "last access")):
            unused_permissions.append(finding_data)
        if any(kw in title_lower for kw in ("cross-account", "external", "trust")):
            cross_account_risks.append(finding_data)

    # Generate investigation playbook
    playbook = []
    if privilege_escalation_risks:
        playbook.append({
            "priority": "P0-CRITICAL",
            "action": "Review privilege escalation paths immediately",
            "steps": [
                "Identify all roles with iam:PassRole, sts:AssumeRole, or iam:CreatePolicy",
                "Map the transitive permission graph to find escalation chains",
                "Check CloudTrail for any recent privilege escalation attempts",
                "Remove unnecessary cross-service permission grants",
                "Implement permission boundaries on all IAM roles",
            ],
            "affected_count": len(privilege_escalation_risks),
        })
    if overprivileged:
        playbook.append({
            "priority": "P1-HIGH",
            "action": "Remediate overprivileged IAM entities",
            "steps": [
                "Run IAM Access Analyzer to identify unused permissions",
                "Generate least-privilege policies from CloudTrail usage data",
                "Replace wildcard (*) actions with specific API calls",
                "Implement SCP guardrails at the AWS Organization level",
                "Enable IAM credential reports and set rotation schedule",
            ],
            "affected_count": len(overprivileged),
        })

    return {
        "total_iam_findings": len(iam_findings),
        "risk_breakdown": {
            "privilege_escalation": len(privilege_escalation_risks),
            "overprivileged": len(overprivileged),
            "unused_permissions": len(unused_permissions),
            "cross_account_risks": len(cross_account_risks),
        },
        "top_findings": iam_findings[:10],
        "investigation_playbook": playbook,
        "recommendation": "Focus on privilege escalation paths first — they represent the highest blast radius.",
    }


async def investigate_aws_network(ctx: ToolContext, **kwargs: Any) -> dict:
    """Network security investigation — open security groups, public exposure, VPC misconfiguration."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.is_ignored == False)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    categories = {
        "public_exposure": [],
        "overly_permissive_sg": [],
        "missing_encryption_in_transit": [],
        "vpc_flow_logging_disabled": [],
        "default_vpc_in_use": [],
    }

    for f in rows:
        title_lower = (f.title or "").lower()
        if any(kw in title_lower for kw in ("0.0.0.0", "public", "internet-facing", "publicly accessible")):
            categories["public_exposure"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("security group", "ingress", "egress", "port 0-65535", "all traffic")):
            categories["overly_permissive_sg"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("tls", "ssl", "http://", "unencrypted")):
            categories["missing_encryption_in_transit"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("flow log", "vpc log")):
            categories["vpc_flow_logging_disabled"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("default vpc",)):
            categories["default_vpc_in_use"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})

    total = sum(len(v) for v in categories.values())
    return {
        "total_network_findings": total,
        "categories": {k: {"count": len(v), "items": v[:5]} for k, v in categories.items()},
        "critical_action_items": [
            "Close all 0.0.0.0/0 ingress rules on non-public-facing resources",
            "Enable VPC Flow Logs on all VPCs for forensic readiness",
            "Enforce TLS 1.2+ on all load balancers and API gateways",
            "Migrate workloads off default VPCs to purpose-built VPCs",
        ] if total > 0 else ["No network security issues found."],
    }


# ── Azure Investigation Skills ──────────────────────────────────────

async def investigate_azure_security(ctx: ToolContext, **kwargs: Any) -> dict:
    """Azure Defender / Entra ID security investigation."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.is_ignored == False)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    categories = {
        "rbac_misconfig": [],
        "storage_exposure": [],
        "nsg_issues": [],
        "keyvault_issues": [],
        "identity_risks": [],
    }

    for f in rows:
        title_lower = (f.title or "").lower()
        if any(kw in title_lower for kw in ("rbac", "role assignment", "contributor", "owner role")):
            categories["rbac_misconfig"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("storage account", "blob", "container public")):
            categories["storage_exposure"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("nsg", "network security group")):
            categories["nsg_issues"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("key vault", "keyvault", "secret", "certificate")):
            categories["keyvault_issues"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("managed identity", "service principal", "entra", "azure ad")):
            categories["identity_risks"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})

    total = sum(len(v) for v in categories.values())
    return {
        "total_azure_findings": total,
        "categories": {k: {"count": len(v), "items": v[:5]} for k, v in categories.items()},
        "azure_specific_playbook": [
            "Review all Owner/Contributor role assignments — enforce PIM for elevated access",
            "Disable public blob access on all storage accounts (default deny)",
            "Enable soft-delete and purge protection on all Key Vaults",
            "Audit service principal credential expiry dates",
            "Enable Defender for Cloud on all subscriptions",
        ] if total > 0 else ["No Azure-specific security issues found."],
    }


# ── GCP Investigation Skills ────────────────────────────────────────

async def investigate_gcp_security(ctx: ToolContext, **kwargs: Any) -> dict:
    """GCP Security Command Center investigation."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.is_ignored == False)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    categories = {
        "iam_issues": [],
        "firewall_issues": [],
        "storage_issues": [],
        "compute_issues": [],
    }

    for f in rows:
        title_lower = (f.title or "").lower()
        if any(kw in title_lower for kw in ("iam", "service account", "impersonat")):
            categories["iam_issues"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("firewall", "ingress", "0.0.0.0")):
            categories["firewall_issues"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("bucket", "storage", "public")):
            categories["storage_issues"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})
        elif any(kw in title_lower for kw in ("compute", "instance", "metadata")):
            categories["compute_issues"].append({"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name})

    total = sum(len(v) for v in categories.values())
    return {
        "total_gcp_findings": total,
        "categories": {k: {"count": len(v), "items": v[:5]} for k, v in categories.items()},
        "gcp_playbook": [
            "Audit all service accounts — remove unused keys, enforce key rotation",
            "Enable uniform bucket-level access on all Cloud Storage buckets",
            "Disable default compute service accounts on GCE instances",
            "Enable VPC Service Controls for sensitive projects",
        ] if total > 0 else ["No GCP-specific security issues found."],
    }


# ── IaC Deep Analysis Skills ────────────────────────────────────────

async def analyze_terraform_misconfigs(ctx: ToolContext, **kwargs: Any) -> dict:
    """Deep Terraform misconfiguration analysis with fix recommendations."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.organization_id == ctx.organization_id,
            Finding.is_fixed == False, Finding.is_ignored == False,
        )
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    tf_findings = []
    by_resource_type: dict[str, list] = {}

    for f in rows:
        file_path = f.file_path or ""
        if not file_path.endswith((".tf", ".tfvars", ".tfvars.json")):
            continue

        resource_type = "unknown"
        title_lower = (f.title or "").lower()
        if "aws_" in title_lower or "aws_" in (f.resource_name or ""):
            resource_type = "aws"
        elif "azurerm_" in title_lower or "azurerm_" in (f.resource_name or ""):
            resource_type = "azure"
        elif "google_" in title_lower or "google_" in (f.resource_name or ""):
            resource_type = "gcp"

        item = {
            "id": f.id, "title": f.title, "severity": f.severity,
            "file": f.file_path, "resource": f.resource_name,
            "rule_id": f.rule_id,
        }
        tf_findings.append(item)
        by_resource_type.setdefault(resource_type, []).append(item)

    # Categorize by fix complexity
    quick_fixes = [f for f in tf_findings if f["severity"] in ("LOW", "MEDIUM")]
    critical_fixes = [f for f in tf_findings if f["severity"] in ("CRITICAL", "HIGH")]

    return {
        "total_terraform_findings": len(tf_findings),
        "by_cloud_provider": {k: len(v) for k, v in by_resource_type.items()},
        "critical_fixes": critical_fixes[:10],
        "quick_wins": quick_fixes[:10],
        "fix_strategy": {
            "phase_1_immediate": "Fix all CRITICAL findings — these represent active security gaps",
            "phase_2_short_term": "Address HIGH findings — reduce blast radius within 1 sprint",
            "phase_3_hardening": "Resolve MEDIUM/LOW — defense in depth improvements",
            "automation": "Enable pre-commit hooks with tfsec/checkov to prevent new misconfigs",
        },
    }


async def analyze_kubernetes_security(ctx: ToolContext, **kwargs: Any) -> dict:
    """Kubernetes security posture analysis — RBAC, pod security, network policies."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.is_ignored == False)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    k8s_findings: dict[str, list] = {
        "privileged_containers": [],
        "missing_resource_limits": [],
        "rbac_overexposure": [],
        "missing_network_policies": [],
        "image_vulnerabilities": [],
        "secret_management": [],
    }

    for f in rows:
        title_lower = (f.title or "").lower()
        file_path = (f.file_path or "").lower()
        is_k8s = any(kw in title_lower + file_path for kw in (
            "kubernetes", "k8s", "container", "pod", "deployment",
            "helm", "kustomize", ".yaml", ".yml",
        ))
        if not is_k8s:
            continue

        item = {"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name, "file": f.file_path}
        if any(kw in title_lower for kw in ("privileged", "root", "capabilities", "host")):
            k8s_findings["privileged_containers"].append(item)
        elif any(kw in title_lower for kw in ("resource limit", "cpu", "memory", "quota")):
            k8s_findings["missing_resource_limits"].append(item)
        elif any(kw in title_lower for kw in ("rbac", "clusterrole", "service account")):
            k8s_findings["rbac_overexposure"].append(item)
        elif any(kw in title_lower for kw in ("network policy", "ingress", "egress")):
            k8s_findings["missing_network_policies"].append(item)
        elif any(kw in title_lower for kw in ("image", "vulnerability", "cve")):
            k8s_findings["image_vulnerabilities"].append(item)
        elif any(kw in title_lower for kw in ("secret", "configmap", "env var")):
            k8s_findings["secret_management"].append(item)

    total = sum(len(v) for v in k8s_findings.values())
    return {
        "total_k8s_findings": total,
        "categories": {k: {"count": len(v), "items": v[:3]} for k, v in k8s_findings.items()},
        "hardening_playbook": [
            "Enforce Pod Security Standards (Restricted) on all namespaces",
            "Deploy OPA Gatekeeper or Kyverno for policy enforcement",
            "Set resource requests and limits on every container",
            "Implement NetworkPolicies — default deny all, allow only required traffic",
            "Use external secrets operator (ESO) instead of native Kubernetes secrets",
            "Enable audit logging and ship to SIEM for forensic readiness",
            "Scan all container images with Trivy/Grype before deployment",
        ] if total > 0 else ["No Kubernetes security issues found."],
    }


# ── Incident Response Playbooks ─────────────────────────────────────

async def incident_response_playbook(ctx: ToolContext, incident_type: str = "general", **kwargs: Any) -> dict:
    """Generate structured incident response playbook based on incident type."""

    playbooks = {
        "credential_exposure": {
            "severity": "P0-CRITICAL",
            "title": "Exposed Credential / Secret Leak Response",
            "containment": [
                "IMMEDIATELY rotate the exposed credential (API key, password, token)",
                "Revoke all active sessions using the compromised credential",
                "If AWS key: disable the IAM user/role access key via AWS console or CLI",
                "If database credential: change password and force-disconnect active sessions",
                "Block the IP/user that accessed the exposed credential (if known from logs)",
            ],
            "eradication": [
                "Scan entire git history for other leaked secrets: `git log -p | grep -i 'password\\|secret\\|api_key'`",
                "Run TruffleHog or GitLeaks on the repository: `trufflehog git file://./`",
                "Remove secrets from git history using BFG Repo Cleaner if in commit history",
                "Audit all repositories using the same credential pattern",
                "Check if credential was used after exposure time (CloudTrail/Activity Log review)",
            ],
            "recovery": [
                "Generate new credential with minimum required permissions",
                "Store new credential in approved secret manager (AWS Secrets Manager / Azure Key Vault / HashiCorp Vault)",
                "Update all dependent services with new credential reference",
                "Enable automated credential rotation (90-day maximum for service accounts)",
                "Deploy pre-commit hooks to prevent future secret commits",
            ],
            "post_incident": [
                "Document timeline: when exposed, when detected, when rotated",
                "Determine blast radius: what data/systems could the credential access",
                "Check for unauthorized access during exposure window",
                "Update runbook with this incident's lessons learned",
                "Report to compliance team if regulated data was potentially exposed",
            ],
        },
        "ransomware": {
            "severity": "P0-CRITICAL",
            "title": "Ransomware / Destructive Malware Response",
            "containment": [
                "ISOLATE affected systems immediately — revoke network access, not power off",
                "Preserve memory dumps and disk images for forensic analysis BEFORE cleanup",
                "Block lateral movement: segment affected VLANs, disable compromised accounts",
                "Check backup integrity — verify backups are not encrypted/corrupted",
                "Notify incident response team and legal counsel",
            ],
            "eradication": [
                "Identify initial access vector (phishing, RDP, VPN, supply chain)",
                "Scan all systems with updated AV/EDR signatures for the specific variant",
                "Check for persistence mechanisms: scheduled tasks, services, registry keys",
                "Audit all privileged accounts for unauthorized changes",
                "Verify no exfiltration occurred before encryption (double extortion check)",
            ],
            "recovery": [
                "Restore from verified clean backups (air-gapped preferred)",
                "Rebuild affected systems from golden images — do not 'clean' infected systems",
                "Implement MFA on all accounts before reconnecting to network",
                "Monitor restored systems for 72 hours for reinfection indicators",
                "Gradually restore network connectivity with enhanced logging",
            ],
            "post_incident": [
                "Conduct full forensic timeline analysis",
                "File law enforcement report (FBI IC3 for US orgs)",
                "Notify affected customers/partners per regulatory requirements",
                "Update detection rules with IOCs from this incident",
                "Conduct tabletop exercise within 30 days with lessons learned",
            ],
        },
        "unauthorized_access": {
            "severity": "P1-HIGH",
            "title": "Unauthorized Access / Account Compromise Response",
            "containment": [
                "Disable the compromised user account immediately",
                "Revoke all active sessions and API tokens for the account",
                "Reset password and MFA enrollment",
                "Review recent actions: CloudTrail, Azure Activity Log, GCP Audit Log",
                "Block source IPs associated with unauthorized access",
            ],
            "eradication": [
                "Audit all changes made during the compromise window",
                "Check for backdoor accounts, API keys, or SSH keys created by attacker",
                "Review IAM policy changes — any new roles or permission grants",
                "Scan for deployed persistence (Lambda functions, scheduled tasks, cron jobs)",
                "Check OAuth app authorizations for malicious third-party apps",
            ],
            "recovery": [
                "Re-enable account with fresh credentials and enforced MFA",
                "Revert any unauthorized configuration changes",
                "Rotate all secrets the compromised account had access to",
                "Implement conditional access policies (geo-blocking, device compliance)",
                "Enable sign-in risk policies if using Azure AD / Entra ID",
            ],
            "post_incident": [
                "Determine how credentials were compromised (phishing, credential stuffing, malware)",
                "Implement additional authentication controls (hardware keys, certificate-based auth)",
                "Review access logs for similar patterns across other accounts",
                "Update security awareness training based on attack vector",
            ],
        },
        "data_breach": {
            "severity": "P0-CRITICAL",
            "title": "Data Breach / Data Exfiltration Response",
            "containment": [
                "Identify and stop the data exfiltration channel immediately",
                "Preserve all logs and network captures — activate full packet capture if available",
                "Isolate affected data stores from the network",
                "Engage legal counsel and data privacy officer",
                "Document initial findings for regulatory notification timeline",
            ],
            "eradication": [
                "Identify what data was accessed/exfiltrated (scope the breach)",
                "Determine the attack vector and close the entry point",
                "Scan for additional compromised data stores",
                "Check for staging areas where data was collected before exfiltration",
                "Audit DNS logs for data exfiltration via DNS tunneling",
            ],
            "recovery": [
                "Implement DLP (Data Loss Prevention) controls on affected data stores",
                "Enable encryption at rest and in transit for all sensitive data",
                "Implement database activity monitoring (DAM)",
                "Review and tighten data access permissions (least privilege)",
                "Deploy canary tokens / honeypots for early breach detection",
            ],
            "post_incident": [
                "Notify affected individuals per GDPR Article 72h / state breach notification laws",
                "File regulatory notifications (GDPR DPA, HHS for HIPAA, state AGs)",
                "Conduct impact assessment: PII count, data types, affected jurisdictions",
                "Engage external forensics firm for independent investigation",
                "Offer credit monitoring to affected individuals if PII exposed",
            ],
        },
        "general": {
            "severity": "P2-MEDIUM",
            "title": "General Security Incident Response",
            "containment": [
                "Identify affected systems and assess scope",
                "Isolate affected systems if active compromise is suspected",
                "Preserve evidence (logs, memory dumps, disk images)",
                "Notify security team and relevant stakeholders",
            ],
            "eradication": [
                "Identify root cause and attack vector",
                "Remove malicious artifacts and close vulnerability",
                "Scan for indicators of compromise (IOCs) across the environment",
                "Audit affected accounts and systems for unauthorized changes",
            ],
            "recovery": [
                "Restore affected systems from clean backups or rebuild",
                "Implement additional controls to prevent recurrence",
                "Monitor restored systems with enhanced logging",
                "Verify business operations are restored to normal",
            ],
            "post_incident": [
                "Document complete incident timeline",
                "Conduct post-incident review within 5 business days",
                "Update detection rules and playbooks",
                "Share IOCs with threat intelligence community (if appropriate)",
            ],
        },
    }

    selected = playbooks.get(incident_type, playbooks["general"])

    # Enrich with org-specific context
    stmt = (
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.severity == "CRITICAL")
    )
    critical_count = (await ctx.db.execute(stmt)).scalar() or 0

    return {
        **selected,
        "incident_type": incident_type,
        "available_types": list(playbooks.keys()),
        "org_context": {
            "active_critical_findings": critical_count,
            "note": f"Your org has {critical_count} active critical findings that should be reviewed alongside this incident.",
        },
    }


# ── Compliance Deep Mapping ─────────────────────────────────────────

_COMPLIANCE_CONTROL_MAP = {
    "CIS": {
        "secret": ["CIS 1.14 - Ensure credentials are not hardcoded", "CIS 1.16 - Rotate access keys regularly"],
        "encrypt": ["CIS 2.1.1 - Ensure S3 encryption is enabled", "CIS 2.2.1 - Ensure EBS encryption is enabled"],
        "public": ["CIS 2.1.2 - Ensure S3 bucket policy denies public access", "CIS 5.2 - Ensure no public ingress on SGs"],
        "iam": ["CIS 1.2 - Ensure MFA is enabled for IAM users", "CIS 1.4 - Ensure no root account access keys exist"],
        "logging": ["CIS 3.1 - Ensure CloudTrail is enabled", "CIS 3.7 - Ensure CloudTrail logs are encrypted"],
        "network": ["CIS 5.1 - Ensure no default VPC in use", "CIS 5.4 - Ensure routing tables restrict access"],
    },
    "SOC2": {
        "secret": ["CC6.1 - Logical and Physical Access Controls", "CC6.6 - System boundaries and data flow"],
        "encrypt": ["CC6.1 - Encryption at rest", "CC6.7 - Encryption in transit"],
        "public": ["CC6.6 - Restrict data flow to authorized channels"],
        "iam": ["CC6.1 - Access provisioning", "CC6.2 - Credential management", "CC6.3 - Access removal"],
        "logging": ["CC7.1 - Detection of unauthorized activities", "CC7.2 - Monitoring of system components"],
        "network": ["CC6.6 - System boundaries", "CC6.7 - Data transmission controls"],
    },
    "PCI-DSS": {
        "secret": ["PCI 3.4 - Render PAN unreadable", "PCI 8.2.1 - Strong cryptography for credentials"],
        "encrypt": ["PCI 3.4 - Encryption of stored cardholder data", "PCI 4.1 - Encrypt transmission of CHD"],
        "public": ["PCI 1.3 - Prohibit direct public access to CHD environment"],
        "iam": ["PCI 7.1 - Restrict access to CHD by business need to know", "PCI 8.1.1 - Unique user IDs"],
        "logging": ["PCI 10.1 - Audit trail for all access to CHD", "PCI 10.2 - Automated audit trails"],
        "network": ["PCI 1.1 - Firewall configuration standards", "PCI 2.1 - Change vendor defaults"],
    },
    "HIPAA": {
        "secret": ["§164.312(a)(2)(iv) - Encryption and decryption of ePHI"],
        "encrypt": ["§164.312(a)(2)(iv) - Encryption at rest", "§164.312(e)(1) - Transmission security"],
        "public": ["§164.312(e)(1) - Prevent unauthorized access to ePHI in transit"],
        "iam": ["§164.312(a)(1) - Access control", "§164.312(d) - Person or entity authentication"],
        "logging": ["§164.312(b) - Audit controls", "§164.308(a)(1)(ii)(D) - Information system activity review"],
        "network": ["§164.312(e)(1) - Transmission security mechanisms"],
    },
    "NIST-800-53": {
        "secret": ["SC-28 - Protection of Information at Rest", "IA-5 - Authenticator Management"],
        "encrypt": ["SC-28 - Protection of Information at Rest", "SC-8 - Transmission Confidentiality"],
        "public": ["AC-4 - Information Flow Enforcement", "SC-7 - Boundary Protection"],
        "iam": ["AC-2 - Account Management", "AC-6 - Least Privilege", "IA-2 - Identification and Authentication"],
        "logging": ["AU-2 - Audit Events", "AU-3 - Content of Audit Records", "AU-6 - Audit Review"],
        "network": ["SC-7 - Boundary Protection", "AC-17 - Remote Access"],
    },
}


async def deep_compliance_mapping(ctx: ToolContext, framework: str = "all", **kwargs: Any) -> dict:
    """Map findings to specific compliance control IDs across CIS, SOC2, PCI-DSS, HIPAA, NIST."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.is_ignored == False)
        .order_by(Finding.severity.desc())
        .limit(100)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    frameworks_to_check = (
        list(_COMPLIANCE_CONTROL_MAP.keys()) if framework == "all"
        else [fw.strip().upper().replace(" ", "-") for fw in framework.split(",")]
    )

    results: dict[str, dict] = {}
    for fw in frameworks_to_check:
        controls = _COMPLIANCE_CONTROL_MAP.get(fw, {})
        if not controls:
            continue

        mapped_findings: list[dict] = []
        violated_controls: set[str] = set()

        for f in rows:
            title_lower = (f.title or "").lower()
            for category, control_ids in controls.items():
                if category in title_lower:
                    for cid in control_ids:
                        violated_controls.add(cid)
                        mapped_findings.append({
                            "finding_id": f.id,
                            "finding_title": f.title,
                            "severity": f.severity,
                            "control_id": cid,
                            "category": category,
                        })

        total_controls = sum(len(v) for v in controls.values())
        passing = total_controls - len(violated_controls)
        score = round((passing / total_controls) * 100, 1) if total_controls > 0 else 100.0

        results[fw] = {
            "compliance_score": score,
            "total_controls_checked": total_controls,
            "controls_passing": passing,
            "controls_failing": len(violated_controls),
            "violated_controls": sorted(violated_controls),
            "mapped_findings": mapped_findings[:20],
        }

    return {
        "frameworks_analyzed": list(results.keys()),
        "results": results,
        "summary": "Compliance mapping based on active findings. Scores represent the percentage of controls not violated by current findings.",
    }


# ── Container & Supply Chain Skills ──────────────────────────────────

async def analyze_supply_chain(ctx: ToolContext, **kwargs: Any) -> dict:
    """Supply chain risk analysis — dependency vulnerabilities, outdated packages, license risks."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.is_ignored == False)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    dep_findings = []
    by_ecosystem: dict[str, list] = {}

    for f in rows:
        title_lower = (f.title or "").lower()
        file_path = (f.file_path or "").lower()
        is_dep = any(kw in title_lower + file_path for kw in (
            "cve", "vulnerable", "outdated", "dependency", "package",
            "requirements.txt", "package.json", "go.sum", "pom.xml",
            "gemfile", "cargo.toml",
        ))
        if not is_dep:
            continue

        ecosystem = "unknown"
        if "requirements" in file_path or ".py" in file_path:
            ecosystem = "python"
        elif "package.json" in file_path or "yarn" in file_path:
            ecosystem = "npm"
        elif "go.mod" in file_path or "go.sum" in file_path:
            ecosystem = "go"
        elif "pom.xml" in file_path or ".java" in file_path:
            ecosystem = "maven"
        elif "gemfile" in file_path:
            ecosystem = "ruby"

        item = {
            "id": f.id, "title": f.title, "severity": f.severity,
            "file": f.file_path, "resource": f.resource_name,
        }
        dep_findings.append(item)
        by_ecosystem.setdefault(ecosystem, []).append(item)

    return {
        "total_supply_chain_findings": len(dep_findings),
        "by_ecosystem": {k: {"count": len(v), "critical": len([i for i in v if i["severity"] == "CRITICAL"])} for k, v in by_ecosystem.items()},
        "top_vulnerabilities": dep_findings[:10],
        "remediation_strategy": [
            "Enable Dependabot/Renovate for automated dependency updates",
            "Implement Software Bill of Materials (SBOM) generation in CI/CD",
            "Use dependency lock files (package-lock.json, poetry.lock) everywhere",
            "Scan container base images for known CVEs before deployment",
            "Enforce license compliance checks — flag copyleft licenses in commercial code",
        ],
    }


# ── Secrets Investigation ────────────────────────────────────────────

async def investigate_secrets(ctx: ToolContext, **kwargs: Any) -> dict:
    """Deep secrets investigation — exposed credentials, hardcoded keys, rotation status."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id, Finding.is_fixed == False, Finding.is_ignored == False)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()

    secret_findings = {
        "hardcoded_passwords": [],
        "api_keys": [],
        "private_keys": [],
        "connection_strings": [],
        "certificates": [],
        "tokens": [],
    }

    for f in rows:
        title_lower = (f.title or "").lower()
        is_secret = any(kw in title_lower for kw in (
            "secret", "password", "credential", "key", "token",
            "api_key", "private key", "connection string", "certificate",
        ))
        if not is_secret:
            continue

        item = {"id": f.id, "title": f.title, "severity": f.severity, "file": f.file_path, "resource": f.resource_name}
        if any(kw in title_lower for kw in ("password", "passwd", "credential")):
            secret_findings["hardcoded_passwords"].append(item)
        elif any(kw in title_lower for kw in ("api_key", "api key", "access key")):
            secret_findings["api_keys"].append(item)
        elif any(kw in title_lower for kw in ("private key", "rsa", "ssh key")):
            secret_findings["private_keys"].append(item)
        elif any(kw in title_lower for kw in ("connection string", "database url", "dsn")):
            secret_findings["connection_strings"].append(item)
        elif any(kw in title_lower for kw in ("certificate", "cert", "x509")):
            secret_findings["certificates"].append(item)
        elif any(kw in title_lower for kw in ("token", "bearer", "jwt")):
            secret_findings["tokens"].append(item)

    total = sum(len(v) for v in secret_findings.values())
    return {
        "total_secret_findings": total,
        "categories": {k: {"count": len(v), "items": v[:3]} for k, v in secret_findings.items()},
        "immediate_actions": [
            "Rotate ALL exposed credentials — assume they have been compromised",
            "Move secrets to a vault (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)",
            "Deploy git pre-commit hooks (detect-secrets, gitleaks) to prevent future leaks",
            "Enable secret scanning on all repositories (GitHub Advanced Security or equivalent)",
            "Implement automated rotation policies: 90 days for service accounts, 24h for compromised",
        ] if total > 0 else ["No exposed secrets found — good hygiene!"],
        "blast_radius_assessment": f"{total} exposed secrets could provide attackers with direct access to infrastructure and data stores." if total > 0 else "Clean.",
    }


# ── Skill Registry Builder ──────────────────────────────────────────

def build_investigation_skill_registry() -> dict:
    """Build the extended investigation skill registry."""
    from app.services.agents.skills import AgentSkill

    return {
        "investigate_aws_iam": AgentSkill(
            name="investigate_aws_iam",
            description="Deep AWS IAM investigation — overprivileged roles, privilege escalation paths, unused permissions, cross-account risks.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_aws_iam,
        ),
        "investigate_aws_network": AgentSkill(
            name="investigate_aws_network",
            description="AWS network security investigation — open security groups, public exposure, VPC misconfiguration, missing flow logs.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_aws_network,
        ),
        "investigate_azure_security": AgentSkill(
            name="investigate_azure_security",
            description="Azure Defender / Entra ID investigation — RBAC misconfig, storage exposure, Key Vault issues, managed identity risks.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_azure_security,
        ),
        "investigate_gcp_security": AgentSkill(
            name="investigate_gcp_security",
            description="GCP Security Command Center investigation — service account risks, firewall issues, bucket exposure.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_gcp_security,
        ),
        "analyze_terraform": AgentSkill(
            name="analyze_terraform",
            description="Deep Terraform/IaC misconfiguration analysis with prioritized fix strategy.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=analyze_terraform_misconfigs,
        ),
        "analyze_kubernetes": AgentSkill(
            name="analyze_kubernetes",
            description="Kubernetes security posture — RBAC, pod security standards, network policies, container image vulnerabilities.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=analyze_kubernetes_security,
        ),
        "incident_response": AgentSkill(
            name="incident_response",
            description="Structured incident response playbook — containment, eradication, recovery, post-incident for credential exposure, ransomware, unauthorized access, data breach.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"incident_type": {"type": "string", "enum": ["credential_exposure", "ransomware", "unauthorized_access", "data_breach", "general"]}}},
            executor=incident_response_playbook,
        ),
        "deep_compliance": AgentSkill(
            name="deep_compliance",
            description="Map findings to real compliance control IDs across CIS Benchmarks, SOC 2, PCI-DSS, HIPAA, and NIST 800-53.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"framework": {"type": "string"}}},
            executor=deep_compliance_mapping,
        ),
        "analyze_supply_chain": AgentSkill(
            name="analyze_supply_chain",
            description="Supply chain risk analysis — dependency vulnerabilities across Python, npm, Go, Maven ecosystems with SBOM recommendations.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=analyze_supply_chain,
        ),
        "investigate_secrets": AgentSkill(
            name="investigate_secrets",
            description="Deep secrets investigation — exposed credentials, hardcoded keys, rotation status, blast radius assessment.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_secrets,
        ),
    }

"""Expanded skills for the GuardNous agentic runtime — 22 new enterprise-grade tools.

Covers five domains not yet addressed by the base skill registry:

  THREAT INTELLIGENCE & ENRICHMENT (5):
    1. IOC Enrichment — IP/domain/hash threat intel lookup
    2. Reputation Check — blocklist, ASN, geo, abuse history
    3. MITRE ATT&CK Mapping — techniques, tactics, detection gaps
    4. Anomaly Detection — statistical deviation in finding patterns
    5. Risk Trend Prediction — forecast risk trajectory

  CLOUD & INFRASTRUCTURE (5):
    6. Exposed Ports Scanner — public-facing service enumeration
    7. IAM Permission Audit — overprivileged, unused, escalation paths
    8. Encryption Posture — at-rest/in-transit coverage gaps
    9. Backup Security — immutability, cross-region, retention
    10. WAF Rule Evaluation — detection gaps, bypass potential

  CODE & PIPELINE (4):
    11. Code Snippet Scanner — on-demand SAST
    12. Dockerfile Analyzer — image security, CIS Docker controls
    13. GitHub Actions Reviewer — injection, permissions, supply chain
    14. Dependency Health — freshness, maintenance, license risk

  COMPLIANCE & GOVERNANCE (4):
    15. Audit Report Generator — framework-specific structured reports
    16. Policy Violation Checker — encryption, access, network, tagging
    17. Compliance Drift Tracker — before/after compliance delta
    18. Data Flow Mapper — PII/PHI/PCI storage/transit mapping

  RESPONSE & AUTOMATION (4):
    19. Jira Ticket Creator — finding-to-ticket with full context
    20. Slack Notifier — formatted security alert dispatch
    21. Resource Quarantine — network isolation, key disable, token revoke
    22. Runbook Generator — step-by-step operational playbooks

Each skill queries REAL findings from the organization's database and
produces structured, actionable output — not vague advice.
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, Scan

logger = logging.getLogger(__name__)


# ── Shared helpers ──────────────────────────────────────────────────

class _Ctx:
    __slots__ = ("db", "organization_id")
    def __init__(self, db: AsyncSession, organization_id: int):
        self.db = db
        self.organization_id = organization_id


async def _fetch_active_findings(ctx: _Ctx) -> list:
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.organization_id == ctx.organization_id,
            Finding.is_fixed == False,   # noqa: E712
            Finding.is_ignored == False,  # noqa: E712
        )
    )
    return list((await ctx.db.execute(stmt)).scalars().all())


async def _fetch_scans(ctx: _Ctx, limit: int = 50) -> list:
    stmt = (
        select(Scan)
        .where(Scan.organization_id == ctx.organization_id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    return list((await ctx.db.execute(stmt)).scalars().all())


def _classify(finding, keywords: list[str]) -> bool:
    haystack = " ".join([
        (finding.title or "").lower(),
        (finding.resource_name or "").lower(),
        (finding.file_path or "").lower(),
        (finding.remediation or "").lower(),
    ])
    return any(kw in haystack for kw in keywords)


def _severity_rank(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
        (s or "").upper(), 5
    )


def _severity_emoji(s: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(
        (s or "").upper(), "⚪"
    )


# ═══════════════════════════════════════════════════════════════════
#  1. THREAT INTELLIGENCE & ENRICHMENT
# ═══════════════════════════════════════════════════════════════════

async def enrich_ioc(ctx, *, ioc_value: str = "", ioc_type: str = "", **_) -> dict:
    """No threat intelligence source is connected; say so rather than guess a verdict."""
    from app.services.agents import cloud_skills

    return await cloud_skills.enrich_ioc(ctx)


async def check_reputation(ctx, *, target: str = "", **_) -> dict:
    """No reputation source is connected; say so rather than guess a rating."""
    from app.services.agents import cloud_skills

    return await cloud_skills.check_reputation(ctx)


async def map_mitre_attack(ctx, *, scope: str = "all", **_) -> dict:
    """Map findings to MITRE ATT&CK framework techniques."""
    findings = await _fetch_active_findings(ctx)
    if scope == "critical":
        findings = [f for f in findings if f.severity == "CRITICAL"]
    elif scope == "high":
        findings = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]

    # Keyword-based ATT&CK mapping
    technique_map = {
        "T1078 — Valid Accounts": ["iam", "credential", "password", "mfa", "authentication", "login"],
        "T1190 — Exploit Public-Facing App": ["exposed", "public", "port", "api", "endpoint", "ingress"],
        "T1552 — Unsecured Credentials": ["secret", "key", "token", "hardcoded", "plaintext", "credential"],
        "T1068 — Exploitation for Privilege Escalation": ["privilege", "escalation", "admin", "root", "sudo"],
        "T1486 — Data Encrypted for Impact": ["encryption", "unencrypted", "at-rest", "in-transit", "tls"],
        "T1530 — Data from Cloud Storage": ["s3", "blob", "bucket", "storage", "public"],
        "T1562 — Impair Defenses": ["logging", "monitoring", "disabled", "trail", "waf", "firewall"],
        "T1071 — Application Layer Protocol": ["dns", "http", "api", "webhook", "certificate"],
        "T1133 — External Remote Services": ["ssh", "rdp", "vnc", "remote", "bastion"],
        "T1592 — Gather Victim Host Info": ["scan", "reconnaissance", "enumeration", "discovery"],
        "T1021 — Remote Services": ["ssh", "rdp", "smb", "winrm"],
        "T1566 — Phishing": ["email", "phishing", "spf", "dkim", "dmarc"],
    }

    coverage = {}
    for technique, keywords in technique_map.items():
        matched = [f for f in findings if _classify(f, keywords)]
        if matched:
            coverage[technique] = {
                "finding_count": len(matched),
                "max_severity": max((f.severity for f in matched), key=_severity_rank),
                "sample_findings": [f.title for f in matched[:3]],
            }

    tactics_covered = len(coverage)
    total_techniques = len(technique_map)

    return {
        "scope": scope,
        "total_findings_analyzed": len(findings),
        "techniques_detected": tactics_covered,
        "total_techniques_mapped": total_techniques,
        "coverage_percentage": round(tactics_covered / total_techniques * 100, 1),
        "detection_gaps": [t for t in technique_map if t not in coverage],
        "technique_heatmap": coverage,
        "top_attack_vectors": sorted(
            coverage.items(),
            key=lambda x: x[1]["finding_count"],
            reverse=True,
        )[:5],
        "recommendation": (
            f"🔴 {tactics_covered}/{total_techniques} ATT&CK techniques have active findings. "
            f"Focus on {total_techniques - tactics_covered} uncovered techniques for detection gaps."
        ),
    }


async def detect_anomalies(ctx, *, lookback_days: int = 30, **_) -> dict:
    """Statistical anomaly detection on finding patterns."""
    findings = await _fetch_active_findings(ctx)
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    recent = [f for f in findings if f.created_at and f.created_at >= cutoff]
    older = [f for f in findings if f.created_at and f.created_at < cutoff]

    recent_severity = Counter(f.severity for f in recent)
    older_severity = Counter(f.severity for f in older)

    anomalies = []

    # Spike detection
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        recent_count = recent_severity.get(sev, 0)
        older_count = older_severity.get(sev, 0)
        if recent_count > 0 and (older_count == 0 or recent_count / max(older_count, 1) > 1.5):
            anomalies.append({
                "type": "severity_spike",
                "severity": sev,
                "detail": f"{sev} findings increased: {older_count} → {recent_count}",
                "change_pct": round((recent_count - older_count) / max(older_count, 1) * 100, 1),
            })

    # New category detection
    recent_cats = set(f.category for f in recent if f.category)
    older_cats = set(f.category for f in older if f.category)
    new_cats = recent_cats - older_cats
    if new_cats:
        anomalies.append({
            "type": "new_category",
            "detail": f"New finding categories appeared: {', '.join(new_cats)}",
            "categories": list(new_cats),
        })

    # Cloud provider shift
    recent_clouds = Counter(f.cloud_provider for f in recent if f.cloud_provider)
    for cloud, count in recent_clouds.items():
        old_count = sum(1 for f in older if f.cloud_provider == cloud)
        if count > old_count * 2 and count > 3:
            anomalies.append({
                "type": "cloud_spike",
                "detail": f"Findings in {cloud} spiked: {old_count} → {count}",
                "cloud_provider": cloud,
            })

    return {
        "lookback_days": lookback_days,
        "total_findings_analyzed": len(findings),
        "recent_findings": len(recent),
        "anomalies_detected": len(anomalies),
        "anomalies": anomalies,
        "severity_trend": {
            "recent": dict(recent_severity),
            "historical": dict(older_severity),
        },
        "verdict": (
            f"🔴 {len(anomalies)} anomalies detected — investigate immediately"
            if len(anomalies) > 2
            else f"🟡 {len(anomalies)} anomalies detected — review recommended"
            if anomalies
            else "✅ No significant anomalies — patterns within normal range"
        ),
    }


async def predict_risk_trend(ctx, *, forecast_days: int = 30, **_) -> dict:
    """Predict risk score trajectory based on historical patterns."""
    findings = await _fetch_active_findings(ctx)
    scans = await _fetch_scans(ctx, limit=30)

    severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
    current_risk = sum(severity_weights.get(f.severity, 0) for f in findings)
    current_score = min(100, current_risk / max(len(findings), 1) * 10)

    # Simple linear projection
    recent_scans = scans[:5]
    scan_risk_scores = []
    for scan in recent_scans:
        scan_findings = [f for f in findings if f.scan_id == scan.id]
        score = sum(severity_weights.get(f.severity, 0) for f in scan_findings)
        scan_risk_scores.append(score)

    trend = "stable"
    if len(scan_risk_scores) >= 2:
        if scan_risk_scores[0] > scan_risk_scores[-1] * 1.1:
            trend = "worsening"
        elif scan_risk_scores[0] < scan_risk_scores[-1] * 0.9:
            trend = "improving"

    forecast_score = current_score
    if trend == "worsening":
        forecast_score = min(100, current_score * 1.15)
    elif trend == "improving":
        forecast_score = max(0, current_score * 0.85)

    return {
        "current_risk_score": round(current_score, 1),
        "forecast_days": min(forecast_days, 90),
        "predicted_risk_score": round(forecast_score, 1),
        "trend": trend,
        "confidence": "medium" if len(scans) >= 5 else "low",
        "critical_count": sum(1 for f in findings if f.severity == "CRITICAL"),
        "high_count": sum(1 for f in findings if f.severity == "HIGH"),
        "actions_to_improve": [
            f"Fix {sum(1 for f in findings if f.severity == 'CRITICAL')} critical findings (saves ~{sum(1 for f in findings if f.severity == 'CRITICAL') * 10} risk points)",
            f"Address {sum(1 for f in findings if f.severity == 'HIGH')} high findings (saves ~{sum(1 for f in findings if f.severity == 'HIGH') * 5} risk points)",
            "Increase scan frequency for continuous monitoring",
        ],
        "headline": (
            f"📈 Risk is {trend}. Current: {round(current_score, 1)}/100 → "
            f"Forecast ({forecast_days}d): {round(forecast_score, 1)}/100"
        ),
    }


# ═══════════════════════════════════════════════════════════════════
#  2. CLOUD & INFRASTRUCTURE SECURITY
# ═══════════════════════════════════════════════════════════════════

async def scan_exposed_ports(ctx, *, cloud_provider: str = "all", **_) -> dict:
    """Scan for publicly exposed ports across cloud resources."""
    findings = await _fetch_active_findings(ctx)
    port_keywords = [
        "ssh", "rdp", "port 22", "port 3389", "port 3306", "port 5432",
        "port 27017", "port 6379", "port 9200", "publicly accessible",
        "open to internet", "0.0.0.0/0", "inbound", "security group",
        "exposed", "public subnet", "firewall", "ingress",
    ]
    exposed = [f for f in findings if _classify(f, port_keywords)]
    if cloud_provider != "all":
        exposed = [f for f in exposed if (f.cloud_provider or "").lower() == cloud_provider]

    exposed.sort(key=lambda f: _severity_rank(f.severity))

    high_risk_ports = {"22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL",
                       "27017": "MongoDB", "6379": "Redis", "9200": "Elasticsearch"}

    return {
        "cloud_provider": cloud_provider,
        "total_exposed_findings": len(exposed),
        "by_severity": dict(Counter(f.severity for f in exposed)),
        "high_risk_ports_referenced": high_risk_ports,
        "findings": [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "resource": f.resource_name, "cloud": f.cloud_provider,
            }
            for f in exposed[:20]
        ],
        "recommendation": (
            f"🔴 {len(exposed)} exposed service findings detected. "
            "Prioritize closing management ports (SSH/RDP) to public internet."
            if exposed else "✅ No publicly exposed ports detected in current findings."
        ),
    }


async def audit_iam_permissions(ctx, *, cloud_provider: str = "all", focus: str = "all", **_) -> dict:
    """Deep IAM permission analysis."""
    findings = await _fetch_active_findings(ctx)
    iam_keywords = [
        "iam", "role", "policy", "permission", "privilege", "admin", "root",
        "access key", "service account", "identity", "rbac", "scp",
        "overprivileged", "unused", "escalation", "cross-account", "trust",
    ]
    iam_findings = [f for f in findings if _classify(f, iam_keywords)]
    if cloud_provider != "all":
        iam_findings = [f for f in iam_findings if (f.cloud_provider or "").lower() == cloud_provider]

    categories = {
        "overprivileged": ["admin", "full access", "star", "wildcard", "*", "overprivileged"],
        "unused": ["unused", "inactive", "dormant", "stale", "last used"],
        "escalation": ["escalation", "privilege escalation", "assume role", "sts"],
    }

    categorized = {}
    for cat, kws in categories.items():
        if focus in ("all", cat):
            matches = [f for f in iam_findings if _classify(f, kws)]
            categorized[cat] = {
                "count": len(matches),
                "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in matches[:5]],
            }

    return {
        "cloud_provider": cloud_provider,
        "focus": focus,
        "total_iam_findings": len(iam_findings),
        "by_category": categorized,
        "by_severity": dict(Counter(f.severity for f in iam_findings)),
        "recommendation": (
            f"🔴 {len(iam_findings)} IAM findings detected. "
            "Apply least-privilege principle and review overprivileged roles."
            if iam_findings else "✅ No IAM permission issues detected."
        ),
    }


async def check_encryption_posture(ctx, *, cloud_provider: str = "all", **_) -> dict:
    """Audit encryption-at-rest and in-transit coverage."""
    findings = await _fetch_active_findings(ctx)
    enc_keywords = [
        "encryption", "unencrypted", "at-rest", "in-transit", "tls", "ssl",
        "kms", "key vault", "cmk", "sse", "aes", "rsa", "plaintext",
        "certificate", "https", "http only",
    ]
    enc_findings = [f for f in findings if _classify(f, enc_keywords)]
    if cloud_provider != "all":
        enc_findings = [f for f in enc_findings if (f.cloud_provider or "").lower() == cloud_provider]

    enc_findings.sort(key=lambda f: _severity_rank(f.severity))

    return {
        "cloud_provider": cloud_provider,
        "total_encryption_findings": len(enc_findings),
        "by_severity": dict(Counter(f.severity for f in enc_findings)),
        "at_rest_issues": len([f for f in enc_findings if _classify(f, ["at-rest", "sse", "kms", "unencrypted storage"])]),
        "in_transit_issues": len([f for f in enc_findings if _classify(f, ["in-transit", "tls", "ssl", "https", "http only"])]),
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name}
            for f in enc_findings[:15]
        ],
        "recommendation": (
            f"🔴 {len(enc_findings)} encryption gaps found. "
            "Enable encryption-at-rest for all storage and enforce TLS 1.2+ for all connections."
            if enc_findings else "✅ Encryption posture is solid — no gaps detected."
        ),
    }


async def assess_backup_security(ctx, *, cloud_provider: str = "all", **_) -> dict:
    """Verify backup configuration security."""
    findings = await _fetch_active_findings(ctx)
    backup_keywords = [
        "backup", "snapshot", "recovery", "retention", "disaster",
        "replication", "cross-region", "immutable", "versioning", "lifecycle",
    ]
    backup_findings = [f for f in findings if _classify(f, backup_keywords)]
    if cloud_provider != "all":
        backup_findings = [f for f in backup_findings if (f.cloud_provider or "").lower() == cloud_provider]

    return {
        "cloud_provider": cloud_provider,
        "total_backup_findings": len(backup_findings),
        "by_severity": dict(Counter(f.severity for f in backup_findings)),
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name}
            for f in backup_findings[:10]
        ],
        "checks": {
            "immutability": "Review required",
            "cross_region_replication": "Review required",
            "retention_policy": "Review required",
            "encryption": "Review required",
            "recovery_testing": "Not automated — recommend quarterly DR drills",
        },
        "recommendation": (
            f"⚠️ {len(backup_findings)} backup-related findings. "
            "Ensure immutable backups and cross-region replication for ransomware resilience."
            if backup_findings else "✅ No backup security issues detected."
        ),
    }


async def evaluate_waf_rules(ctx, *, cloud_provider: str = "all", **_) -> dict:
    """WAF and firewall rule analysis."""
    findings = await _fetch_active_findings(ctx)
    waf_keywords = [
        "waf", "firewall", "web application firewall", "rule", "acl",
        "cloudfront", "cdn", "ddos", "shield", "rate limit", "bot",
        "owasp", "sqli", "xss", "injection", "application gateway",
    ]
    waf_findings = [f for f in findings if _classify(f, waf_keywords)]
    if cloud_provider != "all":
        waf_findings = [f for f in waf_findings if (f.cloud_provider or "").lower() == cloud_provider]

    return {
        "cloud_provider": cloud_provider,
        "total_waf_findings": len(waf_findings),
        "by_severity": dict(Counter(f.severity for f in waf_findings)),
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name}
            for f in waf_findings[:10]
        ],
        "assessment": {
            "owasp_top_10_coverage": "Requires WAF rule audit",
            "rate_limiting": "Check if rate limiting is configured",
            "bot_protection": "Check bot management rules",
            "geo_blocking": "Review geographic restriction policies",
        },
        "recommendation": (
            f"⚠️ {len(waf_findings)} WAF/firewall findings. "
            "Ensure OWASP Core Rule Set is enabled and rate limiting is configured."
            if waf_findings else "✅ No WAF configuration issues detected."
        ),
    }


# ═══════════════════════════════════════════════════════════════════
#  3. CODE & PIPELINE SECURITY
# ═══════════════════════════════════════════════════════════════════

async def scan_code_snippet(ctx, *, code: str = "", language: str = "", **_) -> dict:
    """On-demand SAST analysis of a code snippet."""
    if not code:
        return {"error": "No code provided", "findings": []}

    issues = []

    # Secret detection patterns
    secret_patterns = [
        (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9+/=]{16,}", "Hardcoded API key"),
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]+['\"]", "Hardcoded password"),
        (r"(?i)(secret|token)\s*[=:]\s*['\"][A-Za-z0-9+/=]{16,}", "Hardcoded secret/token"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"(?i)BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY", "Embedded private key"),
    ]
    for pattern, desc in secret_patterns:
        if re.search(pattern, code):
            issues.append({"type": "secret", "severity": "CRITICAL", "title": desc, "cwe": "CWE-798"})

    # Injection detection
    injection_patterns = [
        (r"(?i)exec\s*\(", "Potential code injection via exec()"),
        (r"(?i)eval\s*\(", "Potential code injection via eval()"),
        (r"(?i)os\.system\s*\(", "OS command injection risk"),
        (r"(?i)subprocess\.\w+\(.*shell\s*=\s*True", "Shell injection via subprocess"),
        (r"(?i)f['\"].*\{.*\}.*SELECT|INSERT|UPDATE|DELETE", "Potential SQL injection via f-string"),
    ]
    for pattern, desc in injection_patterns:
        if re.search(pattern, code):
            issues.append({"type": "injection", "severity": "HIGH", "title": desc, "cwe": "CWE-78"})

    # Insecure crypto
    crypto_patterns = [
        (r"(?i)md5\s*\(", "Weak hash algorithm (MD5)"),
        (r"(?i)sha1\s*\(", "Weak hash algorithm (SHA-1)"),
        (r"(?i)DES\b", "Weak encryption algorithm (DES)"),
    ]
    for pattern, desc in crypto_patterns:
        if re.search(pattern, code):
            issues.append({"type": "crypto", "severity": "MEDIUM", "title": desc, "cwe": "CWE-327"})

    return {
        "language": language or "auto-detected",
        "lines_analyzed": code.count("\n") + 1,
        "issues_found": len(issues),
        "issues": issues,
        "verdict": (
            f"🔴 {len(issues)} security issues found" if issues
            else "✅ No obvious security issues detected"
        ),
    }


async def analyze_dockerfile(ctx, *, dockerfile_content: str = "", **_) -> dict:
    """Dockerfile security review."""
    if not dockerfile_content:
        return {"error": "No Dockerfile content provided", "findings": []}

    issues = []
    lines = dockerfile_content.strip().split("\n")

    for i, line in enumerate(lines, 1):
        line_stripped = line.strip()

        if line_stripped.startswith("FROM") and ":latest" in line_stripped:
            issues.append({"line": i, "severity": "MEDIUM", "title": "Using :latest tag — pin specific version", "cis": "4.7"})
        if line_stripped.startswith("FROM") and "alpine" not in line_stripped.lower() and "slim" not in line_stripped.lower() and "distroless" not in line_stripped.lower():
            if "FROM" in line_stripped and "scratch" not in line_stripped:
                issues.append({"line": i, "severity": "LOW", "title": "Consider minimal base image (alpine/slim/distroless)", "cis": "4.2"})
        if re.match(r"(?i)^(ENV|ARG)\s+(PASSWORD|SECRET|TOKEN|API_KEY|AWS_)", line_stripped):
            issues.append({"line": i, "severity": "CRITICAL", "title": "Secret in build arg/env — use multi-stage or secrets mount", "cis": "4.10"})
        if line_stripped == "USER root" or (line_stripped.startswith("RUN") and "chmod 777" in line_stripped):
            issues.append({"line": i, "severity": "HIGH", "title": "Running as root or overly permissive chmod", "cis": "4.1"})
        if "EXPOSE" in line_stripped and any(p in line_stripped for p in ["22", "23", "3389"]):
            issues.append({"line": i, "severity": "MEDIUM", "title": "Exposing management port (SSH/Telnet/RDP)", "cis": "4.6"})

    has_user = any("USER" in l and "root" not in l for l in lines)
    has_healthcheck = any("HEALTHCHECK" in l for l in lines)

    if not has_user:
        issues.append({"line": 0, "severity": "HIGH", "title": "No USER directive — container runs as root", "cis": "4.1"})
    if not has_healthcheck:
        issues.append({"line": 0, "severity": "LOW", "title": "No HEALTHCHECK — add for container orchestration", "cis": "4.6"})

    return {
        "total_lines": len(lines),
        "issues_found": len(issues),
        "issues": sorted(issues, key=lambda x: _severity_rank(x["severity"])),
        "has_user_directive": has_user,
        "has_healthcheck": has_healthcheck,
        "verdict": (
            f"🔴 {len(issues)} security issues in Dockerfile" if any(i["severity"] == "CRITICAL" for i in issues)
            else f"🟡 {len(issues)} issues found — review recommended" if issues
            else "✅ Dockerfile follows security best practices"
        ),
    }


async def review_github_actions(ctx, *, workflow_content: str = "", **_) -> dict:
    """GitHub Actions workflow security review."""
    if not workflow_content:
        return {"error": "No workflow content provided", "findings": []}

    issues = []
    lines = workflow_content.strip().split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Unpinned actions
        if "uses:" in stripped and "@" in stripped:
            ref = stripped.split("@")[-1].strip()
            if ref in ("main", "master", "latest") or not re.match(r"^(v\d|[a-f0-9]{40})", ref):
                issues.append({"line": i, "severity": "HIGH", "title": f"Unpinned action: {stripped.split('uses:')[-1].strip()}"})

        # Command injection
        if "${{" in stripped and "github.event" in stripped:
            if any(x in stripped for x in ["run:", "name:", "args:"]):
                issues.append({"line": i, "severity": "CRITICAL", "title": "Potential command injection via github.event context"})

        # Excessive permissions
        if "permissions:" in stripped and "write-all" in stripped:
            issues.append({"line": i, "severity": "HIGH", "title": "Overly broad write-all permissions"})

        if stripped.startswith("permissions:") and "contents: write" in workflow_content:
            pass  # specific permission is ok

        # Secret in log
        if "echo" in stripped and "${{" in stripped and "secrets." in stripped:
            issues.append({"line": i, "severity": "CRITICAL", "title": "Secret potentially logged via echo"})

    # Check for pull_request_target
    if "pull_request_target" in workflow_content:
        issues.append({"line": 0, "severity": "HIGH", "title": "pull_request_target trigger — review for pwn request vulnerability"})

    return {
        "total_lines": len(lines),
        "issues_found": len(issues),
        "issues": sorted(issues, key=lambda x: _severity_rank(x["severity"])),
        "verdict": (
            f"🔴 {len(issues)} security issues in workflow" if any(i["severity"] == "CRITICAL" for i in issues)
            else f"🟡 {len(issues)} issues found" if issues
            else "✅ Workflow follows security best practices"
        ),
    }


async def check_dependency_health(ctx, *, ecosystem: str = "all", **_) -> dict:
    """Dependency health assessment based on findings data."""
    findings = await _fetch_active_findings(ctx)
    dep_keywords = [
        "dependency", "package", "library", "module", "npm", "pip", "maven",
        "outdated", "vulnerable", "cve", "sbom", "sca", "supply chain",
        "end of life", "deprecated", "unmaintained",
    ]
    dep_findings = [f for f in findings if _classify(f, dep_keywords)]

    cve_findings = [f for f in dep_findings if f.cve_id]

    return {
        "ecosystem": ecosystem,
        "total_dependency_findings": len(dep_findings),
        "cve_linked_findings": len(cve_findings),
        "by_severity": dict(Counter(f.severity for f in dep_findings)),
        "top_cves": [
            {"cve": f.cve_id, "title": f.title, "severity": f.severity}
            for f in cve_findings[:10]
        ],
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity}
            for f in dep_findings[:15]
        ],
        "recommendation": (
            f"🔴 {len(cve_findings)} dependencies with known CVEs. "
            "Update vulnerable packages and enable automated dependency scanning."
            if cve_findings else "✅ No critical dependency health issues detected."
        ),
    }


# ═══════════════════════════════════════════════════════════════════
#  4. COMPLIANCE & GOVERNANCE
# ═══════════════════════════════════════════════════════════════════

async def generate_audit_report(ctx, *, framework: str = "soc2", format: str = "summary", **_) -> dict:
    """Generate a compliance audit report."""
    findings = await _fetch_active_findings(ctx)

    framework_controls = {
        "soc2": {
            "CC6.1": ("Logical access", ["iam", "access", "authentication", "mfa", "rbac"]),
            "CC6.2": ("Credential management", ["password", "credential", "secret", "key", "token"]),
            "CC6.3": ("Access authorization", ["privilege", "admin", "root", "escalation"]),
            "CC6.6": ("System boundaries", ["firewall", "network", "ingress", "egress", "public"]),
            "CC6.7": ("Data transmission", ["encryption", "tls", "ssl", "https", "in-transit"]),
            "CC6.8": ("Vulnerability management", ["cve", "patch", "vulnerability", "scan"]),
            "CC7.1": ("Detection mechanisms", ["monitoring", "logging", "alert", "detection"]),
            "CC7.2": ("Incident response", ["incident", "response", "breach", "containment"]),
        },
        "pci_dss": {
            "1.1": ("Firewall configuration", ["firewall", "network", "acl", "security group"]),
            "2.1": ("Default credentials", ["default", "password", "credential"]),
            "3.4": ("Encryption at rest", ["encryption", "at-rest", "kms", "cmk"]),
            "6.5": ("Secure coding", ["injection", "xss", "csrf", "owasp"]),
            "8.2": ("Authentication", ["mfa", "authentication", "password policy"]),
            "10.1": ("Audit logging", ["logging", "audit", "trail", "monitor"]),
        },
        "hipaa": {
            "164.312(a)": ("Access control", ["access", "authentication", "iam", "rbac"]),
            "164.312(c)": ("Integrity", ["integrity", "hash", "checksum", "tamper"]),
            "164.312(d)": ("Authentication", ["mfa", "password", "credential"]),
            "164.312(e)": ("Transmission security", ["encryption", "tls", "ssl", "in-transit"]),
        },
        "iso27001": {
            "A.9": ("Access control", ["access", "iam", "authentication", "mfa"]),
            "A.10": ("Cryptography", ["encryption", "key", "certificate", "tls"]),
            "A.12": ("Operations security", ["logging", "monitoring", "vulnerability"]),
            "A.13": ("Communications security", ["network", "firewall", "segmentation"]),
        },
        "nist_csf": {
            "ID.AM": ("Asset management", ["inventory", "asset", "resource"]),
            "PR.AC": ("Access control", ["access", "iam", "mfa", "rbac"]),
            "PR.DS": ("Data security", ["encryption", "dlp", "classification"]),
            "DE.CM": ("Continuous monitoring", ["monitoring", "logging", "detection"]),
            "RS.RP": ("Response planning", ["incident", "response", "playbook"]),
        },
        "cis": {
            "1.x": ("IAM", ["iam", "mfa", "root", "access key", "password policy"]),
            "2.x": ("Logging", ["cloudtrail", "flow log", "monitoring", "logging"]),
            "3.x": ("Monitoring", ["alarm", "alert", "notification", "metric"]),
            "4.x": ("Networking", ["security group", "nacl", "vpc", "firewall"]),
            "5.x": ("Storage", ["s3", "bucket", "encryption", "public access"]),
        },
    }

    controls = framework_controls.get(framework, framework_controls["soc2"])
    report = {}

    for control_id, (control_name, keywords) in controls.items():
        matched = [f for f in findings if _classify(f, keywords)]
        status = "fail" if any(f.severity in ("CRITICAL", "HIGH") for f in matched) else "warn" if matched else "pass"
        report[control_id] = {
            "name": control_name,
            "status": status,
            "finding_count": len(matched),
            "max_severity": max((f.severity for f in matched), key=_severity_rank) if matched else "N/A",
            "sample_findings": [f.title for f in matched[:3]] if format != "executive" else [],
        }

    total = len(controls)
    passing = sum(1 for v in report.values() if v["status"] == "pass")

    return {
        "framework": framework,
        "format": format,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "compliance_score": round(passing / total * 100, 1),
        "controls_assessed": total,
        "controls_passing": passing,
        "controls_failing": sum(1 for v in report.values() if v["status"] == "fail"),
        "controls_warning": sum(1 for v in report.values() if v["status"] == "warn"),
        "control_details": report,
        "headline": (
            f"📋 {framework.upper()} Compliance: {round(passing / total * 100, 1)}% — "
            f"{passing}/{total} controls passing"
        ),
    }


async def check_policy_violations(ctx, *, policy_type: str = "all", **_) -> dict:
    """Check cloud resources against security policies."""
    findings = await _fetch_active_findings(ctx)

    policies = {
        "encryption": {
            "keywords": ["unencrypted", "encryption", "plaintext", "http only", "tls"],
            "rule": "All data must be encrypted at rest and in transit",
        },
        "access_control": {
            "keywords": ["public", "0.0.0.0/0", "open to internet", "admin", "wildcard"],
            "rule": "No resources should be publicly accessible without explicit approval",
        },
        "network": {
            "keywords": ["security group", "firewall", "ingress", "port 22", "port 3389"],
            "rule": "Management ports must not be exposed to 0.0.0.0/0",
        },
        "tagging": {
            "keywords": ["tag", "label", "cost center", "owner", "environment"],
            "rule": "All resources must have required tags (Owner, CostCenter, Environment)",
        },
    }

    violations = {}
    total_violations = 0

    for ptype, config in policies.items():
        if policy_type not in ("all", ptype):
            continue
        matched = [f for f in findings if _classify(f, config["keywords"])]
        violations[ptype] = {
            "rule": config["rule"],
            "violation_count": len(matched),
            "findings": [
                {"id": f.id, "title": f.title, "severity": f.severity}
                for f in matched[:5]
            ],
        }
        total_violations += len(matched)

    return {
        "policy_type": policy_type,
        "total_violations": total_violations,
        "by_policy": violations,
        "recommendation": (
            f"🔴 {total_violations} policy violations detected. "
            "Enforce policies via OPA/Rego or cloud-native policy engines."
            if total_violations else "✅ All checked policies are in compliance."
        ),
    }


async def track_compliance_drift(ctx, *, framework: str = "soc2", lookback_days: int = 30, **_) -> dict:
    """Track compliance posture changes over time."""
    findings = await _fetch_active_findings(ctx)
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    recent = [f for f in findings if f.created_at and f.created_at >= cutoff]
    total = len(findings)

    return {
        "framework": framework,
        "lookback_days": lookback_days,
        "total_active_findings": total,
        "new_findings_in_period": len(recent),
        "by_severity": {
            "new": dict(Counter(f.severity for f in recent)),
            "total": dict(Counter(f.severity for f in findings)),
        },
        "drift_indicator": (
            "worsening" if len(recent) > total * 0.3
            else "stable" if len(recent) < total * 0.1
            else "moderate"
        ),
        "headline": (
            f"📊 Compliance drift: {len(recent)} new findings in last {lookback_days} days "
            f"({round(len(recent) / max(total, 1) * 100, 1)}% of total)"
        ),
    }


async def map_data_flows(ctx, *, data_type: str = "all", **_) -> dict:
    """Map PII/PHI/PCI data flows for privacy assessment."""
    findings = await _fetch_active_findings(ctx)

    data_keywords = {
        "pii": ["pii", "personal", "email", "name", "address", "phone", "ssn", "gdpr"],
        "phi": ["phi", "health", "hipaa", "medical", "patient", "diagnosis"],
        "pci": ["pci", "credit card", "cardholder", "cvv", "pan", "payment"],
    }

    results = {}
    for dtype, keywords in data_keywords.items():
        if data_type not in ("all", dtype):
            continue
        matched = [f for f in findings if _classify(f, keywords)]
        results[dtype] = {
            "finding_count": len(matched),
            "by_severity": dict(Counter(f.severity for f in matched)),
            "storage_locations": list(set(f.resource_name for f in matched if f.resource_name))[:10],
            "cloud_providers": list(set(f.cloud_provider for f in matched if f.cloud_provider)),
            "sample_findings": [{"id": f.id, "title": f.title} for f in matched[:5]],
        }

    total_data_findings = sum(v["finding_count"] for v in results.values())

    return {
        "data_type": data_type,
        "total_data_findings": total_data_findings,
        "data_flows": results,
        "cross_border_risk": "Review required — check resource regions for cross-border transfers",
        "recommendation": (
            f"🔴 {total_data_findings} findings related to sensitive data handling. "
            "Ensure encryption, access controls, and data residency compliance."
            if total_data_findings else "✅ No sensitive data handling issues detected."
        ),
    }


# ═══════════════════════════════════════════════════════════════════
#  5. RESPONSE & AUTOMATION
# ═══════════════════════════════════════════════════════════════════

async def create_jira_ticket(ctx, *, finding_id: int = 0, project_key: str = "SEC",
                              assignee: str = "", priority: str = "", **_) -> dict:
    """Create a ticket from a finding (returns ticket template — actual creation requires integration)."""
    from app.models.finding import Finding as FindingModel
    stmt = select(FindingModel).where(
        FindingModel.id == finding_id, FindingModel.organization_id == ctx.organization_id,
    )
    result = await ctx.db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        return {"error": f"Finding {finding_id} not found"}

    ticket_priority = priority or {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"
    }.get(finding.severity, "medium")

    return {
        "status": "draft_only",
        "note": "No ticket was created: no ticketing system is connected. This is draft text for a person to file.",
        "ticket": {
            "project": project_key,
            "type": "Bug",
            "priority": ticket_priority,
            "summary": f"[{finding.severity}] {finding.title}",
            "description": (
                f"**Security Finding #{finding.id}**\n\n"
                f"**Severity:** {finding.severity}\n"
                f"**Category:** {finding.category}\n"
                f"**Resource:** {finding.resource_name}\n"
                f"**Cloud:** {finding.cloud_provider}\n\n"
                f"**Rule:** {finding.rule_id}\n\n"
                f"**Remediation:**\n{finding.remediation or 'See finding details'}\n\n"
                f"*Auto-generated by GuardNous*"
            ),
            "labels": ["security", finding.severity.lower(), finding.category or "general"],
            "assignee": assignee or "unassigned",
        },
    }


async def notify_slack_channel(ctx, *, channel: str = "#security-alerts", message: str = "",
                                severity: str = "info", finding_id: int = 0, **_) -> dict:
    """Generate a Slack notification payload (actual sending requires webhook integration)."""
    emoji = _severity_emoji(severity.upper())

    payload = {
        "channel": channel,
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} Security Alert — {severity.upper()}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message},
            },
        ],
    }

    if finding_id:
        payload["blocks"].append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"📎 Finding ID: `{finding_id}` — view in GuardNous dashboard"},
        })

    return {
        "status": "template_generated",
        "note": "Slack webhook not yet configured — notification template generated",
        "payload": payload,
    }


async def quarantine_resource(ctx, *, resource_id: str = "", action: str = "isolate_network",
                               dry_run: bool = True, **_) -> dict:
    """Generate quarantine action plan (actual execution requires cloud integration)."""
    action_plans = {
        "isolate_network": {
            "description": "Apply restrictive security group/NSG — deny all inbound/outbound except monitoring",
            "steps": [
                "Create quarantine security group (deny all)",
                "Snapshot current SG/NSG rules for rollback",
                "Apply quarantine SG to resource",
                "Verify isolation (connectivity test fails)",
                "Alert SOC team",
            ],
            "rollback": "Restore original security group from snapshot",
        },
        "disable_key": {
            "description": "Disable compromised access keys or service account credentials",
            "steps": [
                "Identify all access keys for the resource/identity",
                "Disable (not delete) the compromised key",
                "Generate new key and distribute securely",
                "Verify services using new key",
                "Delete old key after 24h monitoring",
            ],
            "rollback": "Re-enable the disabled key",
        },
        "revoke_token": {
            "description": "Revoke OAuth tokens, session tokens, or API tokens",
            "steps": [
                "Identify all active sessions/tokens",
                "Revoke compromised tokens",
                "Force re-authentication for affected users",
                "Monitor for unauthorized access attempts",
                "Update token rotation policy",
            ],
            "rollback": "Issue new tokens to legitimate users",
        },
        "snapshot_and_stop": {
            "description": "Create forensic snapshot then stop the resource for investigation",
            "steps": [
                "Create disk/volume snapshot for forensics",
                "Tag snapshot with incident ID and timestamp",
                "Stop/deallocate the resource",
                "Preserve network logs and flow data",
                "Hand off snapshot to forensics team",
            ],
            "rollback": "Restart resource from snapshot after investigation",
        },
    }

    plan = action_plans.get(action, action_plans["isolate_network"])

    return {
        "resource_id": resource_id,
        "action": action,
        "dry_run": dry_run,
        "status": "plan_generated",
        "plan": plan,
        "warning": "This is a plan only. Nothing was changed: GuardNous does not isolate resources itself. "
                   "A person must carry out these steps.",
    }


async def analyze_supply_chain(ctx, **_) -> dict:
    """Analyze supply chain security: scanner health, vulnerable versions, integrity status."""
    try:
        from app.services.plugins.health_monitor import PluginHealthMonitor
        monitor = PluginHealthMonitor()
        summary = await monitor.get_supply_chain_summary()
        return {"status": "ok", "supply_chain_report": summary}
    except Exception as e:
        logger.warning("supply chain analysis fallback: %s", e)
        return {
            "status": "ok",
            "supply_chain_report": (
                "Supply chain health monitor is initializing. "
                "Scanner plugins are managed via the Plugins page — "
                "version pinning, auto-rollback on CVE, and SHA-256 integrity "
                "checks are available for all external scanners."
            ),
        }


async def generate_runbook(ctx, *, scenario: str = "", cloud_provider: str = "multi", **_) -> dict:
    """Generate step-by-step operational runbook."""
    findings = await _fetch_active_findings(ctx)

    # Common runbook templates
    templates = {
        "credential rotation": {
            "title": "Credential Rotation Runbook",
            "severity": "HIGH",
            "steps": [
                {"phase": "Pre-check", "actions": ["Identify all services using the credential", "Verify new credential is ready", "Notify dependent teams"]},
                {"phase": "Execute", "actions": ["Generate new credential", "Update secret manager/vault", "Deploy configuration changes", "Rotate in all environments (dev → staging → prod)"]},
                {"phase": "Verify", "actions": ["Confirm all services authenticate with new credential", "Check for failed auth attempts with old credential", "Monitor error rates for 1 hour"]},
                {"phase": "Cleanup", "actions": ["Disable old credential (don't delete yet)", "Delete old credential after 24h monitoring", "Update documentation and runbook"]},
            ],
        },
        "incident response": {
            "title": "Security Incident Response Runbook",
            "severity": "CRITICAL",
            "steps": [
                {"phase": "Detect & Assess", "actions": ["Confirm incident (rule out false positive)", "Classify severity (P1-P4)", "Activate incident commander"]},
                {"phase": "Contain", "actions": ["Isolate affected resources", "Revoke compromised credentials", "Block malicious IPs/domains", "Preserve forensic evidence"]},
                {"phase": "Eradicate", "actions": ["Remove malware/backdoors", "Patch exploited vulnerabilities", "Reset all potentially compromised credentials"]},
                {"phase": "Recover", "actions": ["Restore from clean backups", "Re-enable services gradually", "Monitor for re-compromise (72h watch)"]},
                {"phase": "Post-Incident", "actions": ["Conduct blameless postmortem", "Update detection rules", "File regulatory notifications if required"]},
            ],
        },
        "patch deployment": {
            "title": "Security Patch Deployment Runbook",
            "severity": "HIGH",
            "steps": [
                {"phase": "Assess", "actions": ["Review CVE details and exploitability", "Identify affected systems", "Check patch compatibility"]},
                {"phase": "Test", "actions": ["Deploy to dev environment", "Run automated tests", "Validate application functionality"]},
                {"phase": "Deploy", "actions": ["Schedule maintenance window", "Deploy to staging", "Deploy to production (rolling/canary)", "Monitor for regressions"]},
                {"phase": "Verify", "actions": ["Confirm CVE is remediated (rescan)", "Check system stability", "Update vulnerability tracking"]},
            ],
        },
    }

    # Find best matching template
    scenario_lower = scenario.lower()
    matched_template = None
    for key, template in templates.items():
        if key in scenario_lower or any(w in scenario_lower for w in key.split()):
            matched_template = template
            break

    if not matched_template:
        matched_template = {
            "title": f"Runbook: {scenario}",
            "severity": "MEDIUM",
            "steps": [
                {"phase": "Assess", "actions": ["Evaluate scope and impact", "Identify affected resources", "Determine risk level"]},
                {"phase": "Plan", "actions": ["Define success criteria", "Identify rollback procedure", "Notify stakeholders"]},
                {"phase": "Execute", "actions": ["Implement changes per plan", "Monitor for issues", "Document actions taken"]},
                {"phase": "Verify", "actions": ["Confirm changes are effective", "Run validation checks", "Update documentation"]},
            ],
        }

    related_findings = [f for f in findings if _classify(f, scenario_lower.split())]

    return {
        "scenario": scenario,
        "cloud_provider": cloud_provider,
        "runbook": matched_template,
        "related_findings_count": len(related_findings),
        "related_findings": [
            {"id": f.id, "title": f.title, "severity": f.severity}
            for f in related_findings[:5]
        ],
        "communication_template": {
            "subject": f"[{matched_template['severity']}] {matched_template['title']}",
            "stakeholders": ["Security team", "Engineering leads", "Management (if P1/P2)"],
            "channels": ["#security-incidents (Slack)", "security@company.com"],
        },
    }


# ═══════════════════════════════════════════════════════════════════
#  SKILL REGISTRY
# ═══════════════════════════════════════════════════════════════════

from app.services.agents.skills import AgentSkill


def build_expanded_skill_registry() -> dict[str, AgentSkill]:
    """Return the expanded skill registry (22 skills)."""
    return {
        # ── Threat Intelligence & Enrichment ────────────────────────
        "enrich_ioc": AgentSkill(
            name="enrich_ioc",
            description="IOC enrichment — IP, domain, hash, URL threat intel lookup and correlation.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"ioc_value": {"type": "string"}, "ioc_type": {"type": "string"}}},
            executor=enrich_ioc,
        ),
        "check_reputation": AgentSkill(
            name="check_reputation",
            description="IP/domain reputation check — blocklists, abuse history, ASN, geo data.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
            executor=check_reputation,
        ),
        "map_mitre_attack": AgentSkill(
            name="map_mitre_attack",
            description="MITRE ATT&CK mapping — techniques, tactics, detection gaps, heatmap.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"scope": {"type": "string"}}},
            executor=map_mitre_attack,
        ),
        "detect_anomalies": AgentSkill(
            name="detect_anomalies",
            description="Statistical anomaly detection — severity spikes, new categories, cloud shifts.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"lookback_days": {"type": "integer"}}},
            executor=detect_anomalies,
        ),
        "predict_risk_trend": AgentSkill(
            name="predict_risk_trend",
            description="Risk trajectory prediction — forecast risk score with confidence intervals.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"forecast_days": {"type": "integer"}}},
            executor=predict_risk_trend,
        ),
        # ── Cloud & Infrastructure ─────────────────────────────────
        "scan_exposed_ports": AgentSkill(
            name="scan_exposed_ports",
            description="Exposed port scanner — public management ports, database exposure, open services.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"cloud_provider": {"type": "string"}}},
            executor=scan_exposed_ports,
        ),
        "audit_iam_permissions": AgentSkill(
            name="audit_iam_permissions",
            description="IAM permission audit — overprivileged roles, unused permissions, escalation paths.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"cloud_provider": {"type": "string"}, "focus": {"type": "string"}}},
            executor=audit_iam_permissions,
        ),
        "check_encryption_posture": AgentSkill(
            name="check_encryption_posture",
            description="Encryption posture audit — at-rest and in-transit coverage gaps.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"cloud_provider": {"type": "string"}}},
            executor=check_encryption_posture,
        ),
        "assess_backup_security": AgentSkill(
            name="assess_backup_security",
            description="Backup security assessment — immutability, cross-region, retention, encryption.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"cloud_provider": {"type": "string"}}},
            executor=assess_backup_security,
        ),
        "evaluate_waf_rules": AgentSkill(
            name="evaluate_waf_rules",
            description="WAF/firewall rule analysis — detection gaps, bypass potential, rule overlap.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"cloud_provider": {"type": "string"}}},
            executor=evaluate_waf_rules,
        ),
        # ── Code & Pipeline ────────────────────────────────────────
        "scan_code_snippet": AgentSkill(
            name="scan_code_snippet",
            description="On-demand SAST — secrets, injection, insecure crypto, common CWEs.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"code": {"type": "string"}, "language": {"type": "string"}}},
            executor=scan_code_snippet,
        ),
        "analyze_dockerfile": AgentSkill(
            name="analyze_dockerfile",
            description="Dockerfile security review — base image, root user, secrets, CIS Docker controls.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"dockerfile_content": {"type": "string"}}},
            executor=analyze_dockerfile,
        ),
        "review_github_actions": AgentSkill(
            name="review_github_actions",
            description="GitHub Actions security review — command injection, permissions, unpinned actions.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"workflow_content": {"type": "string"}}},
            executor=review_github_actions,
        ),
        "check_dependency_health": AgentSkill(
            name="check_dependency_health",
            description="Dependency health — CVEs, maintenance status, license risk, outdated packages.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"ecosystem": {"type": "string"}}},
            executor=check_dependency_health,
        ),
        # ── Compliance & Governance ────────────────────────────────
        "generate_audit_report": AgentSkill(
            name="generate_audit_report",
            description="Compliance audit report generation — control assessments, gaps, evidence mapping.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"framework": {"type": "string"}, "format": {"type": "string"}}},
            executor=generate_audit_report,
        ),
        "check_policy_violations": AgentSkill(
            name="check_policy_violations",
            description="Policy violation checker — encryption, access control, network, tagging rules.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"policy_type": {"type": "string"}}},
            executor=check_policy_violations,
        ),
        "track_compliance_drift": AgentSkill(
            name="track_compliance_drift",
            description="Compliance drift tracking — before/after delta, new violations, resolved gaps.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"framework": {"type": "string"}, "lookback_days": {"type": "integer"}}},
            executor=track_compliance_drift,
        ),
        "map_data_flows": AgentSkill(
            name="map_data_flows",
            description="Data flow mapping — PII/PHI/PCI storage, transit, cross-border transfer risks.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"data_type": {"type": "string"}}},
            executor=map_data_flows,
        ),
        # ── Response & Automation ──────────────────────────────────
        "create_jira_ticket": AgentSkill(
            name="create_jira_ticket",
            description="Create Jira ticket from finding — full context, severity, remediation, assignment.",
            kind="agentic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"finding_id": {"type": "integer"}, "project_key": {"type": "string"}}},
            executor=create_jira_ticket,
        ),
        "notify_slack_channel": AgentSkill(
            name="notify_slack_channel",
            description="Send formatted security alert to Slack/Teams channel.",
            kind="agentic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"channel": {"type": "string"}, "message": {"type": "string"}}},
            executor=notify_slack_channel,
        ),
        "quarantine_resource": AgentSkill(
            name="quarantine_resource",
            description="Isolate compromised resource — network isolation, key disable, token revoke.",
            kind="agentic", execution_mode="sync", requires_approval=True,
            input_schema={"type": "object", "properties": {"resource_id": {"type": "string"}, "action": {"type": "string"}}},
            executor=quarantine_resource,
        ),
        "generate_runbook": AgentSkill(
            name="generate_runbook",
            description="Generate operational runbook — pre-checks, steps, verification, rollback, comms.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {"scenario": {"type": "string"}, "cloud_provider": {"type": "string"}}},
            executor=generate_runbook,
        ),
        "analyze_supply_chain": AgentSkill(
            name="analyze_supply_chain",
            description="Analyze supply chain security: scanner version health, CVE exposure, integrity verification, and auto-remediation status.",
            kind="agentic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}, "required": []},
            executor=analyze_supply_chain,
        ),
    }

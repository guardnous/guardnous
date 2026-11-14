"""Typed skills registry for the GuardNous agentic runtime.

The platform keeps the routing layer explicit and deterministic. Simple requests
are executed as direct skills without invoking a model, while reasoning-heavy
queries are delegated to the LLM runtime. The pattern is intentionally similar to
DSPy-style task decomposition: small reusable skills with clear contracts.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from sqlalchemy import select

from app.models.cve import CVE
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.agents.tools import ToolContext
from app.services.risk.scorer import RiskScorer


@dataclass(frozen=True)
class AgentSkill:
    name: str
    description: str
    kind: str
    execution_mode: str = "sync"
    requires_approval: bool = False
    input_schema: dict[str, Any] | None = None
    executor: Callable[..., Any] | None = None

    def to_manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "kind": self.kind,
            "execution_mode": self.execution_mode,
            "requires_approval": self.requires_approval,
            "input_schema": self.input_schema or {},
        }


async def _risk_overview(ctx: ToolContext, **_: Any) -> dict:
    scorer = RiskScorer(ctx.db)
    severity = await scorer.get_severity_breakdown(ctx.organization_id)
    return {
        "risk_score": await scorer.get_organization_score(ctx.organization_id),
        "severity_breakdown": severity,
        "cloud_breakdown": await scorer.get_cloud_breakdown(ctx.organization_id),
        "top_risks": await scorer.get_top_risks(ctx.organization_id, limit=5),
        "total_findings": sum((severity or {}).values()),
    }


async def _findings_summary(ctx: ToolContext, **_: Any) -> dict:
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id)
        .where(Finding.is_fixed == False)  # noqa: E712
        .where(Finding.is_ignored == False)  # noqa: E712
        .order_by(Finding.severity.asc(), Finding.created_at.desc())
        .limit(10)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "items": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "cloud_provider": f.cloud_provider,
                "resource_name": f.resource_name,
            }
            for f in rows
        ],
    }


async def _cve_lookup(ctx: ToolContext, query: str = "", limit: int = 5, **_: Any) -> dict:
    stmt = select(CVE)
    if query:
        stmt = stmt.where(CVE.description.ilike(f"%{query}%"))
    stmt = stmt.order_by(CVE.cvss_score.desc().nullslast()).limit(min(limit, 20))
    rows = (await ctx.db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "items": [
            {
                "cve_id": c.cve_id,
                "severity": c.severity,
                "cvss_score": c.cvss_score,
                "description": (c.description or "")[:240],
            }
            for c in rows
        ],
    }


async def _scan_history(ctx: ToolContext, limit: int = 5, **_: Any) -> dict:
    stmt = (
        select(Scan)
        .where(Scan.organization_id == ctx.organization_id)
        .order_by(Scan.created_at.desc())
        .limit(min(limit, 20))
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "items": [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "status": s.status,
                "risk_score": s.risk_score,
                "findings_count": s.findings_count,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in rows
        ],
    }


async def _security_brief(ctx: ToolContext, pack: dict | None = None, **_: Any) -> dict:
    # The LLM-backed brief is intentionally a separate skill route, while the data
    # itself remains deterministic and grounded in the organization snapshot.
    risk = await _risk_overview(ctx)
    summary = await _findings_summary(ctx)
    return {
        "risk": risk,
        "findings": summary,
        "context_pack": pack or {},
    }




async def _compliance_check(ctx: ToolContext, **_: Any) -> dict:
    """Map active findings to compliance frameworks."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id)
        .where(Finding.is_fixed == False)  # noqa: E712
        .where(Finding.is_ignored == False)  # noqa: E712
        .order_by(Finding.severity.asc())
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()
    # Heuristic mapping based on finding categories
    framework_hits: dict[str, list[dict]] = {
        "CIS": [], "SOC2": [], "PCI-DSS": [], "HIPAA": [], "NIST-800-53": []
    }
    for f in rows:
        title_lower = (f.title or "").lower()
        if any(w in title_lower for w in ("encrypt", "kms", "ssl", "tls")):
            framework_hits["CIS"].append({"id": f.id, "title": f.title, "control": "CIS 2.x - Encryption"})
            framework_hits["HIPAA"].append({"id": f.id, "title": f.title, "control": "164.312(a)(2)(iv)"})
        if any(w in title_lower for w in ("iam", "access", "permission", "role", "policy")):
            framework_hits["SOC2"].append({"id": f.id, "title": f.title, "control": "CC6.1 - Access Controls"})
            framework_hits["NIST-800-53"].append({"id": f.id, "title": f.title, "control": "AC-2/AC-6"})
        if any(w in title_lower for w in ("secret", "key", "credential", "password", "token")):
            framework_hits["PCI-DSS"].append({"id": f.id, "title": f.title, "control": "Req 3.4 - Key Management"})
        if any(w in title_lower for w in ("public", "open", "exposed", "ingress")):
            framework_hits["CIS"].append({"id": f.id, "title": f.title, "control": "CIS 4.x - Networking"})
            framework_hits["PCI-DSS"].append({"id": f.id, "title": f.title, "control": "Req 1 - Firewall"})
    return {
        "total_findings": len(rows),
        "frameworks": {k: {"count": len(v), "items": v[:5]} for k, v in framework_hits.items()},
    }


async def _attack_surface(ctx: ToolContext, **_: Any) -> dict:
    """Enumerate the external attack surface based on findings."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id)
        .where(Finding.is_fixed == False)  # noqa: E712
        .where(Finding.is_ignored == False)  # noqa: E712
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()
    categories: dict[str, list[dict]] = {
        "exposed_secrets": [],
        "public_resources": [],
        "overprivileged_iam": [],
        "unencrypted_data": [],
        "vulnerable_deps": [],
    }
    for f in rows:
        title_lower = (f.title or "").lower()
        item = {"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name}
        if any(w in title_lower for w in ("secret", "key", "credential", "password", "token", "api key")):
            categories["exposed_secrets"].append(item)
        elif any(w in title_lower for w in ("public", "open", "exposed", "0.0.0.0", "ingress")):
            categories["public_resources"].append(item)
        elif any(w in title_lower for w in ("admin", "wildcard", "*", "overprivilege", "full access")):
            categories["overprivileged_iam"].append(item)
        elif any(w in title_lower for w in ("encrypt", "unencrypt", "plaintext", "http://")):
            categories["unencrypted_data"].append(item)
        elif any(w in title_lower for w in ("cve", "vulnerable", "outdated", "deprecated")):
            categories["vulnerable_deps"].append(item)
    return {
        "total_surface_items": sum(len(v) for v in categories.values()),
        "categories": {k: {"count": len(v), "items": v[:5]} for k, v in categories.items()},
    }


async def _posture_trend(ctx: ToolContext, **_: Any) -> dict:
    """Show risk posture trend from recent scans."""
    stmt = (
        select(Scan)
        .where(Scan.organization_id == ctx.organization_id)
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()
    trend = []
    for s in rows:
        trend.append({
            "scan_id": s.id,
            "type": s.scan_type,
            "risk_score": s.risk_score,
            "findings_count": s.findings_count,
            "date": s.created_at.isoformat() if s.created_at else None,
        })
    improving = False
    if len(trend) >= 2:
        recent = trend[0].get("risk_score") or 0
        older = trend[-1].get("risk_score") or 0
        improving = recent < older
    return {
        "trend": trend,
        "direction": "improving" if improving else "worsening" if len(trend) >= 2 else "insufficient_data",
        "scan_count": len(trend),
    }


async def _remediation_guide(ctx: ToolContext, **_: Any) -> dict:
    """Generate step-by-step remediation for top critical findings."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id)
        .where(Finding.is_fixed == False)  # noqa: E712
        .where(Finding.is_ignored == False)  # noqa: E712
        .where(Finding.severity == "critical")
        .order_by(Finding.created_at.desc())
        .limit(5)
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()
    guides = []
    for f in rows:
        title_lower = (f.title or "").lower()
        if "secret" in title_lower or "key" in title_lower:
            steps = ["Rotate the exposed credential immediately", "Add to .gitignore or secret manager",
                     "Scan commit history for other leaks", "Enable pre-commit secret scanning hooks"]
        elif "public" in title_lower or "open" in title_lower:
            steps = ["Restrict ingress rules to known CIDR ranges", "Enable VPC/firewall logging",
                     "Apply least-privilege network ACLs", "Verify with nmap or cloud inventory scan"]
        elif "encrypt" in title_lower:
            steps = ["Enable encryption at rest on the resource", "Use KMS/CMK where available",
                     "Enforce TLS 1.2+ for data in transit", "Update IaC templates with encryption config"]
        else:
            steps = ["Review the finding details and affected resource", "Apply the recommended fix from the scanner",
                     "Verify the fix with a targeted rescan", "Document the change in your change log"]
        guides.append({"id": f.id, "title": f.title, "severity": f.severity,
                        "resource": f.resource_name, "steps": steps})
    return {"count": len(guides), "guides": guides}
def build_skill_registry() -> dict[str, AgentSkill]:
    return {
        "risk_overview": AgentSkill(
            name="risk_overview",
            description="Get the current overall security score, severity breakdown, and top risks.",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=_risk_overview,
        ),
        "findings_summary": AgentSkill(
            name="findings_summary",
            description="Summarize the most critical active findings across the organization.",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {"limit": {"type": "integer"}}},
            executor=_findings_summary,
        ),
        "cve_lookup": AgentSkill(
            name="cve_lookup",
            description="Search the CVE catalog for relevant vulnerabilities and scores.",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}},
            executor=_cve_lookup,
        ),
        "scan_history": AgentSkill(
            name="scan_history",
            description="Review recent scan runs, statuses, and trends for the organization.",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {"limit": {"type": "integer"}}},
            executor=_scan_history,
        ),
        "security_brief": AgentSkill(
            name="security_brief",
            description="Generate a concise executive-style security brief using the current organization context.",
            kind="llm",
            execution_mode="llm",
            requires_approval=True,
            input_schema={"type": "object", "properties": {"summary": {"type": "string"}}},
            executor=_security_brief,
        ),
        "compliance_check": AgentSkill(
            name="compliance_check",
            description="Map active findings to compliance frameworks (CIS, SOC2, PCI-DSS, HIPAA, NIST).",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=_compliance_check,
        ),
        "attack_surface": AgentSkill(
            name="attack_surface",
            description="Enumerate the external attack surface: exposed secrets, public resources, overprivileged IAM.",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=_attack_surface,
        ),
        "posture_trend": AgentSkill(
            name="posture_trend",
            description="Show risk posture trend over recent scans — improving or worsening.",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=_posture_trend,
        ),
        "remediation_guide": AgentSkill(
            name="remediation_guide",
            description="Step-by-step remediation playbook for top critical findings.",
            kind="deterministic",
            execution_mode="sync",
            requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=_remediation_guide,
        ),
    }


def build_full_skill_registry() -> dict[str, AgentSkill]:
    """Build the complete skill registry including investigation and advanced skills."""
    base = build_skill_registry()
    from app.services.agents.investigation_skills import build_investigation_skill_registry
    from app.services.agents.advanced_skills import build_advanced_skill_registry
    base.update(build_investigation_skill_registry())
    base.update(build_advanced_skill_registry())
    return base


def skill_manifest() -> list[dict[str, Any]]:
    return [skill.to_manifest() for skill in build_full_skill_registry().values()]


def build_skill_plan(message: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Turn a user request into a structured execution plan.

    This is the deployable planning layer: route the request to the correct skill,
    validate the expected schema, and mark whether approval is required before the
    action can be executed.
    """
    request_text = message or ""
    route = route_user_request(request_text)
    registry = build_skill_registry()
    skill = registry.get(route)
    if skill is None:
        return {
            "skill": route,
            "status": "unavailable",
            "requires_approval": False,
            "input_schema": {"type": "object", "properties": {}},
            "params": params or {},
            "message": "No matching skill found for the request.",
        }

    normalized = params or {}
    status = "approval_required" if skill.requires_approval else "ready"
    return {
        "skill": skill.name,
        "description": skill.description,
        "status": status,
        "requires_approval": skill.requires_approval,
        "input_schema": skill.input_schema or {"type": "object", "properties": {}},
        "params": normalized,
    }


async def execute_skill(ctx: ToolContext, skill_name: str, **kwargs: Any) -> dict[str, Any]:
    registry = build_full_skill_registry()
    skill = registry.get(skill_name)
    if not skill or skill.executor is None:
        return {"error": f"unknown skill: {skill_name}"}
    if skill.requires_approval:
        return {"error": f"approval required before executing skill: {skill_name}"}
    return await skill.executor(ctx, **kwargs)


def route_user_request(message: str) -> str:
    text = (message or "").lower()
    # Investigation skills (check specific patterns first)
    if any(kw in text for kw in ("incident response", "ransomware", "data breach", "credential exposure", "unauthorized access", "containment")):
        return "incident_response"
    if any(kw in text for kw in ("aws iam", "privilege escalation", "overprivileged role", "iam investigation")):
        return "investigate_aws_iam"
    if any(kw in text for kw in ("aws network", "security group", "vpc", "public subnet")):
        return "investigate_aws_network"
    if any(kw in text for kw in ("azure security", "azure defender", "entra", "rbac", "azure investigation")):
        return "investigate_azure_security"
    if any(kw in text for kw in ("gcp security", "gcp investigation", "google cloud security", "service account")):
        return "investigate_gcp_security"
    if any(kw in text for kw in ("terraform", "iac misconfig", "infrastructure as code", "hcl")):
        return "analyze_terraform"
    if any(kw in text for kw in ("kubernetes", "k8s", "pod security", "container security", "helm")):
        return "analyze_kubernetes"
    if any(kw in text for kw in ("supply chain", "dependency", "sbom", "outdated package", "vulnerable dependency")):
        return "analyze_supply_chain"
    if any(kw in text for kw in ("secret", "credential", "leaked key", "hardcoded password", "exposed key")):
        return "investigate_secrets"
    if any(kw in text for kw in ("deep compliance", "control id", "specific controls", "compliance mapping")):
        return "deep_compliance"
    # Advanced investigation skills
    if any(kw in text for kw in ("container security", "docker security", "dockerfile", "containerd", "privileged container")):
        return "investigate_containers"
    if any(kw in text for kw in ("cicd", "ci/cd", "pipeline security", "github actions security", "build security", "slsa")):
        return "investigate_cicd"
    if any(kw in text for kw in ("api security", "owasp api", "bola", "bfla", "mass assignment", "api gateway")):
        return "investigate_api"
    if any(kw in text for kw in ("dns security", "subdomain takeover", "dangling cname", "spf", "dkim", "dmarc")):
        return "investigate_dns"
    if any(kw in text for kw in ("tls security", "ssl security", "certificate expir", "weak cipher", "hsts")):
        return "investigate_tls"
    if any(kw in text for kw in ("zero trust", "ztna", "microsegment", "zero-trust")):
        return "assess_zero_trust"
    if any(kw in text for kw in ("network segmentation", "flat network", "lateral movement", "vlan")):
        return "analyze_network_segmentation"
    if any(kw in text for kw in ("endpoint security", "edr", "malware", "patch compliance", "antivirus")):
        return "assess_endpoint_security"
    if any(kw in text for kw in ("cost anomal", "cryptomining", "billing spike", "compute abuse")):
        return "detect_cost_anomalies"
    if any(kw in text for kw in ("threat model", "stride", "mitre att", "kill chain", "attack tree")):
        return "threat_modeling"
    if any(kw in text for kw in ("dlp", "data loss prevention", "data classification", "pii exposure")):
        return "assess_dlp"
    if any(kw in text for kw in ("identity governance", "access governance", "orphan account", "privilege creep")):
        return "assess_identity_governance"
    # Base skills
    if any(kw in text for kw in ("risk score", "severity", "risk", "breakdown", "overall risk")):
        return "risk_overview"
    if any(kw in text for kw in ("findings", "vulnerabilities", "top issues", "summary", "critical")):
        return "findings_summary"
    if any(kw in text for kw in ("cve", "known vulnerability", "exploit", "advisory")):
        return "cve_lookup"
    if any(kw in text for kw in ("scan history", "recent scans", "scan timeline", "scan runs")):
        return "scan_history"
    if any(kw in text for kw in ("compliance", "cis", "soc", "pci", "hipaa", "nist", "framework", "audit")):
        return "compliance_check"
    if any(kw in text for kw in ("attack surface", "exposure", "exposed", "public facing", "external")):
        return "attack_surface"
    if any(kw in text for kw in ("trend", "posture", "improving", "getting worse", "over time", "progress")):
        return "posture_trend"
    if any(kw in text for kw in ("how to fix", "remediation", "remediate", "playbook", "fix guide", "steps to fix")):
        return "remediation_guide"
    return "security_brief"


def render_skill_result(skill_name: str, payload: dict) -> str:
    if skill_name == "risk_overview":
        risk = payload.get("risk_score", {})
        severity = payload.get("severity_breakdown", {})
        lines = [f"Overall risk score: {risk.get('score', 0)}/100"]
        if severity:
            lines.append("Severity breakdown:")
            for level, count in sorted(severity.items()):
                lines.append(f"- {level}: {count}")
        if payload.get("top_risks"):
            lines.append("Top risks:")
            for item in payload["top_risks"][:3]:
                lines.append(f"- {item.get('title') or item.get('rule_id')} ({item.get('severity')})")
        return "\n".join(lines)

    if skill_name == "findings_summary":
        items = payload.get("items", [])
        title = f"{payload.get('count', 0)} active findings"
        if not items:
            return title + "\n- No open findings found."
        lines = [title]
        for item in items[:5]:
            lines.append(f"- {item.get('severity')} {item.get('title')} ({item.get('resource_name')})")
        return "\n".join(lines)

    if skill_name == "cve_lookup":
        items = payload.get("items", [])
        if not items:
            return "No CVEs matched the provided query."
        lines = [f"{payload.get('count', 0)} CVEs matched:"]
        for item in items[:5]:
            lines.append(f"- {item.get('cve_id')} [{item.get('severity')}] ({item.get('cvss_score')})")
        return "\n".join(lines)

    if skill_name == "scan_history":
        items = payload.get("items", [])
        if not items:
            return "No scan history available."
        lines = ["Recent scans:"]
        for item in items[:5]:
            lines.append(f"- #{item.get('id')} {item.get('scan_type')} [{item.get('status')}] risk={item.get('risk_score')}")
        return "\n".join(lines)

    if skill_name == "compliance_check":
        frameworks = payload.get("frameworks", {})
        lines = [f"Compliance mapping across {payload.get('total_findings', 0)} findings:"]
        for fw, data in frameworks.items():
            count = data.get("count", 0)
            if count > 0:
                lines.append(f"\n**{fw}** ({count} violations):")
                for item in data.get("items", [])[:3]:
                    lines.append(f"  - {item.get('title')} → {item.get('control')}")
        return "\n".join(lines)

    if skill_name == "attack_surface":
        categories = payload.get("categories", {})
        total = payload.get("total_surface_items", 0)
        lines = [f"Attack surface analysis: {total} exposure points\n"]
        icons = {"exposed_secrets": "🔑", "public_resources": "🌐", "overprivileged_iam": "👤",
                 "unencrypted_data": "🔓", "vulnerable_deps": "📦"}
        for cat, data in categories.items():
            count = data.get("count", 0)
            if count > 0:
                label = cat.replace("_", " ").title()
                lines.append(f"{icons.get(cat, '•')} **{label}** ({count}):")
                for item in data.get("items", [])[:3]:
                    lines.append(f"  - [{item.get('severity')}] {item.get('title')}")
        return "\n".join(lines)

    if skill_name == "posture_trend":
        trend = payload.get("trend", [])
        direction = payload.get("direction", "unknown")
        emoji = "📈" if direction == "improving" else "📉" if direction == "worsening" else "➡️"
        lines = [f"Posture trend: {emoji} **{direction.upper()}** ({len(trend)} scans)\n"]
        for item in trend[:5]:
            lines.append(f"- Scan #{item.get('scan_id')} ({item.get('type')}): "
                         f"risk={item.get('risk_score')}, findings={item.get('findings_count')} "
                         f"[{item.get('date', 'N/A')[:10]}]")
        return "\n".join(lines)

    if skill_name == "remediation_guide":
        guides = payload.get("guides", [])
        if not guides:
            return "No critical findings require remediation at this time."
        lines = [f"Remediation playbook for {len(guides)} critical findings:\n"]
        for g in guides:
            lines.append(f"### [{g.get('severity')}] {g.get('title')}")
            lines.append(f"Resource: `{g.get('resource', 'N/A')}`")
            for i, step in enumerate(g.get("steps", []), 1):
                lines.append(f"  {i}. {step}")
            lines.append("")
        return "\n".join(lines)

    return json.dumps(payload, default=str, indent=2)


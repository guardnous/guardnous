"""Agent tools: data-access and agentic write functions the copilot can call.

Each tool has an OpenAI-style JSON schema (for function-calling providers) and
an async executor bound to a :class:`ToolContext` (org-scoped DB session).

Tools are split into two categories:
  - **Read tools**: query findings, scans, CVEs (no side-effects)
  - **Write tools**: triage findings, generate fixes, create PRs (agentic actions)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.risk.scorer import RiskScorer


@dataclass
class ToolContext:
    db: AsyncSession
    organization_id: int
    # Who is behind the call, when it runs inside an approved agent run:
    # run_id, requested_by, approved_by.
    meta: dict = field(default_factory=dict)


READ, INTERNAL_WRITE, EXTERNAL_WRITE = "read", "internal_write", "external_write"

# What a tool changes. Anything not listed is read-only.
TOOL_RISK: dict[str, str] = {
    "triage_finding": INTERNAL_WRITE,        # GuardNous data
    "triage_findings": INTERNAL_WRITE,       # GuardNous data, many findings in one reviewed list
    "open_fix_pull_request": EXTERNAL_WRITE,  # a customer repository
    "send_slack_message": EXTERNAL_WRITE,     # the customer's Slack
    "remediate_cloud_finding": EXTERNAL_WRITE,  # a customer cloud resource
}

# Permission the requester and the approver must hold to use a write tool.
TOOL_PERMISSION: dict[str, tuple[str, str]] = {
    "triage_finding": ("findings", "update"),
    "triage_findings": ("findings", "update"),
    "open_fix_pull_request": ("findings", "update"),
    "remediate_cloud_finding": ("integrations", "update"),
}


def tool_risk(name: str) -> str:
    return TOOL_RISK.get(name, READ)


# ── individual tool executors ───────────────────────────────────────

async def _list_findings(ctx: ToolContext, severity: str = "", category: str = "",
                         cloud_provider: str = "", limit: int = 15) -> dict:
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == ctx.organization_id)
        .where(Finding.is_fixed == False)  # noqa: E712
        .where(Finding.is_ignored == False)  # noqa: E712
    )
    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
    if category:
        stmt = stmt.where(Finding.category == category.lower())
    if cloud_provider:
        stmt = stmt.where(Finding.cloud_provider == cloud_provider.lower())
    stmt = stmt.order_by(Finding.severity.asc(), Finding.created_at.desc()).limit(min(limit, 50))
    rows = (await ctx.db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "findings": [
            {
                "id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                "category": f.category, "cloud_provider": f.cloud_provider,
                "resource_name": f.resource_name, "cve_id": f.cve_id,
            }
            for f in rows
        ],
    }


async def _get_finding(ctx: ToolContext, finding_id: int) -> dict:
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == ctx.organization_id)
    )
    f = (await ctx.db.execute(stmt)).scalar_one_or_none()
    if not f:
        return {"error": "finding not found"}
    return {
        "id": f.id, "rule_id": f.rule_id, "title": f.title, "description": f.description,
        "severity": f.severity, "category": f.category, "cloud_provider": f.cloud_provider,
        "resource_type": f.resource_type, "resource_name": f.resource_name,
        "file_path": f.file_path, "line_number": f.line_number,
        "code_snippet": f.code_snippet, "remediation": f.remediation, "cve_id": f.cve_id,
    }


async def _severity_breakdown(ctx: ToolContext) -> dict:
    return await RiskScorer(ctx.db).get_severity_breakdown(ctx.organization_id)


async def _risk_score(ctx: ToolContext) -> dict:
    return await RiskScorer(ctx.db).get_organization_score(ctx.organization_id)


async def _search_cves(ctx: ToolContext, query: str = "", severity: str = "", limit: int = 10) -> dict:
    stmt = select(CVE)
    if query:
        stmt = stmt.where(CVE.description.ilike(f"%{query}%"))
    if severity:
        stmt = stmt.where(CVE.severity == severity.upper())
    stmt = stmt.order_by(CVE.cvss_score.desc().nullslast()).limit(min(limit, 25))
    rows = (await ctx.db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "cves": [
            {"cve_id": c.cve_id, "severity": c.severity, "cvss_score": c.cvss_score,
             "description": (c.description or "")[:280]}
            for c in rows
        ],
    }


async def _triage_finding(
    ctx: ToolContext, finding_id: int, status: str, reason: str = "",
    assigned_to: str = "",
) -> dict:
    """Update a finding's triage status (agentic write tool)."""
    from app.services.triage_memory import VALID_STATUSES, decide

    if status not in VALID_STATUSES:
        return {"error": f"Invalid status '{status}'. Valid: {sorted(VALID_STATUSES)}"}
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == ctx.organization_id)
    )
    f = (await ctx.db.execute(stmt)).scalar_one_or_none()
    if not f:
        return {"error": "finding not found"}

    changed = await decide(ctx.db, f, status, reason=reason, assigned_to=assigned_to, author=_agent_author(ctx))
    await ctx.db.commit()
    return {"status": "ok", "finding_id": finding_id, "new_status": status, "also_applied_to": changed[1:]}


def _agent_author(ctx: ToolContext) -> str:
    """Who a note says made the decision: the agent, and the person who approved it."""
    approver = (ctx.meta or {}).get("approved_by")
    return f"GuardNous AI (approved by {approver})" if approver else "GuardNous AI"


MAX_BATCH = 400


async def check_triage_batch(db, organization_id: int, decisions: list) -> tuple[list[dict], list[str]]:
    """Validate a list of proposed decisions. Returns (accepted with finding details, problems)."""
    from app.services.triage_memory import VALID_STATUSES

    problems: list[str] = []
    wanted: dict[int, dict] = {}
    singles: list[tuple[int, dict]] = []                # one entry per finding; a shared decision is spread out
    for item in decisions or []:
        try:
            ids = [int(i) for i in (item.get("finding_ids") or [])] or [int(item.get("finding_id"))]
        except (TypeError, ValueError, AttributeError):
            problems.append(f"Not a decision: {str(item)[:80]}")
            continue
        singles.extend((finding_id, item) for finding_id in ids)
    for finding_id, item in singles[:MAX_BATCH]:
        status, reason = str(item.get("status") or ""), str(item.get("reason") or "").strip()
        if status not in VALID_STATUSES or status == "open":
            problems.append(f"#{finding_id}: '{status}' is not a status that can be set here.")
        elif status in ("false_positive", "resolved") and len(reason) < 10:
            problems.append(f"#{finding_id}: marking '{status}' needs a specific reason.")
        elif finding_id in wanted and wanted[finding_id]["status"] != status:
            problems.append(f"#{finding_id}: two different decisions were proposed; the first one is kept.")
        else:
            wanted.setdefault(finding_id, {"finding_id": finding_id, "status": status, "reason": reason[:500]})
    if len(singles) > MAX_BATCH:
        problems.append(f"Only the first {MAX_BATCH} findings were considered; {len(singles) - MAX_BATCH} were left out.")
    if not wanted:
        return [], problems

    rows = (await db.execute(
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id.in_(wanted), Scan.organization_id == organization_id)
    )).scalars().all()
    found = {f.id: f for f in rows}
    accepted = []
    for finding_id, item in wanted.items():
        f = found.get(finding_id)
        if f is None:
            problems.append(f"#{finding_id}: no such finding.")
        elif f.status == item["status"]:
            problems.append(f"#{finding_id}: already '{f.status}'.")
        else:
            accepted.append({**item, "severity": f.severity, "title": f.title, "file_path": f.file_path,
                             "from_status": f.status or "open"})
    return accepted, problems


async def _triage_findings(ctx: ToolContext, decisions: list | None = None, _checked: list | None = None,
                           **_ignored) -> dict:
    """Apply a reviewed list of triage decisions. Only the list the approver saw is applied."""
    from app.services.triage_memory import decide

    if not _checked:
        return {"error": "There is no reviewed list of decisions to apply."}
    ids = [int(item["finding_id"]) for item in _checked]
    rows = (await ctx.db.execute(
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id.in_(ids), Scan.organization_id == ctx.organization_id)
    )).scalars().all()
    by_id = {f.id: f for f in rows}
    applied, skipped, copies = [], [], 0
    author = _agent_author(ctx)
    for item in _checked:
        f = by_id.get(int(item["finding_id"]))
        if f is None or (f.status or "open") != item.get("from_status", "open"):
            skipped.append(item["finding_id"])       # changed by someone since the list was reviewed
            continue
        changed = await decide(ctx.db, f, item["status"], reason=item.get("reason", ""), author=author)
        applied.append(f.id)
        copies += len(changed) - 1
    await ctx.db.commit()
    return {
        "status": "ok", "applied": len(applied), "finding_ids": applied,
        "same_finding_in_other_scans_updated": copies,
        "skipped_because_they_changed_meanwhile": skipped,
    }


async def _auto_fix_finding(ctx: ToolContext, finding_id: int, **_ignored) -> dict:
    """Preview the code fix for a finding: reads the file from the repository
    and returns the diff. Changes nothing."""
    from app.services.agents.fix_pr import FixError, prepare_fix

    try:
        prepared = await prepare_fix(ctx.db, ctx.organization_id, finding_id)
    except FixError as exc:
        return {"error": str(exc)}
    return {
        "status": "preview", "note": "Nothing was changed. Use open_fix_pull_request to propose this change.",
        **{k: v for k, v in prepared.items() if k not in ("fixed_content", "original_sha256", "pr_body")},
    }


async def _open_fix_pull_request(ctx: ToolContext, finding_id: int, _prepared: dict | None = None, **_ignored) -> dict:
    """Open a pull request with the fix a person approved."""
    from app.services.agents.fix_pr import FixError, open_pull_request

    if not _prepared or int(_prepared.get("finding_id", -1)) != int(finding_id):
        return {"error": "No approved fix is attached to this request."}
    try:
        return await open_pull_request(
            ctx.db, ctx.organization_id, _prepared, run_id=ctx.meta.get("run_id"),
            requested_by=ctx.meta.get("requested_by", ""), approved_by=ctx.meta.get("approved_by", ""),
        )
    except FixError as exc:
        return {"error": str(exc)}


async def _remediate_cloud_finding(ctx: ToolContext, finding_id: int, _plan: dict | None = None, **_ignored) -> dict:
    """Make the approved change to the cloud resource."""
    from app.services.cloud_posture.remediation import RemediationError, apply

    if not _plan or int(_plan.get("finding_id", -1)) != int(finding_id):
        return {"error": "No approved change is attached to this request."}
    try:
        return await apply(
            ctx.db, ctx.organization_id, _plan, run_id=ctx.meta.get("run_id"),
            requested_by=ctx.meta.get("requested_by", ""), approved_by=ctx.meta.get("approved_by", ""),
        )
    except RemediationError as exc:
        return {"error": str(exc)}


async def slack_webhook_for(db: AsyncSession, organization_id: int) -> str:
    """The organization's Slack webhook, or '' when Slack is not connected."""
    from app.models.org_settings import OrgSettings

    row = (await db.execute(
        select(OrgSettings).where(OrgSettings.organization_id == organization_id)
    )).scalar_one_or_none()
    prefs = (row.notification_prefs if row else None) or {}
    return prefs.get("slack_webhook", "") if prefs.get("slack_enabled") else ""


async def _send_slack_message(ctx: ToolContext, message: str, severity: str = "info", finding_id: int = 0, **_ignored) -> dict:
    """Post an approved message to the organization's Slack webhook."""
    import httpx

    webhook = await slack_webhook_for(ctx.db, ctx.organization_id)
    if not webhook:
        return {"error": "Slack is not connected for this organization (Settings > Notifications)."}
    text = f"*GuardNous alert — {severity.upper()}*\n{message}"
    if finding_id:
        text += f"\nFinding #{finding_id}"
    if ctx.meta.get("approved_by"):
        text += f"\n_Sent by an agent run, approved by {ctx.meta['approved_by']}_"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook, json={"text": text})
    except httpx.HTTPError as exc:
        return {"error": f"Slack could not be reached: {type(exc).__name__}"}
    if resp.status_code >= 400:
        return {"error": f"Slack rejected the message (HTTP {resp.status_code})."}
    return {"status": "sent"}


async def _get_knowledge_stats(ctx: ToolContext) -> dict:
    """Get knowledge store statistics — what the agent has learned."""
    from app.services.agents.knowledge import get_knowledge_store
    return get_knowledge_store().get_stats()


async def _recent_scans(ctx: ToolContext, limit: int = 10) -> dict:
    stmt = (
        select(Scan)
        .where(Scan.organization_id == ctx.organization_id)
        .order_by(Scan.created_at.desc())
        .limit(min(limit, 25))
    )
    rows = (await ctx.db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "scans": [
            {"id": s.id, "scan_type": s.scan_type, "status": s.status,
             "risk_score": s.risk_score, "findings_count": s.findings_count,
             "file_name": s.file_name}
            for s in rows
        ],
    }


# ── Knowledge Graph tools ────────────────────────────────────────────

async def _kg_blast_radius(ctx: ToolContext, resource_id: str, depth: int = 3) -> dict:
    from app.services.knowledge_graph import KnowledgeGraphService
    kg = KnowledgeGraphService(ctx.db, ctx.organization_id)
    return await kg.blast_radius(resource_id, max_depth=min(depth, 5))


async def _kg_related_entities(ctx: ToolContext, entity_id: str, direction: str = "both",
                               relationship: str = "", depth: int = 2) -> dict:
    from app.services.knowledge_graph import KnowledgeGraphService
    kg = KnowledgeGraphService(ctx.db, ctx.organization_id)
    nodes = await kg.bfs(entity_id, max_depth=min(depth, 4),
                         direction=direction, relationship_filter=relationship or None)
    return {"entity_id": entity_id, "related_count": len(nodes),
            "entities": [{"entity_id": n.entity_id, "type": n.entity_type,
                          "label": n.label, "severity": n.severity} for n in nodes[:50]]}


async def _kg_search(ctx: ToolContext, query: str, entity_type: str = "", limit: int = 20) -> dict:
    from app.services.knowledge_graph import KnowledgeGraphService
    kg = KnowledgeGraphService(ctx.db, ctx.organization_id)
    nodes = await kg.search_nodes(query=query, entity_type=entity_type or None, limit=min(limit, 50))
    return {"query": query, "count": len(nodes),
            "nodes": [{"entity_id": n.entity_id, "type": n.entity_type,
                       "label": n.label, "severity": n.severity} for n in nodes]}


async def _kg_stats(ctx: ToolContext) -> dict:
    from app.services.knowledge_graph import KnowledgeGraphService
    kg = KnowledgeGraphService(ctx.db, ctx.organization_id)
    return await kg.stats()


# ── registry ────────────────────────────────────────────────────────

_EXECUTORS = {
    # Read tools
    "list_findings": _list_findings,
    "get_finding": _get_finding,
    "get_severity_breakdown": _severity_breakdown,
    "get_risk_score": _risk_score,
    "search_cves": _search_cves,
    "list_recent_scans": _recent_scans,
    # Write/agentic tools
    "triage_finding": _triage_finding,
    "triage_findings": _triage_findings,
    "auto_fix_finding": _auto_fix_finding,
    "open_fix_pull_request": _open_fix_pull_request,
    "send_slack_message": _send_slack_message,
    "remediate_cloud_finding": _remediate_cloud_finding,
    "get_knowledge_stats": _get_knowledge_stats,
    # Knowledge Graph tools
    "query_blast_radius": _kg_blast_radius,
    "get_related_entities": _kg_related_entities,
    "search_knowledge_graph": _kg_search,
    "get_graph_stats": _kg_stats,
}

# Skill-promoted tools are resolved lazily to avoid circular imports
_SKILL_TOOL_MAP = {
    "check_compliance": "_compliance_check",
    "analyze_attack_surface": "_attack_surface",
    "get_posture_trend": "_posture_trend",
    "generate_remediation_guide": "_remediation_guide",
}

# Investigation skill tools — resolved via investigation_skills module
_INVESTIGATION_TOOL_MAP = {
    "investigate_aws_iam": "investigate_aws_iam",
    "investigate_aws_network": "investigate_aws_network",
    "investigate_azure_security": "investigate_azure_security",
    "investigate_gcp_security": "investigate_gcp_security",
    "analyze_terraform": "analyze_terraform",
    "analyze_kubernetes": "analyze_kubernetes_security",
    "incident_response": "incident_response_playbook",
    "deep_compliance": "deep_compliance_mapping",
    "analyze_supply_chain": "analyze_supply_chain",
    "investigate_secrets": "investigate_secrets",
}

# Advanced investigation skills — resolved via advanced_skills module
_ADVANCED_TOOL_MAP = {
    "investigate_containers": "investigate_containers",
    "investigate_cicd": "investigate_cicd",
    "investigate_api": "investigate_api",
    "investigate_dns": "investigate_dns",
    "investigate_tls": "investigate_tls",
    "assess_zero_trust": "assess_zero_trust",
    "analyze_network_segmentation": "analyze_network_segmentation",
    "assess_endpoint_security": "assess_endpoint_security",
    "detect_cost_anomalies": "detect_cost_anomalies",
    "threat_modeling": "threat_modeling",
    "assess_dlp": "assess_dlp",
    "assess_identity_governance": "assess_identity_governance",
}

# Expanded skills — resolved via expanded_skills module
_EXPANDED_TOOL_MAP = {
    "enrich_ioc": "enrich_ioc",
    "check_reputation": "check_reputation",
    "map_mitre_attack": "map_mitre_attack",
    "detect_anomalies": "detect_anomalies",
    "predict_risk_trend": "predict_risk_trend",
    "scan_exposed_ports": "scan_exposed_ports",
    "audit_iam_permissions": "audit_iam_permissions",
    "check_encryption_posture": "check_encryption_posture",
    "assess_backup_security": "assess_backup_security",
    "evaluate_waf_rules": "evaluate_waf_rules",
    "scan_code_snippet": "scan_code_snippet",
    "analyze_dockerfile": "analyze_dockerfile",
    "review_github_actions": "review_github_actions",
    "check_dependency_health": "check_dependency_health",
    "generate_audit_report": "generate_audit_report",
    "check_policy_violations": "check_policy_violations",
    "track_compliance_drift": "track_compliance_drift",
    "map_data_flows": "map_data_flows",
    "draft_ticket": "create_jira_ticket",
    "quarantine_resource": "quarantine_resource",
    "generate_runbook": "generate_runbook",
}


def _resolve_executor(name: str):
    """Resolve executor — direct registry first, then lazy skill imports."""
    if name in _EXECUTORS:
        return _EXECUTORS[name]
    # Tools backed by the synced cloud inventory take precedence over the
    # older keyword-matching skills of the same name.
    from app.services.agents import cloud_skills
    if name in cloud_skills.EXECUTORS:
        return cloud_skills.EXECUTORS[name]
    from app.services.agents import chat_files
    if name in chat_files.EXECUTORS:
        return chat_files.EXECUTORS[name]
    from app.services.agents import triage_tools
    if name in triage_tools.EXECUTORS:
        return triage_tools.EXECUTORS[name]
    if name in _SKILL_TOOL_MAP:
        from app.services.agents import skills
        return getattr(skills, _SKILL_TOOL_MAP[name])
    if name in _INVESTIGATION_TOOL_MAP:
        from app.services.agents import investigation_skills
        skill_name = _INVESTIGATION_TOOL_MAP[name]
        registry = investigation_skills.build_investigation_skill_registry()
        skill = registry.get(skill_name)
        if skill and skill.executor:
            return skill.executor
    if name in _ADVANCED_TOOL_MAP:
        from app.services.agents import advanced_skills
        skill_name = _ADVANCED_TOOL_MAP[name]
        registry = advanced_skills.build_advanced_skill_registry()
        skill = registry.get(skill_name)
        if skill and skill.executor:
            return skill.executor
    if name in _EXPANDED_TOOL_MAP:
        from app.services.agents import expanded_skills
        skill_name = _EXPANDED_TOOL_MAP[name]
        registry = expanded_skills.build_expanded_skill_registry()
        skill = registry.get(skill_name)
        if skill and skill.executor:
            return skill.executor
    return None

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "list_findings",
            "description": "List active (not fixed/ignored) security findings for the organization. "
                           "Filter by severity, category (iac|secrets|cve) or cloud_provider (aws|gcp|azure).",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "category": {"type": "string"},
                    "cloud_provider": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_finding",
            "description": "Get full detail (code snippet, remediation, resource) for one finding by id.",
            "parameters": {
                "type": "object",
                "properties": {"finding_id": {"type": "integer"}},
                "required": ["finding_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_severity_breakdown",
            "description": "Get counts of active findings grouped by severity.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_risk_score",
            "description": "Get the org's overall risk score (0-100) and per-cloud breakdown.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cves",
            "description": "Search the CVE database by keyword and/or severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "severity": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_recent_scans",
            "description": "List the most recent scans with status and risk score.",
            "parameters": {
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    # ── Agentic write tools ─────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "triage_finding",
            "description": "Update a finding's triage status. Use this to auto-classify findings as "
                           "triaged, false_positive, in_progress, or resolved. Adds an audit note.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "description": "ID of the finding to triage"},
                    "status": {
                        "type": "string",
                        "enum": ["open", "triaged", "in_progress", "resolved", "false_positive"],
                        "description": "New triage status",
                    },
                    "reason": {"type": "string", "description": "Reason for the classification"},
                    "assigned_to": {"type": "string", "description": "Assign to a user (optional)"},
                },
                "required": ["finding_id", "status"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "auto_fix_finding",
            "description": "Preview the code fix for a finding from a connected repository. Reads the file "
                           "and returns a diff. Changes nothing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "description": "ID of the finding to fix"},
                },
                "required": ["finding_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remediate_cloud_finding",
            "description": "Fix a cloud posture finding (rule IDs starting GN-AWS-) by changing the resource in the "
                           "connected AWS account. Supported: GN-AWS-S3-001 (block bucket public access), "
                           "GN-AWS-SG-001 / GN-AWS-SG-002 (remove SSH / RDP open to the internet), GN-AWS-REGION-001 "
                           "(EBS default encryption), GN-AWS-KMS-001 (key rotation). A person sees the exact change "
                           "and must approve it; the previous settings are kept so it can be rolled back.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "description": "ID of the cloud posture finding"},
                },
                "required": ["finding_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "open_fix_pull_request",
            "description": "Open a pull request on the customer's repository that fixes a finding. A person "
                           "reviews the exact diff and must approve before anything is committed. Works on GitHub, GitLab, "
                           "Bitbucket Cloud and Azure DevOps (a merge request on GitLab).",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "description": "ID of the finding to fix"},
                },
                "required": ["finding_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_knowledge_stats",
            "description": "Get statistics about the AI's learned remediation patterns — success rates, "
                           "top patterns, and coverage across rule IDs.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    # ── Skill-promoted tools (advanced analytics) ───────────────────
    {
        "type": "function",
        "function": {
            "name": "check_compliance",
            "description": "Map active findings to compliance frameworks (CIS Benchmarks, SOC 2, PCI-DSS, HIPAA, NIST 800-53). "
                           "Returns findings grouped by framework with control IDs and gap analysis.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_attack_surface",
            "description": "Enumerate the organization's external attack surface: exposed secrets, public resources, "
                           "overprivileged IAM roles, unencrypted data stores, and vulnerable dependencies.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_posture_trend",
            "description": "Analyze the security posture trend over recent scans. Shows risk score trajectory "
                           "and whether the organization's security is improving or worsening.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_remediation_guide",
            "description": "Generate step-by-step remediation playbooks for the top critical findings. "
                           "Includes root cause, fix steps, verification commands, and prevention measures.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    # ── Investigation tools (advanced triage & incident response) ───
    {
        "type": "function",
        "function": {
            "name": "investigate_aws_iam",
            "description": "Deep investigation of AWS IAM misconfigurations: overprivileged roles, "
                           "unused credentials, policy violations, and privilege escalation paths.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_aws_network",
            "description": "Investigate AWS network security: open security groups, public subnets, "
                           "VPC flow log gaps, and network exposure analysis.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_azure_security",
            "description": "Investigate Azure security posture: Defender coverage, RBAC misconfigs, "
                           "NSG rules, Key Vault access, and Entra ID issues.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_gcp_security",
            "description": "Investigate GCP security: service account key misuse, firewall rules, "
                           "IAM bindings, and Cloud Armor coverage.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_terraform",
            "description": "Analyze Terraform/IaC misconfigurations: missing encryption, public access, "
                           "hardcoded secrets, and drift detection across modules.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_kubernetes",
            "description": "Investigate Kubernetes security: privileged containers, missing network policies, "
                           "RBAC over-permissions, and image vulnerabilities.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "incident_response",
            "description": "Generate an incident response playbook for a specific scenario: credential_exposure, "
                           "ransomware, unauthorized_access, data_breach, or general.",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_type": {
                        "type": "string",
                        "enum": ["credential_exposure", "ransomware", "unauthorized_access", "data_breach", "general"],
                        "description": "Type of incident for playbook generation",
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deep_compliance",
            "description": "Deep compliance mapping with specific control IDs across CIS, SOC2, PCI-DSS, "
                           "HIPAA, and NIST 800-53 frameworks. Maps findings to exact control numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["cis", "soc2", "pci_dss", "hipaa", "nist_800_53", "all"],
                        "description": "Target compliance framework",
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_supply_chain",
            "description": "Analyze supply chain security: outdated dependencies, known vulnerable packages, "
                           "typosquatting risks, and SBOM coverage assessment.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_secrets",
            "description": "Investigate exposed secrets and credentials: hardcoded API keys, leaked tokens, "
                           "rotation status, and secret sprawl across repositories.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    # ── Advanced investigation tools (12 enterprise-grade skills) ───
    {
        "type": "function",
        "function": {
            "name": "investigate_containers",
            "description": "Container runtime security analysis: Docker, containerd, CRI-O. Detects privileged "
                           "containers, root execution, missing seccomp profiles, mutable image tags, and CIS Docker controls.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_cicd",
            "description": "CI/CD pipeline security: GitHub Actions, GitLab CI, Jenkins. Detects secret exposure "
                           "in pipelines, runner compromise, weak branch protection, SLSA level assessment.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_api",
            "description": "API security assessment against OWASP API Top 10: BOLA, broken auth, excessive data "
                           "exposure, SSRF, mass assignment, rate limiting gaps, and GraphQL/gRPC risks.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_dns",
            "description": "DNS and domain security: dangling CNAME records, subdomain takeover risks, "
                           "SPF/DKIM/DMARC email authentication, DNSSEC, zone transfer exposure.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_tls",
            "description": "SSL/TLS certificate management: expired certificates, weak ciphers, deprecated "
                           "protocols (TLS 1.0/1.1), missing HSTS, OCSP stapling, certificate chain issues.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assess_zero_trust",
            "description": "Zero trust architecture assessment aligned to NIST SP 800-207. Evaluates identity, "
                           "network, device, and least-privilege maturity pillars with gap scoring.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_network_segmentation",
            "description": "Network segmentation analysis: flat network risks, public internet exposure (0.0.0.0/0), "
                           "open management ports (SSH/RDP), database exposure, lateral movement paths.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assess_endpoint_security",
            "description": "Endpoint and EDR posture assessment: malware indicators, patch compliance against CVEs, "
                           "EDR agent coverage gaps, vulnerability management SLA tracking.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_cost_anomalies",
            "description": "Cloud cost anomaly detection as security signal: cryptomining indicators, data "
                           "exfiltration via egress spikes, unauthorized compute scaling, billing abuse.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "threat_modeling",
            "description": "Threat modeling with STRIDE analysis and MITRE ATT&CK heatmap. Maps findings to "
                           "kill chain phases, identifies most-exposed attack vectors, prioritizes remediation.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assess_dlp",
            "description": "Data Loss Prevention assessment: encryption gaps, public storage exposure, "
                           "PII/PHI/PCI handling, regulatory risk mapping (GDPR, CCPA, HIPAA, PCI-DSS).",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assess_identity_governance",
            "description": "Identity and access governance: MFA coverage gaps, orphan/dormant accounts, "
                           "privilege creep, service account hygiene, SSO federation gaps, access review status.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    # ── Knowledge Graph tools ────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "query_blast_radius",
            "description": "Analyze blast radius of a compromised resource — traces all downstream entities "
                           "(services, findings, CVEs, identities) that would be affected. Returns severity "
                           "distribution and affected entity list.",
            "parameters": {
                "type": "object",
                "properties": {
                    "resource_id": {"type": "string", "description": "Entity ID (ARN, resource name, CVE-ID)"},
                    "depth": {"type": "integer", "description": "Max traversal depth (1-5, default 3)"},
                },
                "required": ["resource_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_related_entities",
            "description": "Find entities connected to a given resource in the knowledge graph — "
                           "upstream dependencies, downstream impacts, related CVEs and findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_id": {"type": "string", "description": "Entity ID to search from"},
                    "direction": {"type": "string", "enum": ["outgoing", "incoming", "both"], "description": "Traversal direction"},
                    "relationship": {"type": "string", "description": "Filter by relationship type (affects, depends_on, exposes, etc.)"},
                    "depth": {"type": "integer", "description": "Max traversal depth (1-4, default 2)"},
                },
                "required": ["entity_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_knowledge_graph",
            "description": "Search the knowledge graph for entities by name or type — find resources, "
                           "findings, CVEs, identities, services, and regions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (partial match on entity_id and label)"},
                    "entity_type": {"type": "string", "description": "Filter by type: resource, finding, cve, identity, service, region"},
                    "limit": {"type": "integer", "description": "Max results (default 20)"},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_graph_stats",
            "description": "Get knowledge graph statistics — total nodes, edges, and type distributions. "
                           "Useful for understanding the overall security posture topology.",
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        },
    },
    # ── Multi-agent delegation tool ─────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "delegate_to_agent",
            "description": "Delegate a sub-task to a specialist agent. Use when the current question "
                           "requires deep expertise in a specific domain (e.g., compliance, threat intel, "
                           "remediation). The target agent will have full access to the organization's data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_agent": {
                        "type": "string",
                        "description": "ID of the agent to delegate to (e.g., 'compliance_advisor', 'threat_intel', 'remediation').",
                    },
                    "task": {
                        "type": "string",
                        "description": "Clear description of the sub-task for the target agent.",
                    },
                    "context": {
                        "type": "string",
                        "description": "Relevant context from the current conversation to pass along.",
                    },
                },
                "required": ["target_agent", "task"],
                "additionalProperties": False,
            },
        },
    },
    # ── Threat Intelligence & Enrichment tools ──────────────────────
    {
        "type": "function",
        "function": {
            "name": "enrich_ioc",
            "description": "Enrich an Indicator of Compromise (IP, domain, file hash, URL) against threat intel "
                           "feeds. Returns reputation score, associated campaigns, MITRE techniques, and geo data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_value": {"type": "string", "description": "The IOC to enrich (IP address, domain, SHA256 hash, or URL)"},
                    "ioc_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"], "description": "Type of IOC"},
                },
                "required": ["ioc_value"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_reputation",
            "description": "Check domain or IP reputation — blocklist status, abuse history, ASN info, "
                           "geolocation, hosting provider, and historical threat associations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or domain name to check"},
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "map_mitre_attack",
            "description": "Map security findings to MITRE ATT&CK framework — techniques, tactics, and procedures. "
                           "Returns a heatmap of covered vs uncovered techniques with detection gaps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["all", "critical", "high"], "description": "Finding severity scope to map"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_anomalies",
            "description": "Statistical anomaly detection on security finding patterns — spikes in new findings, "
                           "severity distribution shifts, new categories appearing, unusual scan results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "lookback_days": {"type": "integer", "description": "Number of days to analyze (default 30)"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "predict_risk_trend",
            "description": "Predict risk score trajectory based on historical trends and current remediation velocity. "
                           "Returns forecast with confidence intervals and recommended actions to bend the curve.",
            "parameters": {
                "type": "object",
                "properties": {
                    "forecast_days": {"type": "integer", "description": "Days to forecast ahead (default 30, max 90)"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    # ── Cloud & Infrastructure Security tools ───────────────────────
    {
        "type": "function",
        "function": {
            "name": "scan_exposed_ports",
            "description": "Check for publicly exposed ports and services across cloud assets — identifies "
                           "open management ports (SSH/RDP), database ports, and unprotected APIs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp", "all"], "description": "Target cloud"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_iam_permissions",
            "description": "Deep IAM permission analysis — overprivileged roles, unused permissions, "
                           "privilege escalation paths, cross-account trust, and service account hygiene.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp", "all"], "description": "Target cloud"},
                    "focus": {"type": "string", "enum": ["overprivileged", "unused", "escalation", "all"], "description": "Analysis focus"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_encryption_posture",
            "description": "Audit encryption-at-rest and in-transit across all cloud services — storage, "
                           "databases, queues, and inter-service communication. Identifies gaps and weak algorithms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp", "all"], "description": "Target cloud"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assess_backup_security",
            "description": "Verify backup configurations — immutability, cross-region replication, retention "
                           "policies, encryption, and recovery testing status across cloud resources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp", "all"], "description": "Target cloud"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "evaluate_waf_rules",
            "description": "WAF and firewall rule analysis — detection gaps, overly permissive rules, "
                           "bypass potential, rule overlap, and recommendations for tightening.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp", "all"], "description": "Target cloud"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    # ── Code & Pipeline Security tools ──────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "scan_code_snippet",
            "description": "On-demand SAST analysis of a code snippet — detects hardcoded secrets, injection "
                           "vulnerabilities, insecure crypto, authentication flaws, and common CWEs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Code snippet to analyze"},
                    "language": {"type": "string", "description": "Programming language (python, javascript, go, java, terraform, yaml)"},
                },
                "required": ["code"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_dockerfile",
            "description": "Dockerfile security review — base image vulnerabilities, running as root, "
                           "secrets in build args, multi-stage build optimization, and CIS Docker controls.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dockerfile_content": {"type": "string", "description": "Dockerfile content to analyze"},
                },
                "required": ["dockerfile_content"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "review_github_actions",
            "description": "GitHub Actions workflow security review — command injection risks, excessive "
                           "permissions, secret exposure, unpinned actions, and supply chain risks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workflow_content": {"type": "string", "description": "GitHub Actions YAML content to review"},
                },
                "required": ["workflow_content"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_dependency_health",
            "description": "Dependency health assessment — maintenance status, update frequency, known CVEs, "
                           "license compatibility, and alternatives for deprecated packages.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ecosystem": {"type": "string", "enum": ["npm", "pip", "maven", "go", "nuget", "all"], "description": "Package ecosystem"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    # ── Compliance & Governance tools ───────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "generate_audit_report",
            "description": "Generate a compliance audit report for a specific framework — structured with "
                           "control assessments, evidence mapping, gap analysis, and remediation timeline.",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["soc2", "pci_dss", "hipaa", "iso27001", "nist_csf", "cis"],
                        "description": "Target compliance framework",
                    },
                    "format": {"type": "string", "enum": ["summary", "detailed", "executive"], "description": "Report detail level"},
                },
                "required": ["framework"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_policy_violations",
            "description": "Evaluate cloud resources against security policy rules — identifies violations "
                           "of tagging policies, naming conventions, encryption requirements, and access controls.",
            "parameters": {
                "type": "object",
                "properties": {
                    "policy_type": {
                        "type": "string",
                        "enum": ["encryption", "access_control", "network", "tagging", "all"],
                        "description": "Type of policies to check",
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "track_compliance_drift",
            "description": "Compare current compliance posture against a previous baseline — identifies new "
                           "violations, resolved gaps, and trending compliance score over time.",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {"type": "string", "description": "Compliance framework to track"},
                    "lookback_days": {"type": "integer", "description": "Days to compare against (default 30)"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "map_data_flows",
            "description": "Map data flows for privacy assessments — identifies where PII/PHI/PCI data is "
                           "stored, processed, and transmitted. Flags cross-border transfers and encryption gaps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "data_type": {"type": "string", "enum": ["pii", "phi", "pci", "all"], "description": "Data classification type"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    # ── Response & Automation tools ─────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "draft_ticket",
            "description": "Draft the text of a ticket for a security finding (summary, description, priority, "
                           "labels) for a person to file. No ticketing system is connected, so nothing is created.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "description": "Finding ID to create ticket for"},
                    "project_key": {"type": "string", "description": "Jira project key (e.g., SEC)"},
                    "assignee": {"type": "string", "description": "Assign to user (optional)"},
                    "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Ticket priority"},
                },
                "required": ["finding_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_slack_message",
            "description": "Post a security alert to the organization's connected Slack channel. A person must "
                           "approve the exact message first. Fails if Slack is not connected.",
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Alert message content (Slack markdown)"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Alert severity"},
                    "finding_id": {"type": "integer", "description": "Related finding ID (optional)"},
                },
                "required": ["message"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "quarantine_resource",
            "description": "Write the plan for isolating a potentially compromised cloud resource (restrictive "
                           "security group, disabled access keys, revoked tokens, snapshot and stop), with rollback "
                           "steps. Returns a plan only; it changes nothing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "resource_id": {"type": "string", "description": "Cloud resource ARN or ID to quarantine"},
                    "action": {
                        "type": "string",
                        "enum": ["isolate_network", "disable_key", "revoke_token", "snapshot_and_stop"],
                        "description": "Quarantine action to take",
                    },
                    "dry_run": {"type": "boolean", "description": "Preview only (true) or execute (false)", "default": True},
                },
                "required": ["resource_id", "action"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_runbook",
            "description": "Generate a step-by-step operational runbook for a security scenario — includes "
                           "pre-checks, execution steps, verification, rollback, and communication templates.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scenario": {
                        "type": "string",
                        "description": "Security scenario (e.g., 'credential rotation', 'incident response', 'patch deployment')",
                    },
                    "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp", "multi"], "description": "Target cloud"},
                },
                "required": ["scenario"],
                "additionalProperties": False,
            },
        },
    },
]

from app.services.agents.cloud_skills import SCHEMAS as _CLOUD_SCHEMAS  # noqa: E402

TOOL_SCHEMAS.extend(_CLOUD_SCHEMAS)

from app.services.agents.chat_files import SCHEMAS as _CHAT_FILE_SCHEMAS  # noqa: E402

TOOL_SCHEMAS.extend(_CHAT_FILE_SCHEMAS)

from app.services.agents.triage_tools import SCHEMAS as _TRIAGE_SCHEMAS  # noqa: E402

TOOL_SCHEMAS.extend(_TRIAGE_SCHEMAS)


async def execute_tool(ctx: ToolContext, name: str, arguments: dict, *, allow_writes: bool = False) -> str:
    """Run a tool. Tools that change something run only for an approved agent
    run (``allow_writes``); chat and other callers get a refusal instead."""
    executor = _resolve_executor(name)
    if not executor:
        return json.dumps({"error": f"unknown tool: {name}"})
    if tool_risk(name) != READ and not allow_writes:
        return json.dumps({
            "error": f"{name} changes data and needs approval. It was not run. "
                     "Ask the user to start this as a task on the Agent Runs page, where it can be approved.",
        })
    try:
        result = await executor(ctx, **(arguments or {}))
    except TypeError as e:
        return json.dumps({"error": f"bad arguments for {name}: {e}"})
    except Exception as e:  # noqa: BLE001 - surface to model, don't crash the turn
        return json.dumps({"error": str(e)})
    return json.dumps(result, default=str)

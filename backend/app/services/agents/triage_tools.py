"""The triage queue: what is waiting for a decision, with the evidence to decide on.

``list_triage_queue`` is a read tool. It lists open findings from the *latest*
assessment of each target only, so the same finding is not offered once per
scan, and attaches the facts a person would look up before deciding:

* whether the CVE is being exploited (CISA KEV) and how likely exploitation is (EPSS);
* how long the finding has been around and in how many assessments it appeared;
* whether the path looks like test or example code. That is a hint to check, never a verdict;
* for cloud findings, that the resource is real and running in a connected account.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, select

from app.models.cve import CVE
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import sla

MAX_PAGE = 100         # a page with its evidence must fit in what the model is shown of one tool result
_RANK = case(
    (func.upper(Finding.severity) == "CRITICAL", 0), (func.upper(Finding.severity) == "HIGH", 1),
    (func.upper(Finding.severity) == "MEDIUM", 2), (func.upper(Finding.severity) == "LOW", 3), else_=4,
)
_TEST_DIRS = ("test/", "tests/", "example/", "examples/", "demo/", "docs/", "fixtures/", "mock/", "samples/")
_TEST_FILES = ("test_", "_test.", ".test.", ".spec.", "example", "sample", "fixture")


def test_path_hint(path: str | None) -> str | None:
    """Why a path looks like non-production code, or None. Used as a hint only."""
    low = (path or "").lower()
    if not low:
        return None
    for marker in _TEST_DIRS:
        if low.startswith(marker) or f"/{marker}" in low:
            return f"path contains '{marker}'"
    name = low.rsplit("/", 1)[-1]
    for marker in _TEST_FILES:
        if marker in name:
            return f"file name contains '{marker}'"
    return None


def scan_target(scan: Scan) -> Any:
    if scan.scan_type == "cloud_posture":
        return ("cloud", scan.source or scan.id, scan.account_name)
    if scan.repository or scan.repository_name:
        return ("repo", scan.account_name, scan.repository or scan.repository_name)
    return ("file", scan.file_name or scan.id)


def target_label(scan: Scan) -> str:
    kind, *rest = scan_target(scan)
    if kind == "repo":
        return "/".join(str(p) for p in rest if p)
    if kind == "cloud":
        return f"cloud account {rest[1] or rest[0]}"
    return f"uploaded file {rest[0]}"


async def latest_scans(db, organization_id: int) -> dict[int, Scan]:
    """The newest completed assessment of each target, by scan id."""
    scans = (await db.execute(
        select(Scan).where(Scan.organization_id == organization_id, Scan.status == "completed").order_by(Scan.id.desc())
    )).scalars().all()
    latest: dict[Any, Scan] = {}
    for scan in scans:
        latest.setdefault(scan_target(scan), scan)
    return {scan.id: scan for scan in latest.values()}


async def internet_facing(ctx) -> dict[str, str]:
    """Cloud resources that can be reached from the internet: resource id -> why.

    Uses the same joins as the ``internet_exposure`` tool: an open security group
    counts only through a running instance with a public address that uses it.
    """
    from app.services.agents.cloud_skills import WORLD, _open_ports, _resources

    rows = await _resources(
        ctx, "aws_security_group", "aws_ec2_instance", "aws_rds_instance", "aws_lb", "aws_eks_cluster", "aws_s3_bucket",
    )
    by_type: dict[str, list] = {}
    for r in rows:
        by_type.setdefault(r.resource_type, []).append(r)
    groups = {r.config.get("group_id"): r for r in by_type.get("aws_security_group", [])}
    open_groups = {gid: _open_ports(g.config) for gid, g in groups.items() if _open_ports(g.config)}

    why: dict[str, str] = {}
    for inst in by_type.get("aws_ec2_instance", []):
        c = inst.config
        if c.get("state") != "running" or not c.get("has_public_ip"):
            continue
        used = [gid for gid in c.get("security_groups") or [] if gid in open_groups]
        ports = sorted({p for gid in used for p in open_groups[gid]})
        if ports:
            why[inst.resource_id] = f"yes: running with a public address, open to the internet on {', '.join(ports[:4])}"
            for gid in used:
                why[groups[gid].resource_id] = f"yes: attached to the public instance {inst.resource_name}"
    for db in by_type.get("aws_rds_instance", []):
        if db.config.get("publicly_accessible"):
            why[db.resource_id] = "yes: the database is publicly accessible"
    for lb in by_type.get("aws_lb", []):
        if lb.config.get("internet_facing"):
            why[lb.resource_id] = "yes: internet-facing load balancer"
    for cluster in by_type.get("aws_eks_cluster", []):
        if cluster.config.get("endpoint_public_access") and set(cluster.config.get("public_access_cidrs") or []) & WORLD:
            why[cluster.resource_id] = "yes: the Kubernetes API endpoint is open to the internet"
    for bucket in by_type.get("aws_s3_bucket", []):
        block = bucket.config.get("public_access_block")
        if not block or not all(block.values()):
            why[bucket.resource_id] = "possibly: the bucket does not block public access"
    for gid, ports in open_groups.items():
        why.setdefault(groups[gid].resource_id, "no: open to the internet in its rules, but no public instance uses it")
    return why


async def triage_queue(ctx, severity: str = "", target: str = "", limit: int = 60, offset: int = 0, **_: Any) -> dict:
    scans = await latest_scans(ctx.db, ctx.organization_id)
    if target:
        scans = {i: s for i, s in scans.items() if target.lower() in target_label(s).lower()}
    if not scans:
        return {"waiting": 0, "findings": [], "note": "There is no completed assessment to triage."}

    waiting = [
        Finding.scan_id.in_(scans), Finding.status == "open",
        Finding.is_fixed == False, Finding.is_ignored == False,  # noqa: E712
    ]
    by_severity = dict((await ctx.db.execute(
        select(func.upper(Finding.severity), func.count(Finding.id)).where(*waiting).group_by(func.upper(Finding.severity))
    )).all())
    page_filter = [*waiting, func.upper(Finding.severity) == severity.upper()] if severity else waiting
    limit = max(1, min(int(limit or 60), MAX_PAGE))
    offset = max(0, int(offset or 0))
    rows = (await ctx.db.execute(
        select(Finding).where(*page_filter).order_by(_RANK, Finding.id).offset(offset).limit(limit)
    )).scalars().all()

    cve_ids = {f.cve_id for f in rows if f.cve_id}
    cves = {
        c.cve_id: c for c in (await ctx.db.execute(select(CVE).where(CVE.cve_id.in_(cve_ids)))).scalars().all()
    } if cve_ids else {}

    # How often, and since when, each of these has been reported in this organization.
    history: dict[tuple, tuple[int, Any]] = {}
    rule_ids = {f.rule_id for f in rows}
    if rule_ids:
        for rule, path, resource, seen, first in (await ctx.db.execute(
            select(Finding.rule_id, Finding.file_path, Finding.resource_name,
                   func.count(func.distinct(Finding.scan_id)), func.min(Finding.created_at))
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.organization_id == ctx.organization_id, Finding.rule_id.in_(rule_ids))
            .group_by(Finding.rule_id, Finding.file_path, Finding.resource_name)
        )).all():
            history[(rule or "", path or "", resource or "")] = (seen, first)

    # How many findings in the queue fail the same rule on the same target: one cause, one decision.
    same_rule = {
        (scan_id, rule): n for scan_id, rule, n in (await ctx.db.execute(
            select(Finding.scan_id, Finding.rule_id, func.count(Finding.id)).where(*waiting)
            .where(Finding.rule_id.in_(rule_ids)).group_by(Finding.scan_id, Finding.rule_id)
        )).all()
    } if rule_ids else {}
    exposed = await internet_facing(ctx) if any(scans[f.scan_id].scan_type == "cloud_posture" for f in rows) else {}

    findings = []
    for f in rows:
        scan = scans[f.scan_id]
        seen, first = history.get((f.rule_id or "", f.file_path or "", f.resource_name or ""), (1, f.created_at))
        item = {
            "id": f.id, "severity": (f.severity or "").upper(), "rule_id": f.rule_id, "title": (f.title or "")[:110],
            "category": f.category, "found_by": f.detected_by, "target": target_label(scan),
            "file_path": f.file_path, "line": f.line_number, "resource": (f.resource_name or "")[:90],
            "first_seen": first.date().isoformat() if first else None,
        }
        item = {k: v for k, v in item.items() if v not in (None, "")}
        if f.sla_deadline:                      # how long is left to fix it, by the remediation policy
            item["sla_deadline"] = f.sla_deadline.date().isoformat()
            item["sla_status"] = sla.status(f)
        if seen > 1:
            item["seen_in_assessments"] = seen
        if same_rule.get((f.scan_id, f.rule_id), 1) > 1:
            item["same_rule_on_this_target"] = same_rule[(f.scan_id, f.rule_id)]
        if scan.scan_type == "cloud_posture":
            item["live_cloud_resource"] = True          # a real resource fails this check; it is not test code
            reason = exposed.get((f.metadata_ or {}).get("resource_id"))
            item["internet_facing"] = reason or "no public exposure found for this resource"
        hint = test_path_hint(f.file_path)
        if hint:
            item["looks_like_test_code"] = f"{hint}. Check the content before calling it a false positive."
        cve = cves.get(f.cve_id) if f.cve_id else None
        if f.cve_id:
            item["cve"] = {
                "id": f.cve_id,
                "known_exploited": bool(cve and cve.is_kev),
                "exploit_probability": round(cve.epss_score, 3) if cve and cve.epss_score is not None else None,
                "cvss": cve.cvss_score if cve else None,
            }
        findings.append(item)

    total = sum(by_severity.values())
    matching = by_severity.get(severity.upper(), 0) if severity else total
    return {
        "waiting": total, "waiting_by_severity": by_severity,
        "returned": len(findings), "offset": offset,
        "next_offset": offset + len(findings) if offset + len(findings) < matching else None,
        "findings": findings,
        "note": "Only the latest assessment of each target is listed. A decision is also applied to the same "
                "finding in older assessments and kept on future ones.",
    }


EXECUTORS = {"list_triage_queue": triage_queue}

SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "list_triage_queue",
            "description": "Open findings waiting for a triage decision, most severe first, from the latest "
                           "assessment of each repository and cloud account. Each comes with evidence: whether "
                           "its CVE is known to be exploited, how long it has been open, and whether the path "
                           "looks like test code. Use offset to page through the queue.",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "target": {"type": "string", "description": "Part of a repository or cloud account name"},
                    "limit": {"type": "integer", "description": "How many to return: 60 by default, 100 at most"},
                    "offset": {"type": "integer"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "triage_findings",
            "description": "Propose triage decisions for many findings at once (400 findings at most). Findings "
                           "that share a cause can share one decision through finding_ids. A person reviews the "
                           "whole list once and approves or rejects it; nothing changes before that. Use this "
                           "instead of calling triage_finding repeatedly. 'false_positive' and 'resolved' take a "
                           "finding off the open list and each needs a specific reason based on what you read.",
            "parameters": {
                "type": "object",
                "properties": {
                    "decisions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "finding_id": {"type": "integer", "description": "One finding"},
                                "finding_ids": {
                                    "type": "array", "items": {"type": "integer"},
                                    "description": "Several findings with the same cause that get the same decision "
                                                   "and reason (for example one rule failing in many files). "
                                                   "Use instead of finding_id.",
                                },
                                "status": {"type": "string", "enum": ["triaged", "in_progress", "false_positive", "resolved"]},
                                "reason": {"type": "string", "description": "Why, in one sentence, citing the evidence"},
                            },
                            "required": ["status", "reason"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["decisions"],
                "additionalProperties": False,
            },
        },
    },
]

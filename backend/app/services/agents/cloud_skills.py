"""Agent tools that answer from the cloud inventory.

Everything here reads the resources synced from connected cloud accounts and
the posture findings raised on them. When the data a tool needs has not been
synced, it returns ``data_source: not_connected`` with what to connect, rather
than an estimate.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Optional

from sqlalchemy import func, select

from app.models.cloud_resource import CloudResource
from app.models.finding import Finding
from app.services.cloud_posture.engine import DETECTED_BY
from app.services.cloud_posture.rules import ADMIN_PORTS, SENSITIVE_PORTS, WORLD, _covers, _world_ports

_MAX = 50


def not_connected(what: str, how: str) -> dict:
    return {"data_source": "not_connected", "message": f"{what} {how}", "results": []}


_NO_CLOUD = (
    "No synced cloud resources of the kind this needs were found.",
    "Connect an AWS account under Cloud Connectors and run a sync, then ask again.",
)


async def _resources(ctx, *types: str) -> list[CloudResource]:
    stmt = select(CloudResource).where(
        CloudResource.organization_id == ctx.organization_id, CloudResource.status == "active",
    )
    if types:
        stmt = stmt.where(CloudResource.resource_type.in_(types))
    if ctx.meta.get("cloud_account"):            # one account's page: only that account's resources
        stmt = stmt.where(CloudResource.account_id == ctx.meta["cloud_account"])
    return list((await ctx.db.execute(stmt.order_by(CloudResource.resource_type, CloudResource.resource_name))).scalars().all())


async def _posture_findings(ctx, *, rule_prefixes: tuple[str, ...] = (), categories: tuple[str, ...] = ()) -> list[Finding]:
    stmt = select(Finding).where(
        Finding.organization_id == ctx.organization_id, Finding.detected_by == DETECTED_BY,
        Finding.is_fixed == False, Finding.is_ignored == False,  # noqa: E712
    )
    rows = list((await ctx.db.execute(stmt)).scalars().all())
    if rule_prefixes:
        rows = [f for f in rows if f.rule_id.startswith(rule_prefixes)]
    if categories:
        rows = [f for f in rows if f.category in categories]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(rows, key=lambda f: (order.get(f.severity, 4), f.id))


def _brief(r: CloudResource) -> dict:
    return {"type": r.resource_type, "name": r.resource_name, "id": r.resource_id, "region": r.region, "account": r.account_id}


def _finding(f: Finding) -> dict:
    return {
        "finding_id": f.id, "rule_id": f.rule_id, "severity": f.severity, "title": f.title,
        "resource": f.resource_name, "resource_type": f.resource_type, "detail": f.description,
        "remediation": f.remediation,
    }


def _public_config(config: dict) -> dict:
    return {k: v for k, v in (config or {}).items() if not k.startswith("_")} | (
        {"could_not_be_read": config["_unreadable"]} if (config or {}).get("_unreadable") else {}
    )


# ── inventory ───────────────────────────────────────────────────────

async def cloud_inventory_summary(ctx, **_: Any) -> dict:
    """What is connected and synced: accounts, resource counts by type and region."""
    from app.models.cloud_account import CloudAccount

    accounts = (await ctx.db.execute(
        select(CloudAccount).where(CloudAccount.organization_id == ctx.organization_id)
    )).scalars().all()
    counts = (await ctx.db.execute(
        select(CloudResource.provider, CloudResource.resource_type, func.count(CloudResource.id))
        .where(CloudResource.organization_id == ctx.organization_id, CloudResource.status == "active")
        .group_by(CloudResource.provider, CloudResource.resource_type)
    )).all()
    if not accounts and not counts:
        return not_connected("No cloud account is connected.", _NO_CLOUD[1])
    regions = (await ctx.db.execute(
        select(CloudResource.region, func.count(CloudResource.id))
        .where(CloudResource.organization_id == ctx.organization_id, CloudResource.status == "active")
        .group_by(CloudResource.region)
    )).all()
    return {
        "accounts": [
            {"name": a.name, "provider": a.provider, "account": a.account_identifier, "status": a.status,
             "last_synced": a.last_synced_at.isoformat() if a.last_synced_at else None, "last_error": a.last_error}
            for a in accounts
        ],
        "total_resources": sum(n for _, _, n in counts),
        "by_type": {f"{p}:{t}": n for p, t, n in sorted(counts)},
        "by_region": {r or "global": n for r, n in regions},
    }


async def list_cloud_resources(ctx, resource_type: str = "", name_contains: str = "", region: str = "",
                               limit: int = 25, **_: Any) -> dict:
    """List synced cloud resources with their configuration."""
    rows = await _resources(ctx, *([resource_type] if resource_type else []))
    if not rows:
        return not_connected(_NO_CLOUD[0], _NO_CLOUD[1])
    if name_contains:
        rows = [r for r in rows if name_contains.lower() in (r.resource_name or "").lower()]
    if region:
        rows = [r for r in rows if r.region == region]
    limit = max(1, min(int(limit or 25), _MAX))
    return {
        "count": len(rows), "returned": min(len(rows), limit),
        "resources": [{**_brief(r), "config": _public_config(r.config)} for r in rows[:limit]],
    }


async def get_cloud_resource(ctx, resource: str = "", **_: Any) -> dict:
    """One resource by ARN or exact name, with the posture findings open on it."""
    rows = [r for r in await _resources(ctx) if resource in (r.resource_id, r.resource_name)]
    if not rows:
        return {"error": f"No synced resource has the ARN or name '{resource}'."}
    r = rows[0]
    findings = [f for f in await _posture_findings(ctx) if (f.metadata_ or {}).get("resource_id") == r.resource_id]
    return {
        **_brief(r), "tags": r.tags or {}, "config": _public_config(r.config),
        "last_synced": r.last_synced.isoformat() if r.last_synced else None,
        "open_findings": [_finding(f) for f in findings],
    }


async def cloud_posture_summary(ctx, **_: Any) -> dict:
    """Open cloud posture findings by severity and rule, and what could not be checked."""
    from app.models.scan import Scan

    scans = (await ctx.db.execute(
        select(Scan).where(Scan.organization_id == ctx.organization_id, Scan.scan_type == "cloud_posture")
    )).scalars().all()
    if not scans:
        return not_connected("No cloud account has been evaluated yet.", _NO_CLOUD[1])
    findings = await _posture_findings(ctx)
    by_rule = Counter((f.rule_id, f.title, f.severity) for f in findings)
    return {
        "accounts": [
            {"account": s.account_name, "last_evaluated": s.completed_at.isoformat() if s.completed_at else None,
             "risk_score": s.risk_score,
             **{k: (s.stage_details or {}).get(k) for k in
                ("resources", "checks", "passed", "failed", "not_checked", "not_checked_examples")}}
            for s in scans
        ],
        "open_findings": len(findings),
        "by_severity": dict(Counter(f.severity for f in findings)),
        "by_rule": [
            {"rule_id": rid, "title": title, "severity": sev, "resources_failing": n}
            for (rid, title, sev), n in by_rule.most_common(30)
        ],
        "most_urgent": [_finding(f) for f in findings[:10]],
    }


# ── exposure ────────────────────────────────────────────────────────

def _open_ports(config: dict) -> list[str]:
    rules = _world_ports(config)
    if any(r[2] == "-1" for r in rules):
        return ["all ports"]
    named = {**ADMIN_PORTS, **SENSITIVE_PORTS, 80: "HTTP", 443: "HTTPS"}
    hits = [f"{name} ({port})" for port, name in sorted(named.items()) if any(_covers(r, port) for r in rules)]
    other = [f"{r[0]}-{r[1]}/{r[2]}" for r in rules if not any(_covers(r, p) for p in named)]
    return hits + other


async def internet_exposure(ctx, **_: Any) -> dict:
    """What is actually reachable from the internet, joined across resources.

    An open security group only matters when something with a public address
    uses it, so instances are matched to their groups.
    """
    rows = await _resources(
        ctx, "aws_security_group", "aws_ec2_instance", "aws_rds_instance", "aws_lb", "aws_eks_cluster", "aws_s3_bucket",
    )
    if not rows:
        return not_connected(_NO_CLOUD[0], _NO_CLOUD[1])
    by_type: dict[str, list[CloudResource]] = {}
    for r in rows:
        by_type.setdefault(r.resource_type, []).append(r)

    groups = {r.config.get("group_id"): r for r in by_type.get("aws_security_group", [])}
    open_groups = {gid: _open_ports(g.config) for gid, g in groups.items() if _open_ports(g.config)}

    instances = []
    for inst in by_type.get("aws_ec2_instance", []):
        c = inst.config
        if c.get("state") != "running" or not c.get("has_public_ip"):
            continue
        ports = sorted({p for gid in c.get("security_groups") or [] for p in open_groups.get(gid, [])})
        if ports:
            instances.append({**_brief(inst), "public_ip": c.get("public_ip"), "open_to_internet": ports,
                              "imdsv1_allowed": (c.get("metadata_options") or {}).get("http_tokens") != "required"})
    used = {g for inst in by_type.get("aws_ec2_instance", []) for g in inst.config.get("security_groups") or []}

    return {
        "instances_reachable_from_internet": instances,
        "public_databases": [
            {**_brief(r), "engine": r.config.get("engine"), "encrypted": r.config.get("storage_encrypted")}
            for r in by_type.get("aws_rds_instance", []) if r.config.get("publicly_accessible")
        ],
        "internet_facing_load_balancers": [
            {**_brief(r), "dns_name": r.config.get("dns_name"), "waf": r.config.get("waf_web_acl"),
             "listeners": r.config.get("listeners")}
            for r in by_type.get("aws_lb", []) if r.config.get("internet_facing")
        ],
        "public_kubernetes_endpoints": [
            _brief(r) for r in by_type.get("aws_eks_cluster", [])
            if r.config.get("endpoint_public_access") and set(r.config.get("public_access_cidrs") or []) & WORLD
        ],
        "open_security_groups": [
            {**_brief(groups[gid]), "group_id": gid, "open_to_internet": ports,
             "attached_to_an_instance": gid in used if by_type.get("aws_ec2_instance") else None}
            for gid, ports in open_groups.items()
        ][:_MAX],
        "buckets_without_public_access_block": [
            f.resource_name for f in await _posture_findings(ctx, rule_prefixes=("GN-AWS-S3-001",))
        ],
    }


# ── focused views (same names as the earlier keyword-based tools) ────

async def _view(ctx, types: tuple[str, ...], *, rule_prefixes: tuple[str, ...] = (), categories: tuple[str, ...] = (),
                describe=None) -> dict:
    rows = await _resources(ctx, *types)
    if not rows:
        return not_connected(_NO_CLOUD[0], _NO_CLOUD[1])
    findings = await _posture_findings(ctx, rule_prefixes=rule_prefixes, categories=categories)
    out: dict[str, Any] = {
        "resources_examined": dict(Counter(r.resource_type for r in rows)),
        "open_findings": len(findings),
        "by_severity": dict(Counter(f.severity for f in findings)),
        "findings": [_finding(f) for f in findings[:_MAX]],
    }
    if describe:
        out["details"] = [describe(r) for r in rows[:_MAX]]
    return out


async def scan_exposed_ports(ctx, **_: Any) -> dict:
    return await internet_exposure(ctx)


async def audit_iam_permissions(ctx, **_: Any) -> dict:
    return await _view(
        ctx, ("aws_iam_user", "aws_iam_role", "aws_account"), rule_prefixes=("GN-AWS-IAM", "GN-AWS-ACCT-00"),
        describe=lambda r: {
            **_brief(r), "admin": r.config.get("has_admin_access"), "mfa": r.config.get("mfa_enabled"),
            "console_access": r.config.get("has_console_access"), "cross_account": r.config.get("allows_cross_account"),
            "attached_policies": r.config.get("attached_policies"),
        } if r.resource_type != "aws_account" else {**_brief(r), **_public_config(r.config)},
    )


async def check_encryption_posture(ctx, **_: Any) -> dict:
    return await _view(
        ctx, ("aws_s3_bucket", "aws_rds_instance", "aws_ebs_volume", "aws_kms_key", "aws_region_settings",
              "aws_cloudtrail_trail", "aws_lb", "aws_eks_cluster", "aws_acm_certificate"),
        categories=("encryption",),
    )


async def assess_backup_security(ctx, **_: Any) -> dict:
    return await _view(
        ctx, ("aws_rds_instance", "aws_s3_bucket"), rule_prefixes=("GN-AWS-RDS-003", "GN-AWS-RDS-004", "GN-AWS-S3-002"),
        describe=lambda r: {
            **_brief(r), "backup_retention_days": r.config.get("backup_retention_period"),
            "deletion_protection": r.config.get("deletion_protection"), "multi_az": r.config.get("multi_az"),
        } if r.resource_type == "aws_rds_instance" else {**_brief(r), "versioning": (r.config.get("versioning") or {}).get("status")},
    )


async def evaluate_waf_rules(ctx, **_: Any) -> dict:
    out = await _view(
        ctx, ("aws_lb",), rule_prefixes=("GN-AWS-LB-003",),
        describe=lambda r: {**_brief(r), "internet_facing": r.config.get("internet_facing"), "type": r.config.get("type"),
                            "waf_web_acl": r.config.get("waf_web_acl")},
    )
    if "details" in out:
        out["note"] = "Shows which load balancers have a WAF web ACL attached. The rules inside each web ACL are not synced."
    return out


async def investigate_dns_security(ctx, **_: Any) -> dict:
    out = await _view(
        ctx, ("aws_route53_zone",), rule_prefixes=("GN-AWS-DNS",),
        describe=lambda r: {**_brief(r), "private": r.config.get("private"), "records": r.config.get("record_count"),
                            "pointer_records": len(r.config.get("pointer_records") or [])},
    )
    if "details" in out:
        out["note"] = "Covers Route 53 only. Email authentication records (SPF, DKIM, DMARC) are not checked yet."
    return out


async def investigate_tls_security(ctx, **_: Any) -> dict:
    return await _view(
        ctx, ("aws_acm_certificate", "aws_lb"), rule_prefixes=("GN-AWS-ACM", "GN-AWS-LB-001", "GN-AWS-LB-002"),
        describe=lambda r: {**_brief(r), "expires": r.config.get("not_after"), "in_use": r.config.get("in_use"),
                            "status": r.config.get("status")} if r.resource_type == "aws_acm_certificate"
        else {**_brief(r), "listeners": r.config.get("listeners")},
    )


# ── tools whose data source does not exist yet ──────────────────────

def _unavailable(what: str, how: str):
    async def tool(ctx, **_: Any) -> dict:
        return not_connected(what, how)
    return tool


assess_endpoint_security = _unavailable(
    "No endpoint protection (EDR) product is connected, so endpoint coverage and detections are unknown.",
    "GuardNous has no EDR connector yet.",
)
detect_cost_anomalies = _unavailable(
    "Cloud billing data is not synced, so cost anomalies cannot be detected.",
    "GuardNous does not read AWS Cost Explorer yet.",
)
enrich_ioc = _unavailable(
    "No threat intelligence source is connected, so this indicator cannot be enriched.",
    "GuardNous has no threat intelligence connector yet. Findings can still be searched with list_findings.",
)
check_reputation = _unavailable(
    "No reputation source is connected, so this address or domain cannot be rated.",
    "GuardNous has no threat intelligence connector yet.",
)

EXECUTORS = {
    "cloud_inventory_summary": cloud_inventory_summary,
    "list_cloud_resources": list_cloud_resources,
    "get_cloud_resource": get_cloud_resource,
    "cloud_posture_summary": cloud_posture_summary,
    "internet_exposure": internet_exposure,
    "scan_exposed_ports": scan_exposed_ports,
    "audit_iam_permissions": audit_iam_permissions,
    "check_encryption_posture": check_encryption_posture,
    "assess_backup_security": assess_backup_security,
    "evaluate_waf_rules": evaluate_waf_rules,
    "investigate_dns": investigate_dns_security,
    "investigate_tls": investigate_tls_security,
    "assess_endpoint_security": assess_endpoint_security,
    "detect_cost_anomalies": detect_cost_anomalies,
    "enrich_ioc": enrich_ioc,
    "check_reputation": check_reputation,
}


def _schema(name: str, description: str, properties: Optional[dict] = None, required: Optional[list] = None) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties or {}, "required": required or [], "additionalProperties": False},
    }}


SCHEMAS = [
    _schema("cloud_inventory_summary",
            "Which cloud accounts are connected, when they last synced, and how many resources of each type and region exist."),
    _schema("list_cloud_resources",
            "List real cloud resources synced from connected accounts, with their configuration.",
            {"resource_type": {"type": "string", "description": "e.g. aws_s3_bucket, aws_security_group, aws_rds_instance, "
                                                                "aws_iam_user, aws_lb, aws_eks_cluster, aws_kms_key, aws_vpc"},
             "name_contains": {"type": "string"}, "region": {"type": "string"}, "limit": {"type": "integer"}}),
    _schema("get_cloud_resource", "Full configuration of one cloud resource and the posture findings open on it.",
            {"resource": {"type": "string", "description": "ARN or exact resource name"}}, ["resource"]),
    _schema("cloud_posture_summary",
            "Open cloud posture findings for connected accounts: by severity and rule, most urgent first, and which "
            "checks could not be run because a setting was unreadable."),
    _schema("internet_exposure",
            "What is actually reachable from the internet in connected cloud accounts: running instances with a public "
            "address behind open security groups, public databases, internet-facing load balancers, public Kubernetes "
            "endpoints and buckets without a public access block."),
]

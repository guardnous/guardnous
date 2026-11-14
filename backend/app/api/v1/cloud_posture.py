"""Cloud posture: what the fixed rules found on synced cloud resources."""
from __future__ import annotations

from collections import Counter
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.cloud_account import CloudAccount
from app.models.cloud_resource import CloudChange
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.services.agents import cloud_skills
from app.services.agents.tools import ToolContext
from app.services.cloud_posture import remediation
from app.services.cloud_posture.engine import DETECTED_BY, SCAN_TYPE, evaluate_organization
from app.services.cloud_posture.rules import RULES

router = APIRouter()

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _change_out(c: CloudChange) -> dict:
    return {
        "id": c.id, "finding_id": c.finding_id, "run_id": c.run_id, "rule_id": c.rule_id, "action": c.action,
        "resource_name": c.resource_name, "account_id": c.account_id, "region": c.region, "status": c.status,
        "requested_by": c.requested_by, "approved_by": c.approved_by, "rolled_back_by": c.rolled_back_by,
        "created_at": c.created_at, "rolled_back_at": c.rolled_back_at,
    }


@router.get("")
async def posture(
    account_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("findings", "read")),
):
    """What the Cloud Posture pages show for the caller's organization:
    every connected account, or one of them when ``account_id`` is given."""
    org = user.organization_id
    accounts = (await db.execute(
        select(CloudAccount).where(CloudAccount.organization_id == org).order_by(CloudAccount.provider, CloudAccount.name)
    )).scalars().all()
    scans = (await db.execute(
        select(Scan).where(Scan.organization_id == org, Scan.scan_type == SCAN_TYPE)
    )).scalars().all()
    findings = (await db.execute(
        select(Finding).where(
            Finding.organization_id == org, Finding.detected_by == DETECTED_BY,
            Finding.is_fixed == False, Finding.is_ignored == False,  # noqa: E712
        )
    )).scalars().all()

    source_of = lambda a: f"cloud://{a.provider}/{a.account_identifier}"  # noqa: E731 - how the engine names an account's scan
    scan_of = {s.source: s for s in scans}
    found_in = lambda f: (f.metadata_ or {}).get("account_id")  # noqa: E731

    def summary(a: CloudAccount) -> dict:
        scan, own = scan_of.get(source_of(a)), [f for f in findings if found_in(f) == a.account_identifier]
        details = (scan.stage_details or {}) if scan else {}
        return {
            "id": a.id, "name": a.name, "provider": a.provider, "account": a.account_identifier, "status": a.status,
            "last_synced_at": a.last_synced_at, "last_error": a.last_error, "regions": a.regions or [],
            "scan_id": scan.id if scan else None, "last_evaluated": scan.completed_at if scan else None,
            "risk_score": scan.risk_score if scan else None,
            "resources": details.get("resources", 0), "checks": details.get("checks", 0),
            "passed": details.get("passed", 0), "failed": details.get("failed", 0),
            "not_checked": details.get("not_checked", 0),
            "open_findings": len(own),
            "by_severity": {sev: sum(1 for f in own if f.severity == sev) for sev in _SEVERITY_ORDER},
        }

    connected = [summary(a) for a in accounts]
    selected = None
    if account_id is not None:
        selected = next((a for a in accounts if a.id == account_id), None)
        if selected is None:
            raise HTTPException(status_code=404, detail="Cloud account not found")
        scans = [s for s in scans if s.source == source_of(selected)]
        findings = [f for f in findings if found_in(f) == selected.account_identifier]

    tallies: dict[str, Counter] = {}
    for scan in scans:
        for rule_id, tally in ((scan.stage_details or {}).get("by_rule") or {}).items():
            tallies.setdefault(rule_id, Counter()).update(tally)
    failing: dict[str, list[Finding]] = {}
    for f in findings:
        failing.setdefault(f.rule_id, []).append(f)

    rules = []
    for rule in RULES:
        tally = tallies.get(rule.id, Counter())
        rules.append({
            "rule_id": rule.id, "title": rule.title, "severity": rule.severity, "category": rule.category,
            "resource_type": rule.resource_type, "cis_aws_1_4": rule.cis or None, "remediation": rule.remediation,
            "can_auto_fix": rule.id in remediation.ACTIONS,
            "failing": len(failing.get(rule.id, [])), "passing": tally["pass"], "not_checked": tally["unknown"],
            "resources": [
                {"finding_id": f.id, "name": f.resource_name, "detail": f.description, "status": f.status,
                 "region": (f.metadata_ or {}).get("region"), "account": (f.metadata_ or {}).get("account_id")}
                for f in failing.get(rule.id, [])[:100]
            ],
        })
    rules.sort(key=lambda r: (-(r["failing"] > 0), _SEVERITY_ORDER.get(r["severity"], 4), r["rule_id"]))

    scope = {"cloud_account": selected.account_identifier} if selected else {}
    exposure = await cloud_skills.internet_exposure(ToolContext(db=db, organization_id=org, meta=scope))
    change_filter = [CloudChange.organization_id == org]
    if selected:
        change_filter.append(CloudChange.account_id == selected.account_identifier)
    changes = (await db.execute(
        select(CloudChange).where(*change_filter).order_by(desc(CloudChange.id)).limit(50)
    )).scalars().all()
    return {
        "account": next(c for c in connected if c["id"] == selected.id) if selected else None,
        "connected_accounts": connected,
        "evaluated": [
            {"scan_id": s.id, "account": s.account_name, "provider": s.cloud_provider, "last_evaluated": s.completed_at,
             "risk_score": s.risk_score, "resources": (s.stage_details or {}).get("resources", 0),
             "checks": (s.stage_details or {}).get("checks", 0), "passed": (s.stage_details or {}).get("passed", 0),
             "failed": (s.stage_details or {}).get("failed", 0),
             "not_checked": (s.stage_details or {}).get("not_checked", 0),
             "not_checked_examples": (s.stage_details or {}).get("not_checked_examples", [])}
            for s in scans
        ],
        "open_findings": len(findings),
        "by_severity": {sev: sum(1 for f in findings if f.severity == sev) for sev in _SEVERITY_ORDER},
        "rules": rules,
        "exposure": None if exposure.get("data_source") == "not_connected" else exposure,
        "changes": [_change_out(c) for c in changes],
    }


@router.post("/evaluate")
async def evaluate_now(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("scans", "create")),
):
    """Run the rules again on the resources already synced. Does not contact the cloud."""
    return {"accounts": await evaluate_organization(db, user.organization_id)}


@router.post("/changes/{change_id}/rollback")
async def rollback_change(
    change_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "manage")),
):
    """Put a cloud resource back to how it was before GuardNous changed it."""
    try:
        change = await remediation.rollback(db, user.organization_id, change_id, by=user.email)
    except remediation.RemediationError as exc:
        status = 404 if "not found" in str(exc).lower() else 409
        raise HTTPException(status_code=status, detail=str(exc))
    await write_audit_log(
        db, action="cloud_change.rollback", resource_type="cloud_change", resource_id=change.id,
        details={"rule_id": change.rule_id, "resource": change.resource_name, "action": change.action}, user=user,
    )
    await db.commit()
    return _change_out(change)

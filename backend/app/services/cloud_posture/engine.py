"""Turn posture rule results into findings.

Each cloud account gets one standing "cloud posture" scan. Evaluating again
updates it in place: a new failure opens a finding, a failure that is gone
resolves its finding, and a failure that comes back reopens it. Findings a
person marked as false positive are left alone.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_resource import CloudResource
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import sla
from app.services.cloud_posture.rules import evaluate
from app.services.risk.scorer import RiskScorer

logger = logging.getLogger(__name__)

SCAN_TYPE = "cloud_posture"
DETECTED_BY = "guardnous-cspm"


# Pipeline stages of a cloud posture assessment (the scan page shows these).
STAGE_DISCOVERY, STAGE_EVALUATION, STAGE_FINDINGS = "cloud_discovery", "cloud_evaluation", "cloud_findings"


def _stage(start: datetime, end: datetime, summary: str) -> dict:
    return {
        "start_time": start.isoformat(), "end_time": end.isoformat(),
        "duration_ms": max(0, int((end - start).total_seconds() * 1000)), "summary": summary,
    }


def discovery_stage(start: datetime, end: datetime, resources: int, regions: list[str]) -> dict:
    """Stage entry for a sync that connected to the cloud account and read its resources."""
    names = f" ({', '.join(regions)})" if len(regions) <= 6 else ""
    where = f"{len(regions)} regions{names}" if regions else "the default regions"
    return _stage(start, end, f"Connected and read {resources} resources from {where} and the global services")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _note(text: str) -> dict:
    return {"author": "GuardNous", "text": text, "created_at": datetime.now(timezone.utc).isoformat()}


async def evaluate_account(
    db: AsyncSession, organization_id: int, provider: str, account_id: str, *, account_name: str = "",
    now: Optional[datetime] = None, sync_stage: Optional[dict] = None,
) -> dict:
    """Evaluate one cloud account's synced resources and update its findings.

    ``sync_stage`` is the discovery stage entry from the sync that just read the
    cloud (see :func:`discovery_stage`); omit it when re-checking synced data.
    """
    if provider != "aws":
        return {"evaluated": False, "reason": f"Posture rules exist for AWS only, not {provider}."}

    rows = (await db.execute(
        select(CloudResource).where(
            CloudResource.organization_id == organization_id, CloudResource.provider == provider,
            CloudResource.account_id == account_id, CloudResource.status == "active",
        )
    )).scalars().all()
    resources = [
        {
            "resource_id": r.resource_id, "resource_name": r.resource_name, "resource_type": r.resource_type,
            "region": r.region, "account_id": r.account_id, "config": r.config or {},
        }
        for r in rows
    ]
    evaluation_started = datetime.now(timezone.utc)
    results = evaluate(resources, now=now)
    findings_started = datetime.now(timezone.utc)
    moment = now or datetime.now(timezone.utc)

    source = f"cloud://{provider}/{account_id}"
    scan = (await db.execute(
        select(Scan).where(
            Scan.organization_id == organization_id, Scan.scan_type == SCAN_TYPE, Scan.source == source,
        )
    )).scalars().first()
    if scan is None:
        scan = Scan(
            organization_id=organization_id, scan_type=SCAN_TYPE, source=source, cloud_provider=provider,
            file_name=f"Cloud posture: {account_name or account_id}", account_name=account_name or account_id,
            status="running", started_at=moment,
        )
        db.add(scan)
        await db.flush()

    existing = {
        (f.rule_id, (f.metadata_ or {}).get("resource_id")): f
        for f in (await db.execute(select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
    }
    failing: set[tuple] = set()
    opened = reopened = resolved = 0

    for result in results:
        if result.status != "fail":
            continue
        key = (result.rule.id, result.resource["resource_id"])
        failing.add(key)
        finding = existing.get(key)
        if finding is None:
            db.add(Finding(
                scan_id=scan.id, organization_id=organization_id, rule_id=result.rule.id, title=result.rule.title,
                description=result.reason, severity=result.rule.severity, category=result.rule.category,
                cloud_provider=provider, resource_type=result.resource["resource_type"],
                resource_name=result.resource["resource_name"], remediation=result.rule.remediation,
                detected_by=DETECTED_BY, status="open", is_fixed=False, is_ignored=False,
                **sla.clock_fields(result.rule.severity, moment),
                metadata_={
                    "source": DETECTED_BY, "resource_id": result.resource["resource_id"],
                    "account_id": account_id, "region": result.resource["region"],
                    **({"cis_aws_1_4": result.rule.cis} if result.rule.cis else {}),
                },
            ))
            opened += 1
            continue
        finding.description = result.reason
        if finding.is_fixed:
            finding.is_fixed, finding.status, finding.resolved_at = False, "open", None
            sla.start_clock(finding, moment)
            finding.notes = [*(finding.notes or []), _note("Reopened: the cloud resource fails this check again.")]
            reopened += 1

    for key, finding in existing.items():
        if key not in failing and not finding.is_fixed and not finding.is_ignored:
            finding.is_fixed, finding.status, finding.resolved_at = True, "resolved", moment
            finding.notes = [*(finding.notes or []), _note("Resolved: the cloud resource no longer fails this check.")]
            resolved += 1
    await db.flush()

    open_findings = (await db.execute(
        select(Finding.severity).where(
            Finding.scan_id == scan.id, Finding.is_fixed == False, Finding.is_ignored == False,  # noqa: E712
        )
    )).scalars().all()
    count = lambda sev: sum(1 for s in open_findings if s == sev)  # noqa: E731
    scan.status, scan.stage, scan.progress = "completed", "completed", 100
    scan.completed_at = datetime.now(timezone.utc)
    scan.findings_count = len(open_findings)
    scan.critical_count, scan.high_count = count("CRITICAL"), count("HIGH")
    scan.medium_count, scan.low_count = count("MEDIUM"), count("LOW")
    scan.risk_score = RiskScorer().calculate_scan_score([{"severity": s} for s in open_findings])
    scan.files_scanned = scan.files_total = len(resources)
    unknown = [r for r in results if r.status == "unknown"]
    by_rule: dict[str, dict] = {}
    for r in results:
        tally = by_rule.setdefault(r.rule.id, {"pass": 0, "fail": 0, "unknown": 0})
        tally[r.status] += 1
    passed = sum(1 for r in results if r.status == "pass")
    finished = datetime.now(timezone.utc)
    # The pipeline shown for this assessment. Discovery is timed by the sync that
    # read the cloud; a re-check of already synced data keeps the last sync's entry.
    discovery = sync_stage or (scan.stage_details or {}).get(STAGE_DISCOVERY)
    types = len({r["resource_type"] for r in resources})
    scan.stage_details = {
        **({STAGE_DISCOVERY: discovery} if discovery else {}),
        STAGE_EVALUATION: _stage(
            evaluation_started, findings_started,
            f"{len(results)} checks on {len(resources)} resources of {types} types: {passed} passed, "
            f"{len(failing)} failed, {len(unknown)} could not be checked",
        ),
        STAGE_FINDINGS: _stage(
            findings_started, finished,
            f"{opened} opened, {reopened} reopened, {resolved} resolved; {len(open_findings)} open now",
        ),
        "by_rule": by_rule,
        "resources": len(resources), "checks": len(results),
        "passed": passed, "failed": len(failing),
        "not_checked": len(unknown),
        "not_checked_examples": sorted({f"{r.rule.id}: {r.reason}" for r in unknown})[:10],
    }
    scan.started_at = _parse(sync_stage["start_time"]) if sync_stage else evaluation_started
    for row in rows:
        row.last_evaluated = moment
    await db.commit()
    if opened or reopened:               # something new to decide on
        from app.services.agents.auto_triage import start_after_scan

        if await start_after_scan(db, scan):
            await db.commit()

    summary = {
        "evaluated": True, "scan_id": scan.id, "resources": len(resources), "checks": len(results),
        "failed": len(failing), "not_checked": len(unknown),
        "opened": opened, "reopened": reopened, "resolved": resolved,
    }
    logger.info("Cloud posture for %s/%s: %s", provider, account_id, summary)
    return summary


async def evaluate_organization(db: AsyncSession, organization_id: int) -> list[dict]:
    """Evaluate every synced cloud account of an organization."""
    from app.models.cloud_account import CloudAccount

    accounts = (await db.execute(
        select(CloudResource.provider, CloudResource.account_id)
        .where(CloudResource.organization_id == organization_id, CloudResource.status == "active")
        .distinct()
    )).all()
    names = {
        (a.provider, a.account_identifier): a.name
        for a in (await db.execute(
            select(CloudAccount).where(CloudAccount.organization_id == organization_id)
        )).scalars().all()
    }
    out = []
    for provider, account_id in accounts:
        if not account_id:
            continue
        out.append({
            "provider": provider, "account_id": account_id,
            **await evaluate_account(
                db, organization_id, provider, account_id, account_name=names.get((provider, account_id), ""),
            ),
        })
    return out

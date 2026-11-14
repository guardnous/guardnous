"""Triage decisions that outlive a scan.

Every scan of a repository writes new finding rows. Without this module a
finding marked "false positive" yesterday comes back as "open" today, and the
same triage work is done again after every scan.

A finding is recognised as *the same finding* when it is in the same
organization, on the same target (repository, or uploaded file), and has the
same rule, file and resource. The line number is left out on purpose: it moves
whenever someone edits the file above it.

Two things happen here:

* :func:`carry_over` / :func:`carry_over_sync` - after a scan has written its
  findings, copy the latest decision made on each one in earlier scans.
* :func:`same_finding_elsewhere` - when a decision is made now, find the
  copies of that finding in other scans of the same target so they get it too.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan

logger = logging.getLogger(__name__)

CARRIED_STATUSES = ("triaged", "in_progress", "false_positive")
AUTHOR = "GuardNous"
MAX_NOTES = 30


def finding_key(finding) -> tuple[str, str, str]:
    return (finding.rule_id or "", finding.file_path or "", finding.resource_name or "")


def _same_target(scan: Scan):
    """SQL condition for "a scan of the same thing", or None when the scan has no stable target."""
    if scan.scan_type == "cloud_posture":
        return None                      # the posture engine keeps its own findings between runs
    names = []
    if scan.repository:
        names.append(Scan.repository == scan.repository)
    if scan.repository_name:
        names.append(and_(
            Scan.repository_name == scan.repository_name,
            Scan.account_name == scan.account_name if scan.account_name else Scan.account_name.is_(None),
        ))
    if names:
        return or_(*names)
    if scan.file_name:
        return and_(Scan.file_name == scan.file_name, Scan.repository.is_(None), Scan.repository_name.is_(None))
    return None


def _decided_before(scan: Scan):
    target = _same_target(scan)
    if target is None or scan.organization_id is None:
        return None
    return (
        select(Finding, Scan.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == scan.organization_id, Scan.id < scan.id, target)
        .where(Finding.status.in_((*CARRIED_STATUSES, "resolved")))
        .order_by(Finding.id.desc())
    )


def _note(text: str) -> dict:
    return {"author": AUTHOR, "text": text, "created_at": datetime.now(timezone.utc).isoformat()}


def apply_decisions(new_findings: Iterable[Finding], earlier: Iterable[tuple[Finding, int]]) -> dict:
    """Copy the most recent earlier decision onto each new finding. ``earlier`` is newest first."""
    latest: dict[tuple, tuple[Finding, int]] = {}
    for old, scan_id in earlier:
        latest.setdefault(finding_key(old), (old, scan_id))

    carried = reappeared = 0
    for finding in new_findings:
        if (finding.status or "open") != "open":
            continue
        match = latest.get(finding_key(finding))
        if match is None:
            continue
        old, scan_id = match
        if old.status == "resolved":
            # Marked fixed, and the scanner found it again: that is news, not a decision to repeat.
            finding.notes = [*(finding.notes or []), _note(
                f"Found again. It was marked resolved in assessment #{scan_id} (finding #{old.id})."
            )][-MAX_NOTES:]
            reappeared += 1
            continue
        finding.status = old.status
        finding.assigned_to = old.assigned_to
        finding.sla_deadline = old.sla_deadline
        if old.status == "false_positive":
            finding.is_ignored = True
            finding.false_positive_reason = old.false_positive_reason
        finding.notes = [*(old.notes or []), _note(
            f"Kept '{old.status}' from assessment #{scan_id} (finding #{old.id}): same rule, file and resource."
        )][-MAX_NOTES:]
        carried += 1
    return {"carried": carried, "reappeared": reappeared}


async def carry_over(db: AsyncSession, scan: Scan) -> dict:
    """Async sessions: call after the scan's findings are added."""
    stmt = _decided_before(scan)
    if stmt is None:
        return {"carried": 0, "reappeared": 0}
    await db.flush()
    try:
        new = (await db.execute(select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
        return apply_decisions(new, (await db.execute(stmt)).all()) if new else {"carried": 0, "reappeared": 0}
    except Exception:  # noqa: BLE001 - remembering decisions must never fail a scan
        logger.exception("Could not carry triage decisions into scan %s", scan.id)
        return {"carried": 0, "reappeared": 0}


def carry_over_sync(db: Session, scan: Scan) -> dict:
    """Worker (sync) sessions: call after the scan's findings are added."""
    stmt = _decided_before(scan)
    if stmt is None:
        return {"carried": 0, "reappeared": 0}
    db.flush()
    try:
        new = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
        return apply_decisions(new, db.execute(stmt).all()) if new else {"carried": 0, "reappeared": 0}
    except Exception:  # noqa: BLE001 - remembering decisions must never fail a scan
        logger.exception("Could not carry triage decisions into scan %s", scan.id)
        return {"carried": 0, "reappeared": 0}


# ── first seen ──────────────────────────────────────────────────────

def is_resolved(finding) -> bool:
    return bool(finding.is_fixed) or finding.status == "resolved"


def seen_before(scan: Scan):
    """Statement for the newest earlier copy of every finding on this scan's target, or None.

    One row per rule, file and resource, however many scans there were. Used to
    keep "first seen" (and with it the SLA clock) when a rescan writes new rows.
    """
    target = _same_target(scan)
    if target is None or scan.organization_id is None:
        return None
    newest = (
        select(func.max(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == scan.organization_id, Scan.id < scan.id, target)
        .group_by(Finding.rule_id, Finding.file_path, Finding.resource_name)
    )
    return select(
        Finding.id, Finding.rule_id, Finding.file_path, Finding.resource_name, Finding.status, Finding.is_fixed,
        Finding.severity, Finding.created_at, Finding.first_seen_at, Finding.sla_deadline,
    ).where(Finding.id.in_(newest)).order_by(Finding.id.desc())


def previous_appearances(earlier: Iterable) -> dict[tuple, object]:
    """Rows of :func:`seen_before` (newest first) by finding key."""
    previous: dict[tuple, object] = {}
    for row in earlier:
        previous.setdefault(finding_key(row), row)
    return previous


async def same_finding_elsewhere(db: AsyncSession, finding: Finding, scan: Optional[Scan] = None) -> list[Finding]:
    """Copies of this finding in other scans of the same target that are still undecided or differ."""
    scan = scan or await db.get(Scan, finding.scan_id)
    if scan is None:
        return []
    target = _same_target(scan)
    if target is None:
        return []
    rule, path, resource = finding_key(finding)
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == scan.organization_id, target, Finding.id != finding.id)
        .where(Finding.rule_id == rule)
        .where(Finding.file_path == path if path else or_(Finding.file_path.is_(None), Finding.file_path == ""))
        .where(Finding.resource_name == resource if resource
               else or_(Finding.resource_name.is_(None), Finding.resource_name == ""))
        .where(Finding.is_fixed == False)  # noqa: E712
    )
    return list((await db.execute(stmt)).scalars().all())


# ── making a decision ───────────────────────────────────────────────

VALID_STATUSES = ("open", "triaged", "in_progress", "resolved", "false_positive")


def _set(finding: Finding, status: str, reason: str, assigned_to: str, note: dict) -> None:
    finding.status = status
    finding.is_ignored = status == "false_positive"
    finding.false_positive_reason = (reason or finding.false_positive_reason) if status == "false_positive" else None
    if assigned_to:
        finding.assigned_to = assigned_to
    if status == "resolved":
        finding.is_fixed, finding.resolved_at = True, datetime.now(timezone.utc)
    elif status == "open":
        finding.is_fixed, finding.resolved_at = False, None
    finding.notes = [*(finding.notes or []), note][-MAX_NOTES:]


async def decide(
    db: AsyncSession, finding: Finding, status: str, *, reason: str = "", assigned_to: str = "", author: str,
) -> list[int]:
    """Record a triage decision on a finding and on its copies in other scans of the same target.

    Returns the ids of every finding changed. The caller commits.
    """
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {sorted(VALID_STATUSES)}")
    text = f"Status changed to '{status}'" + (f": {reason}" if reason else "")
    moment = datetime.now(timezone.utc).isoformat()
    _set(finding, status, reason, assigned_to, {"author": author, "text": text, "created_at": moment})
    changed = [finding.id]
    for copy in await same_finding_elsewhere(db, finding):
        if copy.status == status:
            continue
        _set(copy, status, reason, assigned_to, {
            "author": author, "created_at": moment,
            "text": f"{text} (decided on finding #{finding.id}, the same rule, file and resource)",
        })
        changed.append(copy.id)
    return changed

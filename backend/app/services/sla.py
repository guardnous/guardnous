"""Remediation deadlines (SLA) for findings.

Policy
    Days allowed per severity, from ``SLA_DAYS_*`` in the settings (defaults:
    CRITICAL 7, HIGH 30, MEDIUM 90, LOW 180, INFO none). 0 means no SLA for that
    severity. The policy is per installation, not per organization.

Clock
    The deadline is *first seen* + the allowed days. Every rescan writes new
    finding rows, so "first seen" is taken from the newest earlier copy of the
    same finding (same organization, target, rule, file and resource; see
    ``triage_memory``) and stored in ``Finding.first_seen_at``. A new scan does
    not reset the clock. A finding that was resolved and is found again starts a
    new clock from when it reappeared. A deadline already set on the earlier
    copy (including one changed by hand) is kept while the severity is the same.

Status (computed, never stored) - :func:`status`
    ``none``      no deadline, or the finding is a false positive / ignored
    ``overdue``   open and the deadline has passed
    ``due_soon``  open and the time left is within the warning window: 20% of
                  the allowed time or 3 days, whichever is larger
    ``on_track``  open with more time left than that
    ``met``       resolved on or before the deadline
    ``missed``    resolved after the deadline
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import triage_memory

logger = logging.getLogger(__name__)

NONE, ON_TRACK, DUE_SOON, OVERDUE, MET, MISSED = "none", "on_track", "due_soon", "overdue", "met", "missed"
OPEN_STATUSES = (OVERDUE, DUE_SOON, ON_TRACK)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

DUE_SOON_SHARE = 0.2                     # of the allowed time
DUE_SOON_MINIMUM = timedelta(days=3)
COMPLIANCE_WINDOW_DAYS = 90


# ── policy ──────────────────────────────────────────────────────────

def policy() -> dict[str, int]:
    """Days allowed per severity. Read from the settings on every call so a change applies at once."""
    return {severity: max(0, int(getattr(settings, f"SLA_DAYS_{severity}", 0) or 0)) for severity in SEVERITIES}


def policy_days(severity: Optional[str]) -> int:
    return policy().get((severity or "").upper(), 0)


def deadline_for(severity: Optional[str], first_seen: datetime) -> Optional[datetime]:
    days = policy_days(severity)
    return first_seen + timedelta(days=days) if days else None


# ── status ──────────────────────────────────────────────────────────

def _aware(moment: Optional[datetime]) -> Optional[datetime]:
    """SQLite returns naive datetimes; everything stored is UTC."""
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _now(now: Optional[datetime]) -> datetime:
    return _aware(now) or datetime.now(timezone.utc)


def _excluded(finding) -> bool:
    return finding.status == "false_positive" or bool(finding.is_ignored)


def due_soon_window(finding) -> timedelta:
    """How long before the deadline a finding counts as due soon."""
    deadline = _aware(finding.sla_deadline)
    started = _aware(getattr(finding, "first_seen_at", None)) or _aware(getattr(finding, "created_at", None))
    allowed = deadline - started if deadline and started and deadline > started else timedelta(
        days=policy_days(finding.severity)
    )
    return max(allowed * DUE_SOON_SHARE, DUE_SOON_MINIMUM)


def status(finding, now: Optional[datetime] = None) -> str:
    """SLA status of a finding at ``now`` (default: the current time). See the module text for the rules."""
    deadline = _aware(finding.sla_deadline)
    if deadline is None or _excluded(finding):
        return NONE
    if triage_memory.is_resolved(finding):
        resolved_at = _aware(finding.resolved_at)
        if resolved_at is None:
            return NONE                  # marked fixed without a time: cannot be judged
        return MET if resolved_at <= deadline else MISSED
    left = deadline - _now(now)
    if left < timedelta(0):
        return OVERDUE
    return DUE_SOON if left <= due_soon_window(finding) else ON_TRACK


def days_remaining(finding, now: Optional[datetime] = None) -> Optional[int]:
    """Whole days until the deadline of an open finding; negative when overdue. None when there is no running clock."""
    if status(finding, now) not in OPEN_STATUSES:
        return None
    return int((_aware(finding.sla_deadline) - _now(now)).total_seconds() / 86400)   # truncates towards zero


def active_condition():
    """SQL condition: the finding still has a running clock (not resolved, not a false positive, not ignored)."""
    return and_(
        Finding.is_fixed.isnot(True), Finding.is_ignored.isnot(True),
        Finding.status.notin_(("resolved", "false_positive")),
    )


# ── setting the deadline ────────────────────────────────────────────

def clock_fields(severity: Optional[str], now: Optional[datetime] = None) -> dict:
    """Column values for a finding first seen at ``now`` (for code that builds the row itself)."""
    moment = _now(now)
    return {"first_seen_at": moment, "sla_deadline": deadline_for(severity, moment)}


def start_clock(finding: Finding, now: Optional[datetime] = None) -> None:
    """Start a new clock: the finding was opened, or reopened after being resolved."""
    for name, value in clock_fields(finding.severity, now).items():
        setattr(finding, name, value)


def ensure_deadline(finding: Finding) -> None:
    """Give an open finding without a deadline one, from when it was first seen (e.g. a false positive reopened)."""
    if finding.sla_deadline is not None or _excluded(finding) or triage_memory.is_resolved(finding):
        return
    started = _aware(finding.first_seen_at) or _aware(finding.created_at)
    if started:
        finding.first_seen_at = started
        finding.sla_deadline = deadline_for(finding.severity, started)


def apply_clock(
    new: Iterable[tuple[Finding, Optional[datetime]]], earlier: Iterable, now: Optional[datetime] = None,
    *, from_created: bool = False,
) -> int:
    """Set first-seen and deadline on findings that have no first-seen yet. Returns how many were set.

    ``new`` is (finding, created_at); ``earlier`` is the rows of ``triage_memory.seen_before``.
    ``from_created`` is for the backfill: a finding with no earlier copy was first seen when its
    row was created, not now.
    """
    previous = triage_memory.previous_appearances(earlier)
    moment = _now(now)
    changed = 0
    for finding, created_at in new:
        if finding.first_seen_at is not None:
            continue
        seen = (_aware(created_at) or moment) if from_created else moment
        first_seen, inherited = seen, None
        before = previous.get(triage_memory.finding_key(finding))
        if before is not None and not triage_memory.is_resolved(before):
            first_seen = min(seen, _aware(before.first_seen_at) or _aware(before.created_at) or seen)
            if (before.severity or "").upper() == (finding.severity or "").upper():
                inherited = _aware(before.sla_deadline)
        # else: never seen, or it was resolved and is found again -> a new clock from now
        finding.first_seen_at = first_seen
        if _excluded(finding):
            finding.sla_deadline = None
        elif not triage_memory.is_resolved(finding):
            finding.sla_deadline = inherited or deadline_for(finding.severity, first_seen)
        changed += 1
    return changed


def _unclocked(scan: Scan):
    return select(Finding, Finding.created_at).where(Finding.scan_id == scan.id, Finding.first_seen_at.is_(None))


async def set_deadlines(
    db: AsyncSession, scan: Scan, now: Optional[datetime] = None, *, from_created: bool = False,
) -> int:
    """Async sessions: call after the scan's findings are added and after triage carry-over."""
    try:
        await db.flush()
        new = (await db.execute(_unclocked(scan))).all()
        if not new:
            return 0
        stmt = triage_memory.seen_before(scan)
        earlier = (await db.execute(stmt)).all() if stmt is not None else []
        return apply_clock(new, earlier, now, from_created=from_created)
    except Exception:  # noqa: BLE001 - deadlines must never fail a scan
        logger.exception("Could not set SLA deadlines for scan %s", getattr(scan, "id", None))
        return 0


def set_deadlines_sync(
    db: Session, scan: Scan, now: Optional[datetime] = None, *, from_created: bool = False,
) -> int:
    """Worker (sync) sessions: call after the scan's findings are added and after triage carry-over."""
    try:
        db.flush()
        new = db.execute(_unclocked(scan)).all()
        if not new:
            return 0
        stmt = triage_memory.seen_before(scan)
        earlier = db.execute(stmt).all() if stmt is not None else []
        return apply_clock(new, earlier, now, from_created=from_created)
    except Exception:  # noqa: BLE001 - deadlines must never fail a scan
        logger.exception("Could not set SLA deadlines for scan %s", getattr(scan, "id", None))
        return 0


# ── backfill ────────────────────────────────────────────────────────

async def backfill(db: AsyncSession) -> int:
    """Give findings written before SLA tracking a first-seen time and, when still open, a deadline.

    Idempotent: only findings without ``first_seen_at`` are touched, and every one that is
    touched gets it, so a second run finds nothing (one indexed-size query). Scans are taken
    oldest first so each rescan inherits the clock of the scan before it. The caller commits.
    """
    scan_ids = (await db.execute(
        select(Finding.scan_id).where(Finding.first_seen_at.is_(None)).distinct().order_by(Finding.scan_id)
    )).scalars().all()
    changed = 0
    for scan_id in scan_ids:
        scan = await db.get(Scan, scan_id)
        if scan is not None:
            changed += await set_deadlines(db, scan, from_created=True)
    return changed


async def backfill_at_startup() -> None:
    """Run :func:`backfill` in its own session. Never raises: a failure is logged and startup continues."""
    from app.core.database import async_session

    try:
        async with async_session() as db:
            changed = await backfill(db)
            await db.commit()
        if changed:
            logger.info("SLA backfill: %d findings given a first-seen time and deadline", changed)
    except Exception:  # noqa: BLE001
        logger.exception("SLA backfill failed; findings without a deadline stay as they are")


# ── list filter ─────────────────────────────────────────────────────

FILTERS = OPEN_STATUSES


async def ids_with_status(db: AsyncSession, conditions: list, wanted: str, now: Optional[datetime] = None) -> list[int]:
    """Ids of open findings matching ``conditions`` whose SLA status is ``wanted``, soonest deadline first.

    The warning window depends on each finding's allowed time, so the status is worked out
    here and not in SQL; only the columns needed for that are read.
    """
    rows = (await db.execute(
        select(
            Finding.id, Finding.sla_deadline, Finding.first_seen_at, Finding.created_at, Finding.severity,
            Finding.status, Finding.is_fixed, Finding.is_ignored, Finding.resolved_at,
        ).where(*conditions, Finding.sla_deadline.isnot(None), active_condition())
        .order_by(Finding.sla_deadline.asc(), Finding.id.asc())
    )).all()
    return [row.id for row in rows if status(row, now) == wanted]


# ── summary ─────────────────────────────────────────────────────────

def _iso(moment: Optional[datetime]) -> Optional[str]:
    moment = _aware(moment)
    return moment.isoformat() if moment else None


async def summary(db: AsyncSession, organization_id: int, now: Optional[datetime] = None) -> dict[str, Any]:
    """SLA position of an organization.

    Open findings are counted in the latest assessment of each target only, so a finding
    present in five scans of a repository counts once. Resolved findings are taken from all
    assessments (a fixed finding is absent from the latest one) and counted once per target,
    rule, file and resource.
    """
    from app.services.agents.triage_tools import latest_scans, scan_target

    moment = _now(now)
    counts = {name: 0 for name in (*OPEN_STATUSES, NONE)}
    by_severity = {severity: dict(counts) for severity in SEVERITIES}
    oldest = None

    latest = await latest_scans(db, organization_id)
    if latest:
        rows = (await db.execute(
            select(
                Finding.id, Finding.scan_id, Finding.title, Finding.severity, Finding.sla_deadline,
                Finding.first_seen_at, Finding.created_at, Finding.status, Finding.is_fixed, Finding.is_ignored,
                Finding.resolved_at,
            ).where(
                Finding.organization_id == organization_id, Finding.scan_id.in_(list(latest)), active_condition(),
            )
        )).all()
        for row in rows:
            state = status(row, moment)
            counts[state] += 1
            by_severity.setdefault((row.severity or "").upper(), {name: 0 for name in counts})[state] += 1
            if state == OVERDUE and (oldest is None or _aware(row.sla_deadline) < _aware(oldest.sla_deadline)):
                oldest = row

    since = moment - timedelta(days=COMPLIANCE_WINDOW_DAYS)
    resolved = (await db.execute(
        select(Finding, Scan)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Finding.organization_id == organization_id, Scan.organization_id == organization_id,
            Finding.sla_deadline.isnot(None), Finding.resolved_at.isnot(None), Finding.resolved_at >= since,
            Finding.status == "resolved",
        )
        .order_by(Finding.id.desc())
    )).all()
    judged: dict[tuple, str] = {}
    for finding, scan in resolved:
        key = (scan_target(scan), *triage_memory.finding_key(finding), (finding.metadata_ or {}).get("resource_id"))
        judged.setdefault(key, status(finding, moment))
    met = sum(1 for state in judged.values() if state == MET)
    missed = sum(1 for state in judged.values() if state == MISSED)

    with_sla = sum(counts[name] for name in OPEN_STATUSES)
    return {
        "open": {**counts, "total": sum(counts.values()), "with_sla": with_sla},
        "by_severity": by_severity,
        "oldest_overdue": {
            "id": oldest.id, "scan_id": oldest.scan_id, "title": oldest.title, "severity": oldest.severity,
            "sla_deadline": _iso(oldest.sla_deadline),
            "days_overdue": -(days_remaining(oldest, moment) or 0),
        } if oldest is not None else None,
        "resolved": {
            "days": COMPLIANCE_WINDOW_DAYS, "met": met, "missed": missed, "total": met + missed,
            "met_percent": round(100 * met / (met + missed), 1) if met + missed else None,
        },
        "has_sla": bool(with_sla or met or missed),
        "policy_days": policy(),
        "as_of": moment.isoformat(),
    }

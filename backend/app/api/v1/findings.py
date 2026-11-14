from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import case, select, func, or_, update as sa_update
from app.core.database import get_db
from app.core.rbac import require_permission
from app.core.tenant import org_scoped_select
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.services import sla as sla_service
from app.services.triage_memory import decide
from app.schemas.finding import (
    FindingResponse,
    FindingUpdate,
    FindingListResponse,
    FindingTriageRequest,
    FindingNoteRequest,
    FindingBulkUpdateRequest,
    FindingBulkUpdateResponse,
)

router = APIRouter()

_VALID_STATUSES = {"open", "triaged", "in_progress", "resolved", "false_positive"}
_SORTS = ("sla_deadline",)


def _utc(moment: Optional[datetime]) -> Optional[datetime]:
    if moment is None:
        return None
    return moment.astimezone(timezone.utc) if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _change_deadline(finding: Finding, deadline: Optional[datetime], email: str) -> None:
    """Set the SLA deadline by hand and say so in the finding's notes."""
    before, after = _utc(finding.sla_deadline), _utc(deadline)
    if before == after:
        return
    finding.sla_deadline = after
    show = lambda moment: moment.strftime("%Y-%m-%d %H:%M UTC") if moment else "none"  # noqa: E731
    finding.notes = [*(finding.notes or []), {
        "author": email,
        "text": f"SLA deadline changed from {show(before)} to {show(after)} by {email}",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }]


@router.get("", response_model=FindingListResponse)
async def list_findings(
    page: int = 1,
    page_size: int = 20,
    severity: str = None,
    cloud_provider: str = None,
    category: str = None,
    status: str = None,
    assigned_to: str = None,
    is_fixed: bool = None,
    is_ignored: bool = None,
    search: str = None,
    scan_id: int = None,
    sla: str = None,
    sort: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List findings.

    ``sla`` = overdue | due_soon | on_track keeps open findings with that SLA status,
    soonest deadline first. ``sort=sla_deadline`` orders any list by deadline (soonest
    first, findings without a deadline last). Without either, the order is unchanged.
    """
    if sla and sla not in sla_service.FILTERS:
        raise HTTPException(status_code=400, detail=f"Invalid sla. Must be one of: {list(sla_service.FILTERS)}")
    if sort and sort not in _SORTS:
        raise HTTPException(status_code=400, detail=f"Invalid sort. Must be one of: {list(_SORTS)}")
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    org_id = current_user.organization_id
    base = org_scoped_select(Finding, org_id)
    count_base = (
        select(func.count(Finding.id))
        .where(Finding.organization_id == org_id)
    )

    filters = []
    if severity:
        filters.append(Finding.severity == severity.upper())
    if cloud_provider:
        filters.append(Finding.cloud_provider == cloud_provider.lower())
    if category:
        filters.append(Finding.category == category)
    if status:
        filters.append(Finding.status == status)
    if assigned_to:
        filters.append(Finding.assigned_to == assigned_to)
    if is_fixed is not None:
        filters.append(Finding.is_fixed == is_fixed)
    if is_ignored is not None:
        filters.append(Finding.is_ignored == is_ignored)
    if scan_id:
        filters.append(Finding.scan_id == scan_id)
    if search:
        filters.append(
            or_(
                Finding.title.ilike(f"%{search}%"),
                Finding.resource_name.ilike(f"%{search}%"),
                Finding.rule_id.ilike(f"%{search}%"),
            )
        )

    for f in filters:
        base = base.where(f)
        count_base = count_base.where(f)

    if sla:
        # The status depends on each finding's allowed time, so it is worked out in the service
        matching = await sla_service.ids_with_status(db, [Finding.organization_id == org_id, *filters], sla)
        total = len(matching)
        page_ids = matching[(page - 1) * page_size:page * page_size]
        rows = (await db.execute(base.where(Finding.id.in_(page_ids)))).scalars().all() if page_ids else []
        position = {finding_id: i for i, finding_id in enumerate(page_ids)}
        findings = sorted(rows, key=lambda f: position[f.id])
    else:
        total_result = await db.execute(count_base)
        total = total_result.scalar() or 0

        default_order = (Finding.severity.asc(), Finding.created_at.desc())
        if sort == "sla_deadline":
            stmt = base.order_by(
                case((Finding.sla_deadline.is_(None), 1), else_=0), Finding.sla_deadline.asc(), *default_order,
            )
        else:
            stmt = base.order_by(*default_order)
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(stmt)
        findings = result.scalars().all()

    # Enrich with repository_url from scan
    scan_ids = {f.scan_id for f in findings}
    scan_map: dict[int, str] = {}
    if scan_ids:
        scan_rows = await db.execute(
            select(Scan.id, Scan.repository_url).where(Scan.id.in_(scan_ids))
        )
        scan_map = {r[0]: r[1] for r in scan_rows.all()}

    items = []
    for f in findings:
        resp = FindingResponse.model_validate(f)
        resp.repository_url = scan_map.get(f.scan_id)
        items.append(resp)

    return FindingListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/summary")
async def findings_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Return total counts grouped by severity (unfiltered)."""
    stmt = (
        select(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == current_user.organization_id)
        .group_by(Finding.severity)
    )
    rows = (await db.execute(stmt)).all()
    counts = {r[0]: r[1] for r in rows}
    total = sum(counts.values())
    return {
        "total": total,
        "by_severity": {
            "CRITICAL": counts.get("CRITICAL", 0),
            "HIGH": counts.get("HIGH", 0),
            "MEDIUM": counts.get("MEDIUM", 0),
            "LOW": counts.get("LOW", 0),
        },
    }


@router.get("/sla/summary")
async def findings_sla_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Open findings by SLA status (latest assessment of each target), and how many resolved ones met their SLA.

    Declared before ``/{finding_id}`` so the fixed path is not taken for a finding id.
    """
    return await sla_service.summary(db, current_user.organization_id)


@router.post("/bulk-update", response_model=FindingBulkUpdateResponse)
async def bulk_update_findings(
    req: FindingBulkUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Bulk update status, assignee, or flags for multiple findings at once."""
    if not req.finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids must not be empty")
    if len(req.finding_ids) > 500:
        raise HTTPException(status_code=400, detail="Maximum 500 findings per bulk update")

    result = await db.execute(
        select(Finding.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id.in_(req.finding_ids), Scan.organization_id == current_user.organization_id)
    )
    valid_ids = [row[0] for row in result.all()]
    if not valid_ids:
        raise HTTPException(status_code=404, detail="No matching findings found")

    values: dict = {}
    if req.status is not None:
        if req.status not in _VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {_VALID_STATUSES}")
        values["status"] = req.status
        if req.status == "resolved":
            values["resolved_at"] = datetime.now(timezone.utc)
    if req.assigned_to is not None:
        values["assigned_to"] = req.assigned_to
    if req.is_ignored is not None:
        values["is_ignored"] = req.is_ignored
    if req.is_fixed is not None:
        values["is_fixed"] = req.is_fixed

    if not values:
        raise HTTPException(status_code=400, detail="No update fields provided")

    stmt = sa_update(Finding).where(Finding.id.in_(valid_ids)).values(**values)
    await db.execute(stmt)
    await db.flush()

    return FindingBulkUpdateResponse(updated=len(valid_ids), finding_ids=valid_ids)


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == current_user.organization_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    update: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == current_user.organization_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if update.is_fixed is not None:
        finding.is_fixed = update.is_fixed
    if update.is_ignored is not None:
        finding.is_ignored = update.is_ignored
    if update.status is not None:
        if update.status not in _VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {_VALID_STATUSES}")
        finding.status = update.status
        if update.status == "resolved":
            finding.resolved_at = datetime.now(timezone.utc)
    if update.assigned_to is not None:
        finding.assigned_to = update.assigned_to
    if update.false_positive_reason is not None:
        finding.false_positive_reason = update.false_positive_reason
    if "sla_deadline" in update.model_fields_set:
        _change_deadline(finding, update.sla_deadline, current_user.email)

    await db.flush()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/triage", response_model=FindingResponse)
async def triage_finding(
    finding_id: int,
    triage: FindingTriageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Set triage status with reason — mark as false positive, resolved, etc."""
    if triage.status not in _VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {_VALID_STATUSES}")

    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == current_user.organization_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Also applied to the same finding in other scans of this repository, and kept on the next scan
    changed = await decide(
        db, finding, triage.status, reason=triage.reason or "", assigned_to=triage.assigned_to or "",
        author=current_user.email,
    )
    if triage.status not in ("resolved", "false_positive"):
        # e.g. a false positive put back to open: it has a deadline again, from when it was first seen
        for reopened in (await db.execute(
            select(Finding).where(Finding.id.in_(changed), Finding.organization_id == current_user.organization_id)
        )).scalars().all():
            sla_service.ensure_deadline(reopened)

    await db.flush()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/notes", response_model=FindingResponse)
async def add_finding_note(
    finding_id: int,
    note_req: FindingNoteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Add an investigation note to a finding."""
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == current_user.organization_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.notes = [*(finding.notes or []), {
        "author": current_user.email,
        "text": note_req.text,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }]

    await db.flush()
    await db.refresh(finding)
    return finding


@router.get("/{finding_id}/notes")
async def get_finding_notes(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == current_user.organization_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding_id": finding_id, "notes": finding.notes or ""}


@router.delete("/{finding_id}")
async def delete_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "delete")),
):
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == current_user.organization_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.delete(finding)
    await db.commit()
    return {"status": "deleted", "id": finding_id}

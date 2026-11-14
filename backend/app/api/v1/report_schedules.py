"""CRUD API for report schedules — recurring automated report generation + email delivery."""
import re
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.user import User
from app.models.report_schedule import ReportSchedule

from app.services.schedules import next_run, validate_cron

router = APIRouter()

REPORT_TYPES = {"security", "compliance", "executive"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_recipients(recipients: List[str]) -> List[str]:
    cleaned = list(dict.fromkeys(r.strip().lower() for r in recipients if r and r.strip()))
    bad = [r for r in cleaned if not _EMAIL_RE.match(r)]
    if bad:
        raise HTTPException(status_code=400, detail=f"Invalid email address: {', '.join(bad)}")
    if not cleaned:
        raise HTTPException(status_code=400, detail="Add at least one recipient email address")
    if len(cleaned) > 25:
        raise HTTPException(status_code=400, detail="A schedule can have at most 25 recipients")
    return cleaned


def _valid_report_type(report_type: str) -> str:
    if report_type not in REPORT_TYPES:
        raise HTTPException(status_code=400, detail=f"Report type must be one of: {', '.join(sorted(REPORT_TYPES))}")
    return report_type


class ReportScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    report_type: str = Field("security", max_length=50)
    format: str = Field("pdf", pattern="^(pdf|csv|html|json)$")
    cron_expression: str = Field("0 8 * * 1", max_length=100)
    recipients: List[str] = Field(default_factory=list)
    scan_ids: Optional[List[int]] = None
    enabled: bool = True


class ReportScheduleUpdate(BaseModel):
    name: Optional[str] = None
    report_type: Optional[str] = None
    format: Optional[str] = None
    cron_expression: Optional[str] = None
    recipients: Optional[List[str]] = None
    scan_ids: Optional[List[int]] = None
    enabled: Optional[bool] = None


class ReportScheduleResponse(BaseModel):
    id: int
    name: str
    organization_id: int
    report_type: str
    format: str
    cron_expression: str
    recipients: list
    scan_ids: Optional[list] = None
    enabled: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    last_status: Optional[str] = None
    last_error: Optional[str] = None
    last_report_id: Optional[int] = None
    created_by: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


@router.get("", response_model=List[ReportScheduleResponse])
async def list_report_schedules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "read")),
):
    result = await db.execute(
        select(ReportSchedule)
        .where(ReportSchedule.organization_id == current_user.organization_id)
        .order_by(ReportSchedule.created_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=ReportScheduleResponse, status_code=201)
async def create_report_schedule(
    body: ReportScheduleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "create")),
):
    cron = validate_cron(body.cron_expression)
    schedule = ReportSchedule(
        name=body.name.strip(),
        organization_id=current_user.organization_id,
        report_type=_valid_report_type(body.report_type),
        format=body.format,
        cron_expression=cron,
        recipients=_valid_recipients(body.recipients),
        scan_ids=body.scan_ids or [],
        enabled=body.enabled,
        next_run_at=next_run(cron),
        created_by=current_user.id,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.put("/{schedule_id}", response_model=ReportScheduleResponse)
async def update_report_schedule(
    schedule_id: int,
    body: ReportScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "update")),
):
    result = await db.execute(
        select(ReportSchedule).where(
            ReportSchedule.id == schedule_id,
            ReportSchedule.organization_id == current_user.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Report schedule not found")

    changes = body.model_dump(exclude_unset=True)
    if changes.get("cron_expression") is not None:
        changes["cron_expression"] = validate_cron(changes["cron_expression"])
        schedule.next_run_at = next_run(changes["cron_expression"])
    if changes.get("recipients") is not None:
        changes["recipients"] = _valid_recipients(changes["recipients"])
    if changes.get("report_type") is not None:
        changes["report_type"] = _valid_report_type(changes["report_type"])
    for field, value in changes.items():
        if value is not None:
            setattr(schedule, field, value)

    schedule.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.post("/{schedule_id}/run")
async def run_report_schedule_now(
    schedule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "create")),
):
    """Generate this schedule's report now and email it to the recipients."""
    import asyncio
    from app.tasks.jobs import run_report_schedule

    result = await db.execute(
        select(ReportSchedule).where(
            ReportSchedule.id == schedule_id,
            ReportSchedule.organization_id == current_user.organization_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Report schedule not found")
    # Runs in a thread: it opens its own database sessions and event loop
    outcome = await asyncio.to_thread(run_report_schedule.run, schedule_id)
    if outcome.get("status") == "failed":
        raise HTTPException(status_code=500, detail=" ".join(outcome.get("errors") or ["Report generation failed"]))
    return outcome


@router.delete("/{schedule_id}", status_code=204)
async def delete_report_schedule(
    schedule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "delete")),
):
    result = await db.execute(
        select(ReportSchedule).where(
            ReportSchedule.id == schedule_id,
            ReportSchedule.organization_id == current_user.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Report schedule not found")
    await db.delete(schedule)
    await db.commit()

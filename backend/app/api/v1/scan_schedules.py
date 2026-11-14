"""CRUD API for scan schedules — create, list, update, delete recurring scan configs."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.integration import Integration
from app.models.scan_schedule import ScanSchedule
from app.services.schedules import next_run, validate_cron

router = APIRouter(prefix="/scan-schedules", tags=["scan-schedules"])


# ── Schemas ──────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    integration_id: int
    repository: str = Field(..., min_length=1, max_length=500)
    cron_expression: str = "0 2 * * *"
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    integration_id: int | None = None
    repository: str | None = None
    cron_expression: str | None = None
    enabled: bool | None = None


class ScheduleOut(BaseModel):
    id: int
    name: str
    integration_id: int | None = None
    repository: str | None = None
    cron_expression: str
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    last_status: str | None = None
    last_error: str | None = None
    created_at: datetime | None = None


def _out(obj: ScanSchedule) -> ScheduleOut:
    cfg = obj.config_json or {}
    return ScheduleOut(
        id=obj.id, name=obj.name, integration_id=cfg.get("integration_id"),
        repository=cfg.get("repository"), cron_expression=obj.cron_expression,
        enabled=obj.enabled, last_run_at=obj.last_run_at, next_run_at=obj.next_run_at,
        last_status=obj.last_status, last_error=obj.last_error, created_at=obj.created_at,
    )


async def _require_scannable_repo(db: AsyncSession, org_id: int, integration_id: int, repository: str) -> None:
    """The repository must be enabled on an active integration of this organization."""
    integration = (await db.execute(
        select(Integration).where(
            Integration.id == integration_id,
            Integration.organization_id == org_id,
            Integration.is_active == True,  # noqa: E712
        )
    )).scalar_one_or_none()
    if not integration:
        raise HTTPException(404, "Integration not found")
    enabled = {
        r.get("full_name") for r in (integration.repositories or [])
        if isinstance(r, dict) and r.get("enabled")
    }
    if repository not in enabled:
        raise HTTPException(400, f"{repository} is not enabled for scanning on this integration")


async def _get(db: AsyncSession, schedule_id: int, org_id: int) -> ScanSchedule:
    obj = (await db.execute(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id, ScanSchedule.organization_id == org_id,
        )
    )).scalar_one_or_none()
    if not obj:
        raise HTTPException(404, "Schedule not found")
    return obj


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("", response_model=list[ScheduleOut])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("scans", "read")),
):
    stmt = select(ScanSchedule).where(
        ScanSchedule.organization_id == user.organization_id
    ).order_by(ScanSchedule.created_at.desc())
    return [_out(s) for s in (await db.execute(stmt)).scalars().all()]


@router.post("", response_model=ScheduleOut, status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("scans", "create")),
):
    cron = validate_cron(body.cron_expression)
    await _require_scannable_repo(db, user.organization_id, body.integration_id, body.repository)
    obj = ScanSchedule(
        organization_id=user.organization_id,
        name=body.name.strip(),
        scan_type="full",
        cron_expression=cron,
        config_json={"integration_id": body.integration_id, "repository": body.repository},
        enabled=body.enabled,
        next_run_at=next_run(cron),
        created_by=user.id,
    )
    db.add(obj)
    await db.commit()
    await db.refresh(obj)
    return _out(obj)


@router.put("/{schedule_id}", response_model=ScheduleOut)
async def update_schedule(
    schedule_id: int,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("scans", "create")),
):
    obj = await _get(db, schedule_id, user.organization_id)
    changes = body.model_dump(exclude_unset=True)
    if "name" in changes:
        obj.name = changes["name"].strip()
    if "enabled" in changes:
        obj.enabled = changes["enabled"]
    if "cron_expression" in changes:
        obj.cron_expression = validate_cron(changes["cron_expression"])
        obj.next_run_at = next_run(obj.cron_expression)
    if "integration_id" in changes or "repository" in changes:
        cfg = dict(obj.config_json or {})
        cfg["integration_id"] = changes.get("integration_id") or cfg.get("integration_id")
        cfg["repository"] = changes.get("repository") or cfg.get("repository")
        await _require_scannable_repo(db, user.organization_id, cfg["integration_id"], cfg["repository"])
        obj.config_json = cfg
    obj.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(obj)
    return _out(obj)


@router.post("/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: int,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("scans", "create")),
):
    """Queue this schedule's scan immediately."""
    import asyncio
    from app.tasks.jobs import run_scan_schedule

    await _get(db, schedule_id, user.organization_id)
    # Runs in a thread: it uses the worker's synchronous DB session and queues the scan
    result = await asyncio.to_thread(run_scan_schedule.run, schedule_id)
    if result.get("status") != "queued":
        raise HTTPException(400, result.get("error") or "The scan could not be queued")
    return result


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: int,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("scans", "create")),
):
    stmt = delete(ScanSchedule).where(
        ScanSchedule.id == schedule_id,
        ScanSchedule.organization_id == user.organization_id,
    )
    result = await db.execute(stmt)
    if result.rowcount == 0:
        raise HTTPException(404, "Schedule not found")
    await db.commit()

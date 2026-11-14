"""Jobs API — monitor scan jobs, trigger repo scans, track progress."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.user import User
from app.models.scan import Scan
from app.models.integration import Integration
from app.core.encryption import decrypt_token
from app.schemas.scan import ScanResponse, JobListResponse, RepoScanCreate

router = APIRouter()


@router.get("", response_model=JobListResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """List all scan jobs with stage/progress info."""
    base = Scan.organization_id == current_user.organization_id

    stmt = select(Scan).where(base)
    count_stmt = select(func.count(Scan.id)).where(base)

    if status:
        if status == "active":
            active_filter = or_(
                Scan.status == "pending",
                Scan.status == "running",
            )
            stmt = stmt.where(active_filter)
            count_stmt = count_stmt.where(active_filter)
        else:
            stmt = stmt.where(Scan.status == status)
            count_stmt = count_stmt.where(Scan.status == status)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    scans = result.scalars().all()

    return JobListResponse(items=scans, total=total, page=page, page_size=page_size)


@router.get("/{job_id}", response_model=ScanResponse)
async def get_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """Get detailed job status including stage and progress."""
    result = await db.execute(
        select(Scan).where(
            Scan.id == job_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Job not found")
    return scan


@router.get("/{job_id}/progress")
async def get_job_progress(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """Lightweight polling endpoint for job progress with stage details."""
    result = await db.execute(
        select(
            Scan.id, Scan.status, Scan.stage, Scan.progress,
            Scan.files_scanned, Scan.files_total, Scan.findings_count,
            Scan.error_message, Scan.started_at, Scan.completed_at,
            Scan.stage_details, Scan.secrets_found, Scan.dependencies_analyzed,
            Scan.policies_evaluated, Scan.policies_passed, Scan.policies_failed,
        ).where(
            Scan.id == job_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    return {
        "id": row[0],
        "status": row[1],
        "stage": row[2],
        "progress": row[3] or 0,
        "files_scanned": row[4] or 0,
        "files_total": row[5] or 0,
        "findings_count": row[6] or 0,
        "error_message": row[7],
        "started_at": row[8].isoformat() if row[8] else None,
        "completed_at": row[9].isoformat() if row[9] else None,
        "stage_details": row[10] or {},
        "secrets_found": row[11] or 0,
        "dependencies_analyzed": row[12] or 0,
        "policies_evaluated": row[13] or 0,
        "policies_passed": row[14] or 0,
        "policies_failed": row[15] or 0,
    }


@router.post("/{job_id}/cancel")
async def cancel_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "update")),
):
    """Cancel a running or pending scan job."""
    result = await db.execute(
        select(Scan).where(
            Scan.id == job_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Job not found")

    if scan.status not in ("pending", "running"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel job in '{scan.status}' state")

    scan.status = "cancelled"
    scan.stage = "cancelled"
    scan.cancelled_by = current_user.email
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()

    return {"id": scan.id, "status": "cancelled", "cancelled_by": current_user.email}


@router.post("/scan-repo", response_model=ScanResponse, status_code=201)
async def trigger_repo_scan(
    data: RepoScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "create")),
):
    """Trigger an async repository scan job via Celery."""
    from app.tasks.jobs import run_repo_scan

    # Get integration to find token
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No active VCS integration found. Connect GitHub first.")

    token = decrypt_token(integration.access_token_encrypted)
    parts = data.repository_full_name.split("/")
    account = parts[0] if len(parts) > 1 else integration.account_name or "unknown"
    repo_name = parts[-1]

    scan = Scan(
        organization_id=current_user.organization_id,
        scan_type=",".join(data.scan_types),
        status="pending",
        stage="queued",
        progress=0,
        repository_url=f"https://github.com/{data.repository_full_name}",
        repository_name=repo_name,
        account_name=account,
        source=data.repository_full_name,
        file_name=data.repository_full_name,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    scan_id = scan.id

    # Dispatch Celery task
    run_repo_scan.delay(
        scan_id=scan_id,
        repo_full_name=data.repository_full_name,
        token=token,
        scan_types=data.scan_types,
        org_id=current_user.organization_id,
    )

    await db.commit()
    await db.refresh(scan)
    return scan

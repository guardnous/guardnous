import asyncio
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import redis.asyncio as aioredis
from app.core.database import get_db
from app.core.rbac import ensure_permission, require_permission
from app.core.audit import write_audit_log
from app.core.tenant import org_scoped_select
from app.core.config import settings
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.services.plugins import ScanOrchestrator
from app.services.risk.scorer import RiskScorer
from app.services.sla import set_deadlines
from app.services.triage_memory import carry_over

router = APIRouter()

# Legacy scan_type → plugin name mapping for backward compatibility
_LEGACY_TYPE_MAP = {
    "terraform": "native_terraform",
    "cloudformation": "native_cloudformation",
    "bicep": "native_bicep",
}


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "create")),
):
    scan_type = scan_data.scan_type.lower()
    source = scan_data.source

    # Auto-detect scan type from file name
    if scan_data.file_name:
        if scan_data.file_name.endswith(".tf"):
            scan_type = "terraform"
        elif scan_data.file_name.endswith((".yaml", ".yml", ".json")) and "AWSTemplateFormatVersion" in source:
            scan_type = "cloudformation"
        elif scan_data.file_name.endswith(".bicep"):
            scan_type = "bicep"

    # Create scan record
    scan = Scan(
        organization_id=current_user.organization_id,
        scan_type=scan_type,
        status="running",
        source=source,
        file_name=scan_data.file_name,
        cloud_provider=scan_data.cloud_provider,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    await write_audit_log(
        db, action="create", resource_type="scan", resource_id=scan.id,
        details={"scan_type": scan_type, "file_name": scan_data.file_name},
        user=current_user, request=request,
    )

    # Run scan via orchestrator (routes to all enabled plugins)
    all_results = []
    try:
        orchestrator = ScanOrchestrator()
        # If a specific legacy scan_type was requested, map to plugin names
        plugin_filter = None
        if scan_type != "full" and scan_type in _LEGACY_TYPE_MAP:
            plugin_filter = [_LEGACY_TYPE_MAP[scan_type], "native_secrets"]
        # "full" → None → all enabled plugins that accept the file

        orch_result = orchestrator.scan(
            content=source,
            file_name=scan_data.file_name or "",
            plugin_names=plugin_filter,
        )
        all_results = orch_result.findings

        # Store findings
        for r in all_results:
            _meta = getattr(r, "metadata", {}) or {}
            finding = Finding(
                scan_id=scan.id,
                rule_id=r.rule_id,
                title=r.title,
                description=r.description,
                severity=r.severity,
                category=r.category,
                cloud_provider=r.cloud_provider or scan.cloud_provider,
                resource_type=r.resource_type,
                resource_name=r.resource_name,
                file_path=r.file_path,
                line_number=r.line_number,
                code_snippet=r.code_snippet,
                remediation=r.remediation,
                cve_id=r.cve_id,
                detected_by=_meta.get("source"),
                metadata_=_meta,
            )
            db.add(finding)
        await carry_over(db, scan)
        await set_deadlines(db, scan)

        # Update scan stats
        scorer = RiskScorer()
        scan.risk_score = scorer.calculate_scan_score([{"severity": r.severity} for r in all_results])
        scan.findings_count = len(all_results)
        scan.critical_count = sum(1 for r in all_results if r.severity == "CRITICAL")
        scan.high_count = sum(1 for r in all_results if r.severity == "HIGH")
        scan.medium_count = sum(1 for r in all_results if r.severity == "MEDIUM")
        scan.low_count = sum(1 for r in all_results if r.severity == "LOW")
        scan.status = "completed"
        scan.stage = "completed"
        scan.progress = 100
        scan.completed_at = datetime.now(timezone.utc)
        # A scanner that failed or was blocked (e.g. integrity check) means incomplete results
        from app.services.plugins.orchestrator import plugin_error_summary
        scan.error_message = plugin_error_summary(orch_result.plugin_errors)

    except Exception as e:
        scan.status = "failed"
        scan.stage = "failed"
        scan.metadata_ = {"error": str(e)}

    await db.flush()
    await db.refresh(scan)
    return scan


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    page_size: int = 20,
    status: str = None,
    scan_type: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    org_id = current_user.organization_id
    stmt = org_scoped_select(Scan, org_id)
    count_stmt = select(func.count(Scan.id)).where(Scan.organization_id == org_id)

    if status:
        stmt = stmt.where(Scan.status == status)
        count_stmt = count_stmt.where(Scan.status == status)
    if scan_type:
        stmt = stmt.where(Scan.scan_type == scan_type)
        count_stmt = count_stmt.where(Scan.scan_type == scan_type)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    scans = result.scalars().all()

    return ScanListResponse(items=scans, total=total, page=page, page_size=page_size)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == current_user.organization_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/export")
async def export_scan(
    scan_id: int,
    format: str = Query("pdf", regex="^(pdf|csv|json|html)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """Export a scan's report in PDF, CSV, JSON, or HTML."""
    from app.models.report import Report
    from fastapi.responses import Response, HTMLResponse

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == current_user.organization_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.report_id:
        raise HTTPException(status_code=404, detail="No report generated for this scan yet")

    rpt_result = await db.execute(select(Report).where(Report.id == scan.report_id))
    report = rpt_result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Delegate to the reports download logic
    from app.api.v1.reports import (
        _generate_csv_from_report,
        _generate_pdf_from_report,
        _json_to_html,
    )

    base_name = f"guardnous_scan_{scan_id}"

    if format == "csv":
        return Response(
            content=_generate_csv_from_report(report),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.csv"'},
        )
    elif format == "pdf":
        return Response(
            content=_generate_pdf_from_report(report),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.pdf"'},
        )
    elif format == "html":
        html_content = report.content
        if report.format == "json" and report.content:
            html_content = _json_to_html(report)
        return HTMLResponse(content=html_content or "", headers={
            "Content-Disposition": f'attachment; filename="{base_name}.html"'
        })
    else:
        return Response(
            content=report.content or "{}",
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.json"'},
        )


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """Return lightweight scan progress for polling.

    Designed for the frontend to call on a short interval while a Celery
    scan task is running.
    """
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == current_user.organization_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "stage": scan.stage,
        "progress": scan.progress,
        "findings_count": scan.findings_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "risk_score": scan.risk_score,
        "files_scanned": scan.files_scanned,
        "files_total": scan.files_total,
        "error_message": scan.error_message,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "write")),
):
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail=f"Scan already {scan.status}")
    scan.status = "cancelled"
    scan.stage = "cancelled"
    await db.commit()
    await db.refresh(scan)
    return {"message": "Scan cancelled", "id": scan.id, "status": scan.status}


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "delete")),
):
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    for f in findings:
        await db.delete(f)
    await db.delete(scan)
    await db.commit()
    await write_audit_log(
        db, action="delete", resource_type="scan", resource_id=scan_id,
        user=current_user, details={"scan_type": scan.scan_type},
    )
    return {"status": "deleted", "id": scan_id}


@router.get("/{scan_id}/logs")
async def get_scan_logs(
    scan_id: int,
    current_user: User = Depends(require_permission("scans", "read")),
    db: AsyncSession = Depends(get_db),
):
    """REST endpoint returning all stored logs for a completed/finished scan."""
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        stored = await r.lrange(f"scan:{scan_id}:log_list", 0, -1)
        logs = [json.loads(raw) for raw in stored]
    finally:
        await r.aclose()
    return {"scan_id": scan_id, "count": len(logs), "logs": logs}


@router.get("/{scan_id}/logs/stream")
async def stream_scan_logs(
    scan_id: int,
    request: Request,
    stage: str = Query(None, description="Filter to a single stage"),
    token: str = Query(None, description="JWT token for SSE auth"),
    db: AsyncSession = Depends(get_db),
):
    """SSE endpoint streaming real-time scan logs from Redis pub/sub."""
    from jose import JWTError
    # SSE doesn't support Authorization header, so accept token via query param
    jwt_token = token
    if not jwt_token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            jwt_token = auth_header[7:]
    if not jwt_token:
        raise HTTPException(status_code=401, detail="Token required")

    try:
        from app.core.security import decode_access_token
        user_id = decode_access_token(jwt_token)["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_result = await db.execute(select(User).where(User.id == int(user_id)))
    current_user = user_result.scalar_one_or_none()
    if not current_user or not current_user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    # Same rule as the other scan reads; the token alone is not enough.
    await ensure_permission(current_user, db, "scans", "read")

    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    is_running = scan.status in ("running", "pending", "queued")

    async def event_generator():
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            # First replay stored logs
            stored = await r.lrange(f"scan:{scan_id}:log_list", 0, -1)
            for raw in stored:
                entry = json.loads(raw)
                if stage and entry.get("stage") != stage:
                    continue
                yield f"data: {raw}\n\n"

            if not is_running:
                yield f"data: {json.dumps({'stage': '_system', 'msg': 'Scan finished — end of logs', 'level': 'info', 'ts': ''})}\n\n"
                return

            # Subscribe to live channel for running scans
            pubsub = r.pubsub()
            await pubsub.subscribe(f"scan:{scan_id}:logs")
            try:
                while True:
                    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if msg and msg["type"] == "message":
                        entry = json.loads(msg["data"])
                        if stage and entry.get("stage") != stage:
                            continue
                        yield f"data: {msg['data']}\n\n"
                        if entry.get("stage") == "completed":
                            break
                    else:
                        yield ": keepalive\n\n"
                        await asyncio.sleep(0.5)
            finally:
                await pubsub.unsubscribe(f"scan:{scan_id}:logs")
        finally:
            await r.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

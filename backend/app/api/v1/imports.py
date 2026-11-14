"""
Universal SARIF Import API — GuardNous

POST /api/v1/imports/sarif        — Ingest a SARIF JSON document
POST /api/v1/imports/sarif/upload — Upload a .sarif file (multipart)
GET  /api/v1/imports              — List past imports
GET  /api/v1/imports/formats      — Supported import formats
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.schemas.imports import (
    SARIFImportRequest,
    SARIFImportResponse,
    ImportFindingSummary,
    ImportListItem,
    ImportListResponse,
)
from app.services.sla import set_deadlines
from app.services.scanners.sarif_parser import SARIFParser
from app.services.risk.scorer import RiskScorer

router = APIRouter()

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB


# ── POST /sarif — JSON body ─────────────────────────────────────────────────


@router.post("/sarif", response_model=SARIFImportResponse, status_code=201)
async def import_sarif(
    body: SARIFImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "create")),
):
    """Import findings from a SARIF v2.1.0 JSON document.

    This is the universal ingestion endpoint — accepts output from ANY
    SARIF-compliant scanner (Checkov, Trivy, Semgrep, CodeQL, Snyk,
    Bandit, ESLint, SonarQube, KICS, Terrascan, tfsec, etc.).
    """
    # Limit JSON body size (10MB max)
    body_str = json.dumps(body.sarif) if not isinstance(body.sarif, str) else body.sarif
    if len(body_str) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="SARIF payload exceeds 10MB limit")

    parser = SARIFParser(override_tool_name=body.override_tool_name)
    result = parser.parse(body.sarif)

    return await _persist_import(
        db=db,
        user=current_user,
        result=result,
        label=body.scan_label,
        repository=body.repository,
        commit_sha=body.commit_sha,
        branch=body.branch,
        environment=body.environment,
        tags=body.tags,
    )


# ── POST /sarif/upload — multipart file ─────────────────────────────────────


@router.post("/sarif/upload", response_model=SARIFImportResponse, status_code=201)
async def upload_sarif(
    file: UploadFile = File(..., description="A .sarif or .json file"),
    scan_label: str = Query(None, max_length=200),
    repository: str = Query(None, max_length=500),
    commit_sha: str = Query(None, max_length=100),
    branch: str = Query(None, max_length=200),
    environment: str = Query(None, max_length=100),
    override_tool_name: str = Query(None, max_length=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "create")),
):
    """Upload a SARIF file for import.

    Accepts `.sarif` or `.json` files up to 50 MB.
    """
    if file.content_type and file.content_type not in (
        "application/json",
        "application/sarif+json",
        "application/octet-stream",
        "text/plain",
    ):
        raise HTTPException(400, f"Unsupported content type: {file.content_type}")

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_SIZE:
        raise HTTPException(413, "File exceeds 50 MB limit")

    try:
        sarif_data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON in uploaded file: {exc}")

    parser = SARIFParser(override_tool_name=override_tool_name)
    result = parser.parse(sarif_data)

    return await _persist_import(
        db=db,
        user=current_user,
        result=result,
        label=scan_label or file.filename,
        repository=repository,
        commit_sha=commit_sha,
        branch=branch,
        environment=environment,
    )


# ── GET / — list past imports ────────────────────────────────────────────────


@router.get("", response_model=ImportListResponse)
async def list_imports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """List past SARIF imports for the current organisation."""
    base = select(Scan).where(
        Scan.organization_id == current_user.organization_id,
        Scan.scan_type == "sarif_import",
    )
    count_q = select(func.count(Scan.id)).where(
        Scan.organization_id == current_user.organization_id,
        Scan.scan_type == "sarif_import",
    )

    total = (await db.execute(count_q)).scalar() or 0
    scans = (
        await db.execute(
            base.order_by(Scan.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    items = []
    for s in scans:
        meta = s.metadata_ or {}
        items.append(
            ImportListItem(
                scan_id=s.id,
                scan_type=s.scan_type,
                status=s.status,
                findings_count=s.findings_count or 0,
                tools=meta.get("tools_detected"),
                repository=meta.get("repository"),
                created_at=s.created_at,
            )
        )

    return ImportListResponse(items=items, total=total, page=page, page_size=page_size)


# ── GET /formats — list supported formats ────────────────────────────────────


@router.get("/formats")
async def supported_formats():
    """Return list of supported import formats."""
    return {
        "formats": [
            {
                "id": "sarif",
                "name": "SARIF v2.1.0",
                "description": (
                    "Static Analysis Results Interchange Format — "
                    "the universal standard for security scanner output. "
                    "Supports 100+ scanners including Checkov, Trivy, Semgrep, "
                    "CodeQL, Snyk, Bandit, ESLint, SonarQube, KICS, Terrascan, "
                    "tfsec, Gitleaks, SpotBugs, and more."
                ),
                "spec_url": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html",
                "endpoints": [
                    "POST /api/v1/imports/sarif",
                    "POST /api/v1/imports/sarif/upload",
                ],
                "content_types": [
                    "application/json",
                    "application/sarif+json",
                ],
            }
        ],
        "total": 1,
    }


# ── Persistence helper ───────────────────────────────────────────────────────


async def _persist_import(
    *,
    db: AsyncSession,
    user: User,
    result,
    label: str | None = None,
    repository: str | None = None,
    commit_sha: str | None = None,
    branch: str | None = None,
    environment: str | None = None,
    tags: dict | None = None,
) -> SARIFImportResponse:
    """Create Scan + Findings from parsed SARIF result and return response."""
    now = datetime.now(timezone.utc)

    scan_meta: dict = {
        "tools_detected": result.tools_detected,
        "sarif_version": result.sarif_version,
        "runs_processed": result.runs_processed,
    }
    if repository:
        scan_meta["repository"] = repository
    if commit_sha:
        scan_meta["commit_sha"] = commit_sha
    if branch:
        scan_meta["branch"] = branch
    if environment:
        scan_meta["environment"] = environment
    if tags:
        scan_meta["tags"] = tags
    if result.errors:
        scan_meta["import_errors"] = result.errors

    tool_label = ", ".join(result.tools_detected) if result.tools_detected else "sarif"

    scan = Scan(
        organization_id=user.organization_id,
        scan_type="sarif_import",
        status="running",
        source=f"SARIF import: {tool_label}",
        file_name=label,
        cloud_provider="",
        started_at=now,
        metadata_=scan_meta,
    )
    db.add(scan)
    await db.flush()

    # Counters
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for r in result.findings:
        meta = getattr(r, "metadata", {}) or {}
        finding = Finding(
            scan_id=scan.id,
            rule_id=r.rule_id,
            title=r.title,
            description=r.description,
            severity=r.severity,
            category=r.category,
            cloud_provider=r.cloud_provider,
            resource_type=r.resource_type,
            resource_name=r.resource_name,
            file_path=r.file_path,
            line_number=r.line_number,
            code_snippet=r.code_snippet,
            remediation=r.remediation,
            cve_id=r.cve_id,
            detected_by=meta.get("source", tool_label),
            metadata_=meta,
        )
        db.add(finding)
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
    await set_deadlines(db, scan)

    # Score & stats
    scorer = RiskScorer()
    risk_score = scorer.calculate_scan_score(
        [{"severity": r.severity} for r in result.findings]
    )

    scan.risk_score = risk_score
    scan.findings_count = len(result.findings)
    scan.critical_count = sev_counts["CRITICAL"]
    scan.high_count = sev_counts["HIGH"]
    scan.medium_count = sev_counts["MEDIUM"]
    scan.low_count = sev_counts["LOW"]
    scan.status = "completed" if not result.errors else "partial"
    scan.completed_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(scan)

    # Top findings preview
    top = []
    for r in result.findings[:20]:
        meta = getattr(r, "metadata", {}) or {}
        top.append(
            ImportFindingSummary(
                rule_id=r.rule_id,
                title=r.title[:200],
                severity=r.severity,
                category=r.category,
                file_path=r.file_path or None,
                line_number=r.line_number or None,
                detected_by=meta.get("source"),
            )
        )

    status = "completed" if not result.errors else "partial"
    message = (
        f"Successfully imported {len(result.findings)} findings from {result.runs_processed} run(s)"
        if not result.errors
        else f"Imported {len(result.findings)} findings with {len(result.errors)} error(s)"
    )

    return SARIFImportResponse(
        scan_id=scan.id,
        status=status,
        message=message,
        findings_imported=len(result.findings),
        findings_skipped=result.results_skipped,
        runs_processed=result.runs_processed,
        tools_detected=result.tools_detected,
        critical=sev_counts["CRITICAL"],
        high=sev_counts["HIGH"],
        medium=sev_counts["MEDIUM"],
        low=sev_counts["LOW"],
        info=sev_counts["INFO"],
        risk_score=risk_score,
        sarif_version=result.sarif_version,
        errors=result.errors,
        top_findings=top,
        repository=repository,
        commit_sha=commit_sha,
        imported_at=now,
    )

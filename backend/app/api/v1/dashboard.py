from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.risk.scorer import RiskScorer
from app.schemas.dashboard import (
    DashboardResponse, DashboardSummaryResponse,
    RiskScoreResponse, SeverityBreakdown, CloudBreakdown, TopRisk,
)

router = APIRouter()


@router.get("", response_model=DashboardResponse)
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    org_id = current_user.organization_id
    scorer = RiskScorer(db)

    risk_data = await scorer.get_organization_score(org_id)
    trend = await scorer.get_trend(org_id)
    severity = await scorer.get_severity_breakdown(org_id)
    cloud = await scorer.get_cloud_breakdown(org_id)
    top_risks = await scorer.get_top_risks(org_id)

    # Recent scans
    result = await db.execute(
        select(Scan)
        .where(Scan.organization_id == org_id)
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    recent_scans = [
        {
            "id": s.id,
            "scan_type": s.scan_type,
            "status": s.status,
            "risk_score": s.risk_score,
            "findings_count": s.findings_count,
            "file_name": s.file_name,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in result.scalars().all()
    ]

    # Totals
    total_findings_result = await db.execute(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == org_id)
        .where(Finding.is_fixed == False)
        .where(Finding.is_ignored == False)
    )
    total_findings = total_findings_result.scalar() or 0

    total_scans_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.organization_id == org_id)
    )
    total_scans = total_scans_result.scalar() or 0

    # Category breakdown
    cat_result = await db.execute(
        select(Finding.category, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == org_id)
        .where(Finding.is_fixed == False)
        .where(Finding.is_ignored == False)
        .where(Finding.category.isnot(None))
        .group_by(Finding.category)
    )
    category_breakdown: dict[str, int] = {}
    for name, count in cat_result.all():          # "IAC" and "iac" are one category
        key = (name or "other").strip().lower() or "other"
        category_breakdown[key] = category_breakdown.get(key, 0) + count

    passed_checks, failed_checks = await _check_results(db, org_id)

    return DashboardResponse(
        risk_score=RiskScoreResponse(
            overall=risk_data["overall"],
            aws=risk_data["aws"],
            gcp=risk_data["gcp"],
            azure=risk_data["azure"],
            trend=trend,
        ),
        severity_breakdown=SeverityBreakdown(**severity),
        cloud_breakdown=CloudBreakdown(**cloud),
        category_breakdown=category_breakdown,
        recent_scans=recent_scans,
        top_risks=[TopRisk(**r) for r in top_risks],
        total_findings=total_findings,
        total_scans=total_scans,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
    )


async def _check_results(db: AsyncSession, org_id: int) -> tuple[int, int]:
    """Checks that passed and failed in the latest completed assessment of each target.

    A check is a policy evaluated on a repository scan, or a posture rule
    evaluated on a cloud resource. Only results that were actually recorded are
    counted; an older scan of the same target is not added on top of a newer one.
    """
    scans = (await db.execute(
        select(Scan).where(Scan.organization_id == org_id, Scan.status == "completed").order_by(Scan.id.desc())
    )).scalars().all()
    seen: set = set()
    passed = failed = 0
    for scan in scans:
        target = scan.repository_name or (scan.source if scan.scan_type == "cloud_posture" else None) or scan.file_name or scan.id
        if target in seen:
            continue
        seen.add(target)
        if scan.scan_type == "cloud_posture":
            details = scan.stage_details or {}
            passed += int(details.get("passed") or 0)
            failed += int(details.get("failed") or 0)
        else:
            passed += scan.policies_passed or 0
            failed += scan.policies_failed or 0
    return passed, failed


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """Lightweight summary for widgets and quick-glance views."""
    org_id = current_user.organization_id
    scorer = RiskScorer(db)

    risk_data = await scorer.get_organization_score(org_id)
    severity = await scorer.get_severity_breakdown(org_id)

    total_findings_q = await db.execute(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == org_id)
        .where(Finding.is_ignored == False)
    )
    total_findings = total_findings_q.scalar() or 0

    open_findings_q = await db.execute(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == org_id)
        .where(Finding.is_fixed == False)
        .where(Finding.is_ignored == False)
    )
    open_findings = open_findings_q.scalar() or 0

    fixed_findings_q = await db.execute(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == org_id)
        .where(Finding.is_fixed == True)
    )
    fixed_findings = fixed_findings_q.scalar() or 0

    total_scans_q = await db.execute(
        select(func.count(Scan.id)).where(Scan.organization_id == org_id)
    )
    total_scans = total_scans_q.scalar() or 0

    from app.models.integration import Integration
    integrations_q = await db.execute(
        select(func.count(Integration.id)).where(
            Integration.organization_id == org_id,
            Integration.is_active == True,
        )
    )
    integrations_count = integrations_q.scalar() or 0

    return DashboardSummaryResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        open_findings=open_findings,
        fixed_findings=fixed_findings,
        critical_count=severity.get("critical", 0),
        high_count=severity.get("high", 0),
        medium_count=severity.get("medium", 0),
        low_count=severity.get("low", 0),
        risk_score=risk_data["overall"],
        integrations_count=integrations_count,
        recent_activity=[],
    )

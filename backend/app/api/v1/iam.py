"""IAM Threat Intelligence API endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.user import User
from app.models.iam import Identity, IAMThreat, AttackPath, IAMScanResult
from app.schemas.iam import (
    IdentityResponse, ThreatResponse, AttackPathResponse,
    IAMDashboardStats, IAMScanRequest, IAMScanResultResponse,
)

router = APIRouter()


# ─── Dashboard Stats ───────────────────────────────────────────────────────────

@router.get("/dashboard", response_model=IAMDashboardStats)
async def iam_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get IAM threat intelligence dashboard statistics."""
    org_id = current_user.organization_id

    # Count identities
    total = await db.scalar(
        select(sa_func.count(Identity.id)).where(Identity.organization_id == org_id)
    ) or 0
    active = await db.scalar(
        select(sa_func.count(Identity.id)).where(
            Identity.organization_id == org_id, Identity.is_active == True
        )
    ) or 0
    dormant = await db.scalar(
        select(sa_func.count(Identity.id)).where(
            Identity.organization_id == org_id, Identity.days_inactive > 90
        )
    ) or 0
    svc_accounts = await db.scalar(
        select(sa_func.count(Identity.id)).where(
            Identity.organization_id == org_id, Identity.identity_type == "service_account"
        )
    ) or 0
    admins = await db.scalar(
        select(sa_func.count(Identity.id)).where(
            Identity.organization_id == org_id, Identity.admin_access == True
        )
    ) or 0
    no_mfa = await db.scalar(
        select(sa_func.count(Identity.id)).where(
            Identity.organization_id == org_id, Identity.mfa_enabled == False
        )
    ) or 0

    # Threats
    total_threats = await db.scalar(
        select(sa_func.count(IAMThreat.id)).where(IAMThreat.organization_id == org_id)
    ) or 0
    critical_threats = await db.scalar(
        select(sa_func.count(IAMThreat.id)).where(
            IAMThreat.organization_id == org_id, IAMThreat.severity == "critical"
        )
    ) or 0
    high_threats = await db.scalar(
        select(sa_func.count(IAMThreat.id)).where(
            IAMThreat.organization_id == org_id, IAMThreat.severity == "high"
        )
    ) or 0
    open_threats = await db.scalar(
        select(sa_func.count(IAMThreat.id)).where(
            IAMThreat.organization_id == org_id, IAMThreat.status == "open"
        )
    ) or 0
    paths = await db.scalar(
        select(sa_func.count(AttackPath.id)).where(AttackPath.organization_id == org_id)
    ) or 0

    avg_risk = await db.scalar(
        select(sa_func.avg(Identity.risk_score)).where(Identity.organization_id == org_id)
    ) or 0

    # By provider
    provider_rows = (await db.execute(
        select(Identity.cloud_provider, sa_func.count(Identity.id))
        .where(Identity.organization_id == org_id)
        .group_by(Identity.cloud_provider)
    )).all()
    by_provider = {row[0]: row[1] for row in provider_rows}

    # By type
    type_rows = (await db.execute(
        select(Identity.identity_type, sa_func.count(Identity.id))
        .where(Identity.organization_id == org_id)
        .group_by(Identity.identity_type)
    )).all()
    by_type = {row[0]: row[1] for row in type_rows}

    # By risk level
    risk_rows = (await db.execute(
        select(Identity.risk_level, sa_func.count(Identity.id))
        .where(Identity.organization_id == org_id)
        .group_by(Identity.risk_level)
    )).all()
    by_risk = {row[0]: row[1] for row in risk_rows}

    return IAMDashboardStats(
        total_identities=total,
        active_identities=active,
        dormant_identities=dormant,
        service_accounts=svc_accounts,
        admin_users=admins,
        mfa_disabled=no_mfa,
        total_threats=total_threats,
        critical_threats=critical_threats,
        high_threats=high_threats,
        open_threats=open_threats,
        attack_paths=paths,
        avg_risk_score=round(float(avg_risk), 1),
        by_provider=by_provider,
        by_identity_type=by_type,
        by_risk_level=by_risk,
        credential_issues=0,
        excessive_permissions=admins,
    )


# ─── Identities CRUD ──────────────────────────────────────────────────────────

@router.get("/identities", response_model=dict)
async def list_identities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    cloud_provider: str | None = None,
    identity_type: str | None = None,
    risk_level: str | None = None,
    search: str | None = None,
    sort_by: str = "risk_score",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List cloud identities with filtering and pagination."""
    org_id = current_user.organization_id
    q = select(Identity).where(Identity.organization_id == org_id)

    if cloud_provider:
        q = q.where(Identity.cloud_provider == cloud_provider)
    if identity_type:
        q = q.where(Identity.identity_type == identity_type)
    if risk_level:
        q = q.where(Identity.risk_level == risk_level)
    if search:
        q = q.where(
            Identity.display_name.ilike(f"%{search}%")
            | Identity.external_id.ilike(f"%{search}%")
            | Identity.email.ilike(f"%{search}%")
        )

    # Count
    count_q = select(sa_func.count()).select_from(q.subquery())
    total = await db.scalar(count_q) or 0

    # Sort
    sort_col = getattr(Identity, sort_by, Identity.risk_score)
    q = q.order_by(sort_col.desc()).offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(q)
    items = result.scalars().all()

    return {
        "items": [IdentityResponse.model_validate(i) for i in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/identities/{identity_id}", response_model=IdentityResponse)
async def get_identity(
    identity_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get identity details."""
    identity = await db.get(Identity, identity_id)
    if not identity or identity.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    return IdentityResponse.model_validate(identity)


# ─── Threats ───────────────────────────────────────────────────────────────────

@router.get("/threats", response_model=dict)
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    threat_type: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List IAM threats with filtering."""
    org_id = current_user.organization_id
    q = select(IAMThreat).where(IAMThreat.organization_id == org_id)

    if severity:
        q = q.where(IAMThreat.severity == severity)
    if status:
        q = q.where(IAMThreat.status == status)
    if threat_type:
        q = q.where(IAMThreat.threat_type == threat_type)

    count_q = select(sa_func.count()).select_from(q.subquery())
    total = await db.scalar(count_q) or 0

    q = q.options(selectinload(IAMThreat.identity))
    q = q.order_by(IAMThreat.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    items = result.scalars().all()

    return {
        "items": [ThreatResponse.model_validate(i) for i in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.patch("/threats/{threat_id}/status")
async def update_threat_status(
    threat_id: int,
    status: str = Query(...),
    notes: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Update threat status (open → investigating → resolved / false_positive)."""
    threat = await db.get(IAMThreat, threat_id)
    if not threat or threat.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat.status = status
    if status in ("resolved", "false_positive"):
        threat.resolved_at = datetime.now(timezone.utc)
        threat.resolved_by = current_user.email
    if notes:
        threat.resolution_notes = notes
    await db.flush()
    return {"status": "updated", "threat_id": threat_id, "new_status": status}


# ─── Attack Paths ──────────────────────────────────────────────────────────────

@router.get("/attack-paths", response_model=list[AttackPathResponse])
async def list_attack_paths(
    severity: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List discovered attack paths."""
    org_id = current_user.organization_id
    q = select(AttackPath).where(AttackPath.organization_id == org_id)
    if severity:
        q = q.where(AttackPath.severity == severity)
    q = q.order_by(AttackPath.risk_score.desc()).limit(50)
    result = await db.execute(q)
    return [AttackPathResponse.model_validate(p) for p in result.scalars().all()]


# ─── Scan ──────────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=IAMScanResultResponse)
async def start_iam_scan(
    body: IAMScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "create")),
):
    """Analyze IAM posture from the synced cloud inventory of one provider.

    Identities, findings and attack paths are derived by fixed rules from IAM
    resources discovered by the cloud connectors (see services/iam_posture.py).
    Requires a connected cloud account; nothing is generated without data.
    """
    import time
    from sqlalchemy import delete as sa_delete

    from app.core.config import settings
    from app.models.cloud_account import CloudAccount
    from app.models.cloud_resource import CloudResource
    from app.services import iam_posture

    org_id = current_user.organization_id
    provider = (body.cloud_provider or "").lower()
    if provider not in iam_posture.IAM_RESOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported cloud provider '{body.cloud_provider}'")
    started = time.monotonic()

    accounts = (await db.execute(
        select(CloudAccount).where(CloudAccount.organization_id == org_id, CloudAccount.provider == provider)
    )).scalars().all()
    if not accounts and not settings.DEMO_DATA_ENABLED:
        raise HTTPException(
            status_code=409,
            detail=f"No {provider.upper()} account is connected. Connect one under Cloud Connectors and "
                   "sync it; the IAM scan analyzes the identities found there.",
        )

    res_q = select(CloudResource).where(
        CloudResource.organization_id == org_id,
        CloudResource.provider == provider,
        CloudResource.status == "active",
        CloudResource.resource_type.in_(iam_posture.IAM_RESOURCE_TYPES[provider]),
    )
    if not settings.DEMO_DATA_ENABLED:
        res_q = res_q.where(CloudResource.source != "seed")
    resources = (await db.execute(res_q)).scalars().all()

    postures = iam_posture.analyze(provider, [
        {"resource_type": r.resource_type, "resource_id": r.resource_id,
         "resource_name": r.resource_name, "config": r.config or {}}
        for r in resources
    ])

    # Replace this provider's identities, keeping analyst triage decisions.
    old_identities = (await db.execute(
        select(Identity).where(Identity.organization_id == org_id, Identity.cloud_provider == provider)
    )).scalars().all()
    old_ids = [i.id for i in old_identities]
    ext_by_id = {i.id: i.external_id for i in old_identities}
    triage: dict[tuple, IAMThreat] = {}
    if old_ids:
        for t in (await db.execute(
            select(IAMThreat).where(IAMThreat.identity_id.in_(old_ids), IAMThreat.status != "open")
        )).scalars().all():
            triage[(ext_by_id.get(t.identity_id), t.threat_type)] = t
        await db.execute(sa_delete(AttackPath).where(AttackPath.source_identity_id.in_(old_ids)))
        await db.execute(sa_delete(IAMThreat).where(IAMThreat.identity_id.in_(old_ids)))
        await db.execute(sa_delete(Identity).where(Identity.id.in_(old_ids)))
        await db.flush()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    threat_total = path_total = 0
    for p in postures:
        ident = Identity(
            organization_id=org_id, tenant_id=current_user.tenant_id,
            cloud_provider=p.provider, identity_type=p.identity_type,
            external_id=p.external_id, display_name=p.display_name,
            is_active=p.is_active, last_activity=p.last_activity,
            created_externally=p.created_externally, days_inactive=p.days_inactive,
            risk_score=p.risk_score, risk_level=p.risk_level, risk_factors=p.risk_factors,
            permissions_count=len(p.attached_policies), admin_access=p.admin_access,
            mfa_enabled=p.mfa_enabled, has_console_access=p.has_console_access,
            has_programmatic_access=p.has_programmatic_access, access_keys=p.access_keys,
            credential_age_days=p.credential_age_days, attached_policies=p.attached_policies,
            raw_data=p.raw_data,
        )
        db.add(ident)
        await db.flush()  # identity PK needed by threats and paths

        for t in p.threats:
            prior = triage.get((p.external_id, t.threat_type))
            keep = prior is not None and prior.status in ("investigating", "false_positive")
            db.add(IAMThreat(
                organization_id=org_id, identity_id=ident.id,
                threat_type=t.threat_type, title=t.title, description=t.description,
                severity=t.severity, confidence=1.0, detection_method="rule_based",
                evidence=t.evidence, mitre_technique=t.mitre_technique,
                status=prior.status if keep else "open",
                resolved_by=prior.resolved_by if keep else None,
                resolution_notes=prior.resolution_notes if keep else None,
                remediation_steps=[
                    {"step": n, "description": d, "automated": False} for n, d in enumerate(t.remediation, 1)
                ],
                auto_remediable=False,
            ))
            threat_total += 1
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1

        for path in p.paths:
            db.add(AttackPath(
                organization_id=org_id, source_identity_id=ident.id,
                title=path.title, description=path.description, severity=path.severity,
                complexity=path.complexity, target_resource=path.target_resource,
                path_steps=path.steps, risk_score=p.risk_score,
            ))
            path_total += 1

    last_synced = max((a.last_synced_at for a in accounts if a.last_synced_at), default=None)
    note = None
    if not resources:
        note = (
            "No IAM resources are in the synced inventory. "
            + ("The account has not been synced yet." if last_synced is None
               else "Check that the connector credentials can list IAM resources.")
        )

    scan = IAMScanResult(
        organization_id=org_id,
        cloud_provider=provider,
        scan_type=body.scan_type,
        status="completed",
        identities_scanned=len(postures),
        threats_found=threat_total,
        attack_paths_found=path_total,
        completed_at=datetime.now(timezone.utc),
        duration_seconds=round(time.monotonic() - started, 3),
        summary={
            "identities": len(postures),
            "threats": threat_total,
            "attack_paths": path_total,
            "risk_breakdown": severity_counts,
            "accounts": [a.name for a in accounts],
            "inventory_synced_at": last_synced.isoformat() if last_synced else None,
            "note": note,
        },
    )
    db.add(scan)
    await db.flush()

    return IAMScanResultResponse.model_validate(scan)


@router.get("/scans", response_model=list[IAMScanResultResponse])
async def list_iam_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """List IAM scan history."""
    result = await db.execute(
        select(IAMScanResult)
        .where(IAMScanResult.organization_id == current_user.organization_id)
        .order_by(IAMScanResult.started_at.desc())
        .limit(20)
    )
    return [IAMScanResultResponse.model_validate(s) for s in result.scalars().all()]

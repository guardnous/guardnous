"""Organization management API — CRUD for top-level customer entities."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List
import re

from app.core.database import get_db
from app.core.rbac import require_permission, ensure_tenant_access, is_superuser
from app.core.audit import write_audit_log
from app.models.tenant import Tenant
from app.models.organization import Organization
from app.schemas.enterprise import (
    TenantCreate, TenantUpdate, TenantResponse, OrganizationCreate, OrganizationResponse,
)

router = APIRouter()


@router.get("/", response_model=List[TenantResponse])
async def list_tenants(
    user=Depends(require_permission("tenants", "read")),
    db: AsyncSession = Depends(get_db),
):
    """List all organizations. Platform admins see all; org admins see their own."""
    if user.role in ("admin", "superadmin"):
        result = await db.execute(select(Tenant).order_by(Tenant.created_at.desc()))
    else:
        result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    return result.scalars().all()


@router.post("/", response_model=TenantResponse, status_code=201)
async def create_tenant(
    data: TenantCreate,
    request: Request,
    user=Depends(require_permission("tenants", "create")),
    db: AsyncSession = Depends(get_db),
):
    if not is_superuser(user):
        raise HTTPException(403, "Only installation administrators can create organizations")
    slug = data.slug or re.sub(r"[^a-z0-9-]", "-", data.name.lower())
    existing = await db.execute(select(Tenant).where(Tenant.slug == slug))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Organization with this slug already exists")

    tenant = Tenant(
        name=data.name, slug=slug, domain=data.domain,
        plan=data.plan, max_users=data.max_users,
        max_organizations=data.max_organizations,
    )
    db.add(tenant)
    await db.flush()
    await write_audit_log(
        db, action="create", resource_type="tenant", resource_id=tenant.id,
        details={"name": data.name, "slug": slug, "plan": data.plan},
        user=user, request=request,
    )
    await db.commit()
    await db.refresh(tenant)

    # Send tenant-created notification email to the creating admin (fire-and-forget)
    try:
        from app.core.email import send_tenant_created_email
        await send_tenant_created_email(
            to_email=user.email,
            admin_name=user.full_name or user.email.split("@")[0],
            tenant_name=data.name,
            tenant_plan=data.plan or "free",
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Tenant-created email failed: %s", e)

    return tenant


# ─── Organization (BU) convenience routes (MUST be before /{tenant_id}) ───

@router.get("/organizations", response_model=List[OrganizationResponse])
async def list_all_organizations(
    tenant_id: int = None,
    user=Depends(require_permission("organizations", "read")),
    db: AsyncSession = Depends(get_db),
):
    """List teams. Admins see all; others see their organization's teams."""
    q = select(Organization)
    if not is_superuser(user):
        q = q.where(Organization.tenant_id == user.tenant_id)
    elif tenant_id:
        q = q.where(Organization.tenant_id == tenant_id)
    result = await db.execute(q.order_by(Organization.id))
    return result.scalars().all()


@router.post("/organizations", response_model=OrganizationResponse, status_code=201)
async def create_organization_simple(
    data: OrganizationCreate,
    user=Depends(require_permission("organizations", "create")),
    db: AsyncSession = Depends(get_db),
):
    """Create team under the caller's organization."""
    tid = user.tenant_id
    result = await db.execute(select(Tenant).where(Tenant.id == tid))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(404, "Organization not found")

    count = await db.execute(
        select(func.count(Organization.id)).where(Organization.tenant_id == tid)
    )
    if count.scalar() >= (tenant.max_organizations or 999999):
        raise HTTPException(400, f"Team limit reached ({tenant.max_organizations})")

    slug = data.slug or re.sub(r"[^a-z0-9-]", "-", data.name.lower())
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        slug = f"{slug}-{tid}"

    org = Organization(
        name=data.name, slug=slug, tenant_id=tid,
        admin_email=data.admin_email,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org


# ─── Tenant detail routes (/{tenant_id} path param) ─────────

@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: int,
    user=Depends(require_permission("tenants", "read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(404, "Organization not found")
    if user.role not in ("admin", "superadmin") and user.tenant_id != tenant_id:
        raise HTTPException(403, "Access denied to this organization")
    return tenant


@router.patch("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: int,
    data: TenantUpdate,
    request: Request,
    user=Depends(require_permission("tenants", "update")),
    db: AsyncSession = Depends(get_db),
):
    ensure_tenant_access(user, tenant_id)
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(404, "Organization not found")

    ALLOWED_FIELDS = {"name", "slug", "domain", "settings"}
    updates = data.model_dump(exclude_unset=True)
    if "name" in updates and (updates["name"] is None or not str(updates["name"]).strip()):
        raise HTTPException(status_code=400, detail="Organization name cannot be empty or null")
    for field, value in updates.items():
        if field not in ALLOWED_FIELDS:
            continue
        setattr(tenant, field, value)
    await write_audit_log(
        db, action="update", resource_type="tenant", resource_id=tenant_id,
        details={"updated_fields": list(updates.keys())},
        user=user, request=request,
    )
    await db.commit()
    await db.refresh(tenant)
    return tenant


@router.get("/{tenant_id}/organizations", response_model=List[OrganizationResponse])
async def list_organizations(
    tenant_id: int,
    user=Depends(require_permission("organizations", "read")),
    db: AsyncSession = Depends(get_db),
):
    ensure_tenant_access(user, tenant_id)
    result = await db.execute(
        select(Organization).where(Organization.tenant_id == tenant_id)
    )
    return result.scalars().all()


@router.post("/{tenant_id}/organizations", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    tenant_id: int,
    data: OrganizationCreate,
    user=Depends(require_permission("organizations", "create")),
    db: AsyncSession = Depends(get_db),
):
    ensure_tenant_access(user, tenant_id)
    # Check tenant limits
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(404, "Organization not found")

    count = await db.execute(
        select(func.count(Organization.id)).where(Organization.tenant_id == tenant_id)
    )
    if count.scalar() >= (tenant.max_organizations or 999999):
        raise HTTPException(400, f"Team limit reached ({tenant.max_organizations})")

    slug = data.slug or re.sub(r"[^a-z0-9-]", "-", data.name.lower())
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        slug = f"{slug}-{tenant_id}"

    org = Organization(
        name=data.name, slug=slug, tenant_id=tenant_id,
        admin_email=data.admin_email,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org

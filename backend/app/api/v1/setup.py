"""Setup wizard API — first-run detection and bootstrap."""
import re
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text, func

from app.core.database import get_db
from app.core.security import get_password_hash, create_access_token
from app.models.user import User
from app.models.tenant import Tenant
from app.models.organization import Organization
from app.models.rbac import Role, UserRole
from app.models.user_organization import UserOrganization
from app.schemas.enterprise import SetupCheckResponse, SetupWizardRequest, SetupWizardResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/check", response_model=SetupCheckResponse)
async def check_setup(db: AsyncSession = Depends(get_db)):
    """Check if the initial setup has been completed. No auth required."""
    try:
        # DB connectivity test
        await db.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    # Check if any admin user exists (covers both "admin" and "superadmin" roles)
    admin_result = await db.execute(
        select(func.count(User.id)).where(User.role.in_(["admin", "superadmin"]))
    )
    has_admin = admin_result.scalar() > 0

    # Check if any tenant exists
    tenant_result = await db.execute(select(func.count(Tenant.id)))
    has_tenant = tenant_result.scalar() > 0

    user_total = (await db.execute(select(func.count(User.id)))).scalar() or 0

    return SetupCheckResponse(
        is_setup_complete=has_admin or user_total > 0,
        has_admin=has_admin,
        has_tenant=has_tenant,
        db_connected=db_connected,
    )


@router.post("/initialize", response_model=SetupWizardResponse)
async def initialize_setup(
    data: SetupWizardRequest,
    db: AsyncSession = Depends(get_db),
):
    """One-time setup — creates tenant, org, and admin. Idempotent: fails if admin exists."""
    # Guard: only on a pristine installation. Checking for *any* user (not just
    # admins) stops this unauthenticated route from minting a superadmin after
    # tenants have signed up through /auth/register.
    user_result = await db.execute(select(func.count(User.id)))
    if user_result.scalar() > 0:
        raise HTTPException(400, "Setup already completed. Use /auth/login instead.")

    try:
        # Ensure seed data (permissions, roles) exists before creating admin
        from app.core.seed import _seed_permissions, _seed_system_roles
        perm_map = await _seed_permissions(db)
        await _seed_system_roles(db, perm_map)

        # 1. Create tenant (or reuse seed tenant)
        existing_tenant = (await db.execute(
            select(Tenant).where(Tenant.id == 1000)
        )).scalar_one_or_none()

        if existing_tenant:
            existing_tenant.name = data.tenant_name
            existing_tenant.slug = re.sub(r"[^a-z0-9-]", "-", data.tenant_name.lower())
            tenant = existing_tenant
        else:
            tenant_slug = re.sub(r"[^a-z0-9-]", "-", data.tenant_name.lower())
            tenant = Tenant(name=data.tenant_name, slug=tenant_slug, plan="enterprise")
            db.add(tenant)
        await db.flush()

        # 2. Create organization
        org_slug = re.sub(r"[^a-z0-9-]", "-", data.organization_name.lower())
        org = Organization(
            name=data.organization_name, slug=org_slug,
            tenant_id=tenant.id, admin_email=data.admin_email,
        )
        db.add(org)
        await db.flush()

        # 3. Create admin user with superadmin role
        admin = User(
            email=data.admin_email,
            hashed_password=get_password_hash(data.admin_password),
            full_name=data.admin_full_name,
            role="superadmin",
            organization_id=org.id,
            tenant_id=tenant.id,
            status="active",
        )
        db.add(admin)
        await db.flush()

        # 4. Link admin to their organization
        db.add(UserOrganization(
            user_id=admin.id,
            organization_id=org.id,
            role_in_org="admin",
        ))

        # 5. Assign platform_admin role
        role_result = await db.execute(select(Role).where(Role.slug == "platform_admin"))
        platform_role = role_result.scalar_one_or_none()
        if platform_role:
            db.add(UserRole(
                user_id=admin.id, role_id=platform_role.id, tenant_id=tenant.id,
            ))

        await db.commit()
        logger.info("Setup wizard complete: admin=%s tenant=%s org=%s",
                     data.admin_email, tenant.id, org.id)

        # Generate login token
        token = create_access_token(data={
            "sub": str(admin.id),
            "tenant_id": tenant.id,
            "org_id": org.id,
            "role": "superadmin",
        })

        return SetupWizardResponse(
            success=True,
            message="Setup complete! You are now logged in as platform admin.",
            tenant_id=tenant.id,
            admin_user_id=admin.id,
            access_token=token,
        )
    except Exception as e:
        await db.rollback()
        logger.exception("Setup wizard failed")
        raise HTTPException(500, f"Setup failed: {str(e)}")

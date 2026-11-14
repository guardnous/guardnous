"""Admin endpoints for managing organizations (super admin only)."""
import re
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.core.security import get_current_active_user
from app.core.config import settings
from app.core.rbac import is_superuser
from app.models.user import User
from app.models.organization import Organization
from app.models.onboarding_token import OnboardingToken
from app.schemas.admin import (
    OrganizationCreate, OrganizationResponse, OrganizationListResponse,
    OnboardingTokenCreate, OnboardingTokenResponse,
)

router = APIRouter()


def require_super_admin(current_user: User):
    """Require an installation superuser (role admin/superadmin).

    Decided by role only. An email address is not proof of identity: the same
    address can be registered in another tenant.
    """
    if not is_superuser(current_user):
        raise HTTPException(status_code=403, detail="Super admin access required")
    return current_user


@router.post("", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    data: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Create a new organization (super admin only)."""
    require_super_admin(current_user)

    slug = re.sub(r"[^a-z0-9-]", "-", data.subdomain.lower().strip())
    schema_name = f"tenant_{slug.replace('-', '_')}"

    # Check uniqueness
    existing = await db.execute(
        select(Organization).where(
            (Organization.slug == slug) | (Organization.subdomain == data.subdomain)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Organization subdomain already exists")

    org = Organization(
        name=data.name,
        slug=slug,
        subdomain=data.subdomain.lower().strip(),
        admin_email=data.admin_email,
        plan=data.plan,
        status="pending",
        schema_name=schema_name,
        webhook_secret=secrets.token_hex(32),
    )
    db.add(org)
    await db.flush()
    await db.refresh(org)
    return org


@router.get("", response_model=OrganizationListResponse)
async def list_organizations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all organizations (super admin only)."""
    require_super_admin(current_user)

    count_result = await db.execute(select(func.count(Organization.id)))
    total = count_result.scalar() or 0

    result = await db.execute(select(Organization).order_by(Organization.created_at.desc()))
    orgs = result.scalars().all()

    return OrganizationListResponse(items=orgs, total=total)


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get organization details (super admin only)."""
    require_super_admin(current_user)
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.post("/{org_id}/onboarding-token", response_model=OnboardingTokenResponse, status_code=201)
async def create_onboarding_token(
    org_id: int,
    data: OnboardingTokenCreate | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Generate a one-time onboarding token for an organization."""
    require_super_admin(current_user)

    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    expires_hours = data.expires_in_hours if data else 72
    token_value = secrets.token_urlsafe(48)

    token = OnboardingToken(
        organization_id=org_id,
        token=token_value,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=expires_hours),
    )
    db.add(token)
    await db.flush()
    await db.refresh(token)

    # Build onboarding URL
    resp = OnboardingTokenResponse.model_validate(token)
    resp.onboarding_url = f"{settings.FRONTEND_URL}/onboard/{token_value}"
    return resp

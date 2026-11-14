"""Onboarding endpoints — public (token-validated) and authenticated."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_password_hash, create_access_token
from app.models.organization import Organization
from app.models.onboarding_token import OnboardingToken
from app.models.user import User
from app.schemas.onboarding import OnboardingValidate, OnboardingSetup, OnboardingComplete

router = APIRouter()


@router.get("/validate/{token}", response_model=OnboardingValidate)
async def validate_token(token: str, db: AsyncSession = Depends(get_db)):
    """Validate an onboarding token (public, no auth required)."""
    result = await db.execute(
        select(OnboardingToken).where(OnboardingToken.token == token)
    )
    obt = result.scalar_one_or_none()

    if not obt:
        return OnboardingValidate(valid=False)

    if obt.is_used:
        return OnboardingValidate(valid=False)

    now = datetime.now(timezone.utc)
    expires = obt.expires_at if obt.expires_at.tzinfo else obt.expires_at.replace(tzinfo=timezone.utc)
    if expires < now:
        return OnboardingValidate(valid=False)

    # Fetch org
    org_result = await db.execute(
        select(Organization).where(Organization.id == obt.organization_id)
    )
    org = org_result.scalar_one_or_none()

    return OnboardingValidate(
        valid=True,
        organization_name=org.name if org else None,
        organization_id=obt.organization_id,
        admin_email=org.admin_email if org else None,
    )


@router.post("/complete", response_model=OnboardingComplete)
async def complete_onboarding(data: OnboardingSetup, db: AsyncSession = Depends(get_db)):
    """Complete onboarding: set password, create admin user, activate org."""
    # Validate token
    result = await db.execute(
        select(OnboardingToken).where(OnboardingToken.token == data.token)
    )
    obt = result.scalar_one_or_none()

    if not obt or obt.is_used:
        raise HTTPException(status_code=400, detail="Invalid or expired onboarding token")
    now = datetime.now(timezone.utc)
    expires = obt.expires_at if obt.expires_at.tzinfo else obt.expires_at.replace(tzinfo=timezone.utc)
    if expires < now:
        raise HTTPException(status_code=400, detail="Invalid or expired onboarding token")

    # Get org
    org_result = await db.execute(
        select(Organization).where(Organization.id == obt.organization_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check if admin user already exists
    existing = await db.execute(
        select(User).where(User.email == org.admin_email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Admin user already exists")

    # Create admin user
    user = User(
        email=org.admin_email,
        hashed_password=get_password_hash(data.password),
        full_name=data.full_name,
        role="admin",
        organization_id=org.id,
    )
    db.add(user)

    # Mark token as used
    obt.is_used = True
    obt.used_at = datetime.now(timezone.utc)

    # Activate organization
    org.status = "active"
    if data.vcs_type:
        org.vcs_type = data.vcs_type

    await db.flush()
    await db.refresh(user)

    # Generate access token
    access_token = create_access_token(data={"sub": str(user.id)})

    return OnboardingComplete(
        success=True,
        organization_id=org.id,
        user_id=user.id,
        access_token=access_token,
    )

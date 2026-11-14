import json
import logging
import re

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import (
    verify_password, get_password_hash, create_access_token, get_current_active_user,
    generate_totp_secret, get_totp_uri, verify_totp_code, generate_qr_base64,
    generate_backup_codes, verify_backup_code, create_mfa_token, decode_mfa_token,
    create_email_verification_token, decode_email_verification_token,
    create_password_reset_token, decode_password_reset_token,
)
from app.core.rbac import get_user_permissions
from app.core.audit import write_audit_log
from app.core.app_logger import app_log
from app.models.user import User
from app.models.organization import Organization
from app.models.tenant import Tenant
from app.models.org_settings import OrgSettings
from app.models.rbac import Role, UserRole
from app.models.user_organization import UserOrganization
from app.schemas.auth import (
    LoginResponse, TwoFactorSetup, TwoFactorVerify,
    UserCreate, UserResponse, UserMeResponse,
    ForgotPasswordRequest, ResetPasswordRequest,
)


router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Create a new organization with the registering user as Platform Admin.

    This is a one-time org founding act. After this, all users join via invite only.
    """
    # Password complexity validation
    password = user_data.password
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r'[A-Z]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter")
    if not re.search(r'\d', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character")

    # Check if user exists — email uniqueness is per-organization, but at registration
    # the org doesn't exist yet. We only block if same email already registered a tenant.
    # (Same email CAN exist in different tenants — that's multi-tenant isolation.)

    # Extract email domain for uniqueness check
    email_domain = user_data.email.split("@")[1].lower()
    # Block common free email providers from org registration
    free_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"}

    # Use user-provided domain if given, otherwise auto-extract from email
    use_domain = user_data.domain.strip().lower() if user_data.domain else (
        email_domain if email_domain not in free_providers else None
    )

    # Check if domain already claimed
    if use_domain:
        existing_tenant_domain = await db.execute(
            select(Tenant).where(Tenant.domain == use_domain)
        )
        if existing_tenant_domain.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail=f"Organization for domain '{use_domain}' already exists. "
                       "Please ask your admin to invite you.",
            )

    # 1. Create Tenant (top-level customer entity)
    tenant_name = getattr(user_data, "tenant_name", None) or user_data.organization_name or email_domain.split(".")[0].title()
    tenant_slug = re.sub(r"[^a-z0-9-]", "-", tenant_name.lower()).strip("-")
    # Ensure unique slug
    existing_tenant = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    if existing_tenant.scalar_one_or_none():
        tenant_slug = f"{tenant_slug}-{hash(user_data.email) % 10000}"
    tenant = Tenant(
        name=tenant_name,
        slug=tenant_slug,
        domain=use_domain,
        plan="free",
    )
    db.add(tenant)
    await db.flush()

    # 2. Create default Team (DB: Organization) under the Organization (DB: Tenant)
    org_name = f"{tenant_name} GuardNous" if not user_data.organization_name else user_data.organization_name
    org_slug = re.sub(r"[^a-z0-9-]", "-", org_name.lower()).strip("-")
    existing_org = await db.execute(select(Organization).where(Organization.slug == org_slug))
    if existing_org.scalar_one_or_none():
        org_slug = f"{org_slug}-{hash(user_data.email) % 10000}"
    org = Organization(
        name=org_name,
        slug=org_slug,
        tenant_id=tenant.id,
        admin_email=user_data.email,
        plan_tier="free",
        max_users=10,
        max_repos=5,
    )
    db.add(org)
    await db.flush()

    # 3. Create User as Platform Admin
    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role="platform_admin",
        organization_id=org.id,
        tenant_id=tenant.id,
        status="active",
    )
    db.add(user)
    await db.flush()

    # 4. Assign platform_admin role (full access)
    role_result = await db.execute(select(Role).where(Role.slug == "platform_admin"))
    platform_admin_role = role_result.scalar_one_or_none()
    if platform_admin_role:
        db.add(UserRole(
            user_id=user.id,
            role_id=platform_admin_role.id,
            tenant_id=tenant.id,
        ))

    # 5. Add user→org membership in junction table
    db.add(UserOrganization(
        user_id=user.id,
        organization_id=org.id,
        role_in_org="admin",
    ))

    # 6. Create OrgSettings with setup_completed=False to enforce setup wizard
    org_settings = OrgSettings(organization_id=org.id, setup_completed=False)
    db.add(org_settings)

    await db.commit()
    await db.refresh(user)

    # Send welcome + verification email (fire-and-forget)
    try:
        from app.core.email import send_account_created_email
        from app.core.config import settings as app_settings

        verify_token = create_email_verification_token(user.id)
        verify_url = f"{app_settings.FRONTEND_URL}/verify-email?token={verify_token}"

        await send_account_created_email(
            to_email=user.email,
            user_name=user.full_name or user.email.split("@")[0],
            org_name=org_name,
            role="Platform Admin",
            verify_url=verify_url,
        )
    except Exception as e:
        logger.warning("Verification email failed for %s: %s", user.email, e)

    return user


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    # Multi-tenant: same email can exist across orgs. Find the user whose password matches.
    result = await db.execute(select(User).where(User.email == form_data.username))
    candidates = result.scalars().all()

    user = None
    for candidate in candidates:
        if verify_password(form_data.password, candidate.hashed_password):
            user = candidate
            break

    if not user:
        await app_log.warning(db, "AUTH", f"Failed login attempt for {form_data.username}", source="auth.login", metadata={"ip": request.client.host if request.client else None})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if getattr(user, "status", "active") == "deactivated":
        raise HTTPException(status_code=403, detail="Account deactivated")

    # Check if 2FA is required
    user_has_2fa = getattr(user, "totp_enabled", False) and getattr(user, "totp_confirmed", False)

    # Check org enforcement
    org_enforces_2fa = False
    if user.organization_id:
        org_result = await db.execute(
            select(OrgSettings).where(OrgSettings.organization_id == user.organization_id)
        )
        org_settings = org_result.scalar_one_or_none()
        if org_settings and getattr(org_settings, "enforce_2fa", False):
            org_enforces_2fa = True

    if user_has_2fa:
        # User has 2FA set up → require verification
        # No DB writes in this branch — skip commit to avoid unnecessary round-trip
        mfa_token = create_mfa_token(user.id)
        return LoginResponse(mfa_required=True, mfa_token=mfa_token, user_id=user.id)

    if org_enforces_2fa and not user_has_2fa:
        # Org mandates 2FA but user hasn't set it up → force setup
        secret = generate_totp_secret()
        user.totp_secret = secret
        user.totp_enabled = True
        user.totp_confirmed = False
        totp_uri = get_totp_uri(secret, user.email)
        qr_b64 = generate_qr_base64(totp_uri)
        plain_codes, hashed_codes = generate_backup_codes()
        user.backup_codes = json.dumps(hashed_codes)
        mfa_token = create_mfa_token(user.id)
        await db.commit()
        return LoginResponse(
            mfa_setup_required=True,
            mfa_token=mfa_token,
            totp_uri=totp_uri,
            qr_code=qr_b64,
            user_id=user.id,
        )

    # Resolve org name for JWT claims
    org_name = None
    if user.organization_id:
        org_row = await db.execute(
            select(Organization).where(Organization.id == user.organization_id)
        )
        org_obj = org_row.scalar_one_or_none()
        if org_obj:
            org_name = org_obj.name

    # No 2FA — issue full token directly
    access_token = create_access_token(data={
        "sub": str(user.id),
        "email": user.email,
        "tenant_id": user.tenant_id,
        "org_id": user.organization_id,
        "org_name": org_name,
        "role": user.role,
    })

    await write_audit_log(
        db, action="login", resource_type="auth", resource_id=user.id,
        user=user, request=request,
    )
    await app_log.info(db, "AUTH", f"User {user.email} logged in successfully", user=user, source="auth.login")
    await db.commit()

    return LoginResponse(
        access_token=access_token,
        tenant_id=user.tenant_id,
        organization_id=user.organization_id,
        organization_name=org_name,
        user_id=user.id,
        role=user.role,
    )


@router.post("/verify-2fa", response_model=LoginResponse)
async def verify_2fa(body: TwoFactorVerify, request: Request, db: AsyncSession = Depends(get_db)):
    """Verify 6-digit TOTP code (or backup code) after password step. Returns full JWT."""
    user_id = decode_mfa_token(body.mfa_token or "")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    code = body.code.strip()
    secret = getattr(user, "totp_secret", None)
    valid = False

    # Try TOTP first
    if secret and verify_totp_code(secret, code):
        valid = True
    else:
        # Try backup code
        ok, updated_json = verify_backup_code(code, getattr(user, "backup_codes", None))
        if ok:
            valid = True
            user.backup_codes = updated_json

    if not valid:
        raise HTTPException(status_code=401, detail="Invalid verification code")

    # If this is setup confirmation, mark confirmed
    if not getattr(user, "totp_confirmed", False):
        user.totp_confirmed = True

    # Resolve org name for JWT claims
    org_name = None
    if user.organization_id:
        org_row = await db.execute(
            select(Organization).where(Organization.id == user.organization_id)
        )
        org_obj = org_row.scalar_one_or_none()
        if org_obj:
            org_name = org_obj.name

    access_token = create_access_token(data={
        "sub": str(user.id),
        "email": user.email,
        "tenant_id": user.tenant_id,
        "org_id": user.organization_id,
        "org_name": org_name,
        "role": user.role,
    })

    await write_audit_log(
        db, action="login_2fa", resource_type="auth", resource_id=user.id,
        user=user, request=request,
    )
    await app_log.info(db, "AUTH", f"User {user.email} passed 2FA", user=user, source="auth.verify_2fa")
    await db.commit()

    return LoginResponse(
        access_token=access_token,
        tenant_id=user.tenant_id,
        organization_id=user.organization_id,
        organization_name=org_name,
        user_id=user.id,
        role=user.role,
    )


@router.post("/2fa/setup", response_model=TwoFactorSetup)
async def setup_2fa(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new TOTP secret + QR code for the current user (voluntary setup)."""
    secret = generate_totp_secret()
    current_user.totp_secret = secret
    current_user.totp_enabled = True
    current_user.totp_confirmed = False
    totp_uri = get_totp_uri(secret, current_user.email)
    qr_b64 = generate_qr_base64(totp_uri)
    plain_codes, hashed_codes = generate_backup_codes()
    current_user.backup_codes = json.dumps(hashed_codes)
    await db.commit()
    return TwoFactorSetup(totp_uri=totp_uri, qr_code=qr_b64, backup_codes=plain_codes)


@router.post("/2fa/confirm")
async def confirm_2fa(
    body: TwoFactorVerify,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Confirm TOTP setup by verifying a 6-digit code from the authenticator app."""
    secret = getattr(current_user, "totp_secret", None)
    if not secret:
        raise HTTPException(status_code=400, detail="2FA setup not initiated")

    if not verify_totp_code(secret, body.code.strip()):
        raise HTTPException(status_code=400, detail="Invalid code — try again")

    current_user.totp_confirmed = True
    await db.commit()
    return {"status": "ok", "message": "Two-factor authentication enabled successfully"}


@router.post("/2fa/disable")
async def disable_2fa(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable 2FA for the current user."""
    current_user.totp_secret = None
    current_user.totp_enabled = False
    current_user.totp_confirmed = False
    current_user.backup_codes = None
    await db.commit()
    return {"status": "ok", "message": "Two-factor authentication disabled"}


@router.get("/2fa/backup-codes")
async def get_backup_codes(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Regenerate backup codes (invalidates old ones)."""
    if not getattr(current_user, "totp_enabled", False):
        raise HTTPException(status_code=400, detail="2FA is not enabled")
    plain_codes, hashed_codes = generate_backup_codes()
    current_user.backup_codes = json.dumps(hashed_codes)
    await db.commit()
    return {"backup_codes": plain_codes}


@router.get("/me", response_model=UserMeResponse)
async def get_me(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Return current user with effective permissions and org/tenant context."""
    permissions = await get_user_permissions(
        user_id=current_user.id,
        db=db,
        tenant_id=current_user.tenant_id,
        organization_id=current_user.organization_id,
    )

    # Get tenant and org names
    tenant_name = None
    org_name = None
    if current_user.tenant_id:
        t = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
        tenant = t.scalar_one_or_none()
        if tenant:
            tenant_name = tenant.name
    if current_user.organization_id:
        o = await db.execute(select(Organization).where(Organization.id == current_user.organization_id))
        org = o.scalar_one_or_none()
        if org:
            org_name = org.name

    # Check if initial setup wizard has been completed for this org
    setup_done = True
    if current_user.organization_id and current_user.role in ("admin", "super_admin", "superadmin", "owner"):
        row = await db.execute(
            select(OrgSettings).where(OrgSettings.organization_id == current_user.organization_id)
        )
        org_settings = row.scalar_one_or_none()
        if org_settings and not org_settings.setup_completed:
            setup_done = False
        elif not org_settings:
            setup_done = False

    # Get all org memberships for the user
    from app.schemas.auth import OrgMembershipResponse
    memberships_result = await db.execute(
        select(UserOrganization, Organization)
        .join(Organization, UserOrganization.organization_id == Organization.id)
        .where(UserOrganization.user_id == current_user.id)
    )
    orgs_list = [
        OrgMembershipResponse(
            organization_id=uo.organization_id,
            organization_name=org_obj.name,
            role_in_org=uo.role_in_org or "member",
            is_active=org_obj.is_active if hasattr(org_obj, "is_active") else True,
        )
        for uo, org_obj in memberships_result.all()
    ]

    return UserMeResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        # These columns are nullable; an account created without them must not break sign-in.
        is_active=bool(current_user.is_active),
        organization_id=current_user.organization_id,
        tenant_id=current_user.tenant_id,
        status=getattr(current_user, "status", "active"),
        last_login_at=current_user.last_login_at,
        permissions=sorted(permissions),
        tenant_name=tenant_name,
        organization_name=org_name,
        totp_enabled=bool(getattr(current_user, "totp_enabled", False) and getattr(current_user, "totp_confirmed", False)),
        setup_completed=setup_done,
        email_verified=bool(getattr(current_user, "email_verified", False)),
        organizations=orgs_list,
    )


# ─── Email Verification ─────────────────────────────────────────────

@router.get("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    """Verify a user's email via the token sent in the confirmation email."""
    user_id = decode_email_verification_token(token)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if getattr(user, "email_verified", False):
        return {"status": "already_verified", "message": "Email is already verified"}

    user.email_verified = True
    await db.commit()
    return {"status": "verified", "message": "Email verified successfully"}


@router.post("/resend-verification")
async def resend_verification_email(
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Resend the email verification link (authenticated users only)."""
    if getattr(current_user, "email_verified", False):
        return {"status": "already_verified", "message": "Email is already verified"}

    from app.core.email import send_account_created_email
    from app.core.config import settings as app_settings

    # Get org name for the email
    org_name = "your organization"
    if current_user.organization_id:
        o = await db.execute(select(Organization).where(Organization.id == current_user.organization_id))
        org = o.scalar_one_or_none()
        if org:
            org_name = org.name

    verify_token = create_email_verification_token(current_user.id)
    verify_url = f"{app_settings.FRONTEND_URL}/verify-email?token={verify_token}"

    email_result = await send_account_created_email(
        to_email=current_user.email,
        user_name=current_user.full_name or current_user.email.split("@")[0],
        org_name=org_name,
        role=current_user.role,
        verify_url=verify_url,
    )
    return {"status": "sent", "email_status": email_result.get("status")}


@router.post("/forgot-password")
async def forgot_password(body: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Send a password reset link. Always returns success to avoid leaking user existence."""
    import re
    email = body.email.strip().lower()
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return {"message": "If an account exists with that email, you will receive a password reset link."}

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()

    if user and user.status == "active":
        token = create_password_reset_token(user.id)
        from app.core.config import settings as app_settings
        reset_url = f"{app_settings.FRONTEND_URL}/reset-password?token={token}"

        from app.core.email import send_password_reset_email
        await send_password_reset_email(
            to_email=user.email,
            user_name=user.full_name or user.email.split("@")[0],
            reset_url=reset_url,
        )

    return {"message": "If an account exists with that email, you will receive a password reset link."}


@router.post("/reset-password")
async def reset_password(body: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Reset password using a valid reset token."""
    import re
    password = body.new_password
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must contain an uppercase letter")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Password must contain a lowercase letter")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=400, detail="Password must contain a digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(status_code=400, detail="Password must contain a special character")

    user_id = decode_password_reset_token(body.token)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    user.hashed_password = get_password_hash(password)
    db.add(user)
    await db.commit()

    return {"message": "Password has been reset successfully. You can now log in with your new password."}

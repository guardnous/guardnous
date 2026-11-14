"""Team & multi-organization management API.

Covers:
  - Multi-organization dashboard
  - Team CRUD (scoped to caller's organization)
  - Team switching (returns new JWT)
  - User invitations (invite, list, accept, revoke)
  - Team member management (list, change role, remove)
  - Current organization details, stats, and settings
  - Super-admin: suspend / reactivate organizations
"""
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import create_access_token, get_current_active_user
from app.core.rbac import (
    ROLE_RANK, ensure_can_grant_role, ensure_can_invite_as, ensure_tenant_access, is_superuser, sync_user_role,
)
from app.models.invitation import UserInvitation
from app.models.organization import Organization
from app.models.rbac import Role, UserRole
from app.models.tenant import Tenant
from app.models.user import User
from app.models.user_organization import UserOrganization

logger = logging.getLogger(__name__)

router = APIRouter()

_INVITE_ROLES = ("admin", "superadmin", "platform_admin", "tenant_admin", "org_admin")
# Roles that administer every team of their tenant.
_TENANT_ADMIN_ROLES = ("admin", "superadmin", "platform_admin", "tenant_admin")


# ─── Schemas ────────────────────────────────────────────────

class OrgResponse(BaseModel):
    id: int
    tenant_id: Optional[int] = None
    name: str
    slug: str
    subdomain: Optional[str] = None
    admin_email: Optional[str] = None
    plan: Optional[str] = None
    status: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class OrgCreate(BaseModel):
    name: str
    slug: str
    subdomain: Optional[str] = None
    admin_email: Optional[str] = None


class InviteRequest(BaseModel):
    emails: list[str]
    role: str = "viewer"
    message: Optional[str] = None


class InviteResponse(BaseModel):
    id: int
    email: str
    role_slug: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class OrgSwitchResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    organization_id: int
    organization_name: str
    tenant_id: Optional[int] = None


class MemberResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    role: str
    status: Optional[str] = "active"
    last_login_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class MemberRoleUpdate(BaseModel):
    role: str


class TenantSwitchResponse(BaseModel):
    tenant_id: int
    tenant_name: str
    organizations: list[OrgResponse]


class MultiTenantDashboard(BaseModel):
    total_tenants: int
    total_organizations: int
    total_users: int
    total_invitations: int
    pending_invitations: int
    tenants: list[dict]


# ─── Dashboard ──────────────────────────────────────────────

@router.get("/dashboard", response_model=MultiTenantDashboard)
async def multi_tenant_dashboard(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    # Everyone except installation superusers sees only their own tenant.
    scoped = not is_superuser(current_user)
    tid = current_user.tenant_id

    def _scope(col):
        return [col == tid] if scoped else []

    tenant_q = select(Tenant).where(*_scope(Tenant.id))

    tenant_count = (await db.execute(
        select(sa_func.count(Tenant.id)).where(*_scope(Tenant.id))
    )).scalar() or 0
    org_count = (await db.execute(
        select(sa_func.count(Organization.id)).where(*_scope(Organization.tenant_id))
    )).scalar() or 0
    user_count = (await db.execute(
        select(sa_func.count(User.id)).where(*_scope(User.tenant_id))
    )).scalar() or 0
    inv_count = (await db.execute(
        select(sa_func.count(UserInvitation.id)).where(*_scope(UserInvitation.tenant_id))
    )).scalar() or 0
    pending_count = (await db.execute(
        select(sa_func.count(UserInvitation.id)).where(
            UserInvitation.status == "pending", *_scope(UserInvitation.tenant_id)
        )
    )).scalar() or 0

    tenants_q = await db.execute(tenant_q.order_by(Tenant.created_at.desc()).limit(20))
    tenants = []
    for t in tenants_q.scalars().all():
        org_ct = (await db.execute(
            select(sa_func.count(Organization.id)).where(Organization.tenant_id == t.id)
        )).scalar() or 0
        user_ct = (await db.execute(
            select(sa_func.count(User.id)).where(User.tenant_id == t.id)
        )).scalar() or 0
        tenants.append({
            "id": t.id, "name": t.name, "slug": t.slug, "plan": t.plan,
            "status": t.status, "org_count": org_ct, "user_count": user_ct,
            "created_at": str(t.created_at),
        })

    return MultiTenantDashboard(
        total_tenants=tenant_count,
        total_organizations=org_count,
        total_users=user_count,
        total_invitations=inv_count,
        pending_invitations=pending_count,
        tenants=tenants,
    )


# ─── Organizations ──────────────────────────────────────────

@router.get("/organizations", response_model=list[OrgResponse])
async def list_organizations(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(Organization).order_by(Organization.created_at.desc())
    if not is_superuser(current_user):
        q = q.where(Organization.tenant_id == current_user.tenant_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/organizations", response_model=OrgResponse)
async def create_organization(
    body: OrgCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role not in ("admin", "superadmin", "platform_admin", "tenant_admin"):
        raise HTTPException(403, "Only tenant admins can create teams")
    existing = await db.execute(select(Organization).where(Organization.slug == body.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(400, f"Team with slug '{body.slug}' already exists")

    org = Organization(
        name=body.name,
        slug=body.slug,
        subdomain=body.subdomain,
        admin_email=body.admin_email or current_user.email,
        tenant_id=current_user.tenant_id,
        status="active",
        webhook_secret=secrets.token_hex(32),
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org


# ─── Org Switching ──────────────────────────────────────────

@router.post("/switch/{org_id}", response_model=OrgSwitchResponse)
async def switch_organization(
    org_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Switch the user's active organization and return a new JWT."""
    # Verify org exists and belongs to the user's tenant
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Team not found")

    # The team must be in the caller's tenant (superusers excepted)
    if not is_superuser(current_user) and org.tenant_id != current_user.tenant_id:
        raise HTTPException(403, "You do not have access to this team")

    # Tenant owners may enter any team in their tenant; everyone else needs a membership
    is_platform_admin = current_user.role in ("admin", "superadmin", "platform_admin", "tenant_admin")
    if not is_platform_admin:
        member_check = await db.execute(
            select(UserOrganization.id).where(
                UserOrganization.user_id == current_user.id,
                UserOrganization.organization_id == org_id,
            )
        )
        if not member_check.scalar_one_or_none():
            raise HTTPException(403, "You are not a member of this organization")

    # Update user's active organization
    current_user.organization_id = org_id
    await db.commit()

    # Issue new JWT with updated org_id
    access_token = create_access_token(data={
        "sub": str(current_user.id),
        "tenant_id": current_user.tenant_id,
        "org_id": org_id,
        "role": current_user.role,
    })

    return OrgSwitchResponse(
        access_token=access_token,
        organization_id=org.id,
        organization_name=org.name,
        tenant_id=current_user.tenant_id,
    )


# ─── Invitations ────────────────────────────────────────────

@router.post("/invite", response_model=list[InviteResponse])
async def bulk_invite_users(
    body: InviteRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Invite users by email to the current user's organization."""
    if current_user.role not in _INVITE_ROLES:
        raise HTTPException(403, "Only admins can invite users")
    ensure_can_invite_as(current_user, body.role)
    results = []
    now = datetime.now(timezone.utc)
    for email in body.emails:
        # Skip if there's already a pending invite for this email in this org
        existing = await db.execute(
            select(UserInvitation).where(
                UserInvitation.email == email,
                UserInvitation.organization_id == current_user.organization_id,
                UserInvitation.status == "pending",
            )
        )
        if existing.scalar_one_or_none():
            continue

        invite = UserInvitation(
            email=email,
            tenant_id=current_user.tenant_id or 0,
            organization_id=current_user.organization_id,
            role_slug=body.role,
            token=str(uuid.uuid4()),
            status="pending",
            invited_by_id=current_user.id,
            expires_at=now + timedelta(days=7),
        )
        db.add(invite)
        await db.flush()
        results.append(invite)

    await db.commit()
    for r in results:
        await db.refresh(r)

    # Send invitation emails (fire-and-forget — don't fail the request)
    try:
        from app.core.email import send_org_invite_email
        from app.core.config import settings

        org_name = ""
        if current_user.organization_id:
            org = await db.get(Organization, current_user.organization_id)
            if org:
                org_name = org.name or ""

        inviter_name = current_user.full_name or current_user.email
        for invite in results:
            try:
                invite_link = f"{settings.FRONTEND_URL}/invite/{invite.token}"
                await send_org_invite_email(
                    to_email=invite.email,
                    org_name=org_name,
                    inviter_name=inviter_name,
                    invite_link=invite_link,
                    role=invite.role_slug or "viewer",
                )
            except Exception as e:
                logger.warning("Failed to send invite email to %s: %s", invite.email, e)
    except Exception as e:
        logger.warning("Email sending setup failed: %s", e)

    return results


@router.get("/invitations", response_model=list[InviteResponse])
async def list_invitations(
    status: str | None = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List invitations for the current user's organization."""
    q = select(UserInvitation).where(
        UserInvitation.organization_id == current_user.organization_id,
    ).order_by(UserInvitation.created_at.desc())
    if status:
        q = q.where(UserInvitation.status == status)
    result = await db.execute(q.limit(50))
    return result.scalars().all()


@router.post("/invitations/{invitation_id}/accept")
async def accept_invitation(
    invitation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Accept an invitation — the invitation's email must match the current user."""
    invite = await db.get(UserInvitation, invitation_id)
    if not invite:
        raise HTTPException(404, "Invitation not found")
    if invite.status != "pending":
        raise HTTPException(400, f"Invitation is already {invite.status}")
    if invite.email.lower() != current_user.email.lower():
        raise HTTPException(403, "This invitation is not for your email")

    now = datetime.now(timezone.utc)
    if invite.expires_at and invite.expires_at.replace(tzinfo=timezone.utc) < now:
        invite.status = "expired"
        await db.commit()
        raise HTTPException(400, "Invitation has expired")

    # Accept: update invite status
    invite.status = "accepted"
    invite.accepted_at = now

    # Update user's org membership if the invite is for a different org
    if invite.organization_id and invite.organization_id != current_user.organization_id:
        current_user.organization_id = invite.organization_id
    if invite.tenant_id:
        current_user.tenant_id = invite.tenant_id

    # Assign role from invitation
    if invite.role_slug:
        role_result = await db.execute(select(Role).where(Role.slug == invite.role_slug))
        role = role_result.scalar_one_or_none()
        if role:
            existing_role = await db.execute(
                select(UserRole).where(
                    UserRole.user_id == current_user.id,
                    UserRole.role_id == role.id,
                    UserRole.tenant_id == invite.tenant_id,
                )
            )
            if not existing_role.scalar_one_or_none():
                db.add(UserRole(
                    user_id=current_user.id,
                    role_id=role.id,
                    tenant_id=invite.tenant_id,
                    organization_id=invite.organization_id,
                ))

    await db.commit()
    return {"status": "accepted", "organization_id": invite.organization_id}


@router.delete("/invitations/{invitation_id}")
async def revoke_invitation(
    invitation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    # Whoever may invite may revoke; an ordinary member may do neither.
    if current_user.role not in _INVITE_ROLES:
        raise HTTPException(403, "Only admins can revoke invitations")
    invite = await db.get(UserInvitation, invitation_id)
    if not invite:
        raise HTTPException(404, "Invitation not found")
    # Only allow revoking invitations from the user's own org
    if invite.organization_id != current_user.organization_id:
        raise HTTPException(403, "Cannot revoke invitations from another team")
    invite.status = "revoked"
    await db.commit()
    return {"status": "revoked"}


# ─── Member Management ─────────────────────────────────────

@router.get("/members", response_model=list[MemberResponse])
async def list_members(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List members of the current user's organization."""
    result = await db.execute(
        select(User)
        .where(
            User.organization_id == current_user.organization_id,
            User.status != "deactivated",
        )
        .order_by(User.created_at.desc())
    )
    return result.scalars().all()


@router.put("/members/{user_id}/role")
async def update_member_role(
    user_id: int,
    body: MemberRoleUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Change a member's role within the organization."""
    if current_user.role not in ("admin", "superadmin", "platform_admin", "org_admin"):
        raise HTTPException(403, "Only admins can change member roles")

    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.organization_id != current_user.organization_id:
        raise HTTPException(403, "User is not in your team")
    if target.id == current_user.id:
        raise HTTPException(400, "Cannot change your own role")

    ensure_can_grant_role(current_user, body.role, target_current_role=target.role)
    await sync_user_role(db, target, body.role, assigned_by=current_user)
    await db.commit()
    return {"status": "updated", "user_id": user_id, "new_role": body.role}


@router.delete("/members/{user_id}")
async def remove_member(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a member from the organization (soft-deactivate)."""
    if current_user.role not in ("admin", "superadmin", "platform_admin", "org_admin"):
        raise HTTPException(403, "Only admins can remove members")

    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.organization_id != current_user.organization_id:
        raise HTTPException(403, "User is not in your team")
    if target.id == current_user.id:
        raise HTTPException(400, "Cannot remove yourself")
    # A team admin must not be able to lock out the tenant owner or an operator.
    if ROLE_RANK.get(target.role, 0) > ROLE_RANK.get(current_user.role, 0):
        raise HTTPException(403, "Cannot remove a user with a higher role")

    target.status = "deactivated"
    target.is_active = False
    await db.commit()
    return {"status": "removed", "user_id": user_id}


# ─── Legacy Tenant Switch (backward compat) ────────────────

@router.get("/tenants/{tenant_id}/switch", response_model=TenantSwitchResponse)
async def switch_tenant(
    tenant_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    ensure_tenant_access(current_user, tenant_id)
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(404, "Organization not found")

    orgs_q = await db.execute(
        select(Organization).where(Organization.tenant_id == tenant_id)
    )
    orgs = orgs_q.scalars().all()

    return TenantSwitchResponse(
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        organizations=[OrgResponse.model_validate(o) for o in orgs],
    )


# ─── User–Organization Assignment ───────────────────────────

@router.get("/users/search")
async def search_users_in_tenant(
    q: str = "",
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Search users within the current tenant (autocomplete-friendly)."""
    query = select(User).where(User.tenant_id == current_user.tenant_id)
    # Only tenant admins see people outside their own team.
    if current_user.role not in _TENANT_ADMIN_ROLES:
        query = query.where(User.organization_id == current_user.organization_id)
    if q:
        query = query.where(
            (User.email.ilike(f"%{q}%")) | (User.full_name.ilike(f"%{q}%"))
        )
    query = query.limit(20)
    result = await db.execute(query)
    users = result.scalars().all()
    return [
        {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role}
        for u in users
    ]


@router.post("/assign-user")
async def assign_user_to_org(
    payload: dict,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Assign a user to an organization. Admin/platform_admin only."""
    if current_user.role not in ("admin", "superadmin", "platform_admin"):
        raise HTTPException(403, "Only admins can assign users to organizations")

    user_id = payload.get("user_id")
    organization_id = payload.get("organization_id")
    role_in_org = payload.get("role_in_org", "member")

    if not user_id or not organization_id:
        raise HTTPException(400, "user_id and organization_id are required")

    # Verify target user exists
    target_user = await db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "User not found")

    # Verify org exists and belongs to the same tenant (unless superadmin for cross-tenant)
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    if not is_superuser(current_user):
        if org.tenant_id != current_user.tenant_id:
            raise HTTPException(403, "Cannot assign users to organizations in other tenants")
        if target_user.tenant_id != current_user.tenant_id:
            raise HTTPException(404, "User not found")

    # Check existing membership
    existing = await db.execute(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == organization_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(409, "User is already a member of this organization")

    membership = UserOrganization(
        user_id=user_id,
        organization_id=organization_id,
        role_in_org=role_in_org,
        added_by=current_user.id,
    )
    db.add(membership)

    # If user has no active org, set this as their active org
    if not target_user.organization_id:
        target_user.organization_id = organization_id

    await db.commit()

    # Send notification email
    try:
        from app.core.email import send_org_assignment_email
        await send_org_assignment_email(
            to_email=target_user.email,
            user_name=target_user.full_name or target_user.email.split("@")[0],
            org_name=org.name,
            role=role_in_org,
            added_by_name=current_user.full_name or current_user.email,
        )
    except Exception:
        pass  # non-critical

    return {"status": "assigned", "user_id": user_id, "organization_id": organization_id, "role_in_org": role_in_org}


@router.delete("/remove-user")
async def remove_user_from_org(
    payload: dict,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a user from an organization. Admin/platform_admin only."""
    if current_user.role not in ("admin", "superadmin", "platform_admin"):
        raise HTTPException(403, "Only admins can remove users from organizations")

    user_id = payload.get("user_id")
    organization_id = payload.get("organization_id")
    if not user_id or not organization_id:
        raise HTTPException(400, "user_id and organization_id are required")

    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(404, "Membership not found")
    ensure_tenant_access(current_user, org.tenant_id)

    result = await db.execute(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == organization_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(404, "Membership not found")

    await db.delete(membership)

    # If this was the user's active org, switch to another
    target_user = await db.get(User, user_id)
    if target_user and target_user.organization_id == organization_id:
        other = await db.execute(
            select(UserOrganization.organization_id)
            .where(UserOrganization.user_id == user_id, UserOrganization.organization_id != organization_id)
            .limit(1)
        )
        other_org = other.scalar_one_or_none()
        target_user.organization_id = other_org  # may be None

    await db.commit()
    return {"status": "removed", "user_id": user_id, "organization_id": organization_id}


@router.get("/user-memberships/{user_id}")
async def get_user_memberships(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all organization memberships for a user."""
    # Your own memberships, or as a tenant admin those of a user in your tenant.
    if user_id != current_user.id and not is_superuser(current_user):
        target = await db.get(User, user_id)
        if (
            current_user.role not in _TENANT_ADMIN_ROLES
            or not target
            or target.tenant_id is None
            or target.tenant_id != current_user.tenant_id
        ):
            raise HTTPException(404, "User not found")
    result = await db.execute(
        select(UserOrganization, Organization)
        .join(Organization, UserOrganization.organization_id == Organization.id)
        .where(UserOrganization.user_id == user_id)
    )
    return [
        {
            "id": uo.id,
            "organization_id": uo.organization_id,
            "organization_name": org.name,
            "role_in_org": uo.role_in_org,
            "joined_at": uo.joined_at.isoformat() if uo.joined_at else None,
        }
        for uo, org in result.all()
    ]


# ─── Current Organization ──────────────────────────────────


class OrgDetailResponse(BaseModel):
    id: int
    tenant_id: Optional[int] = None
    name: str
    slug: str
    subdomain: Optional[str] = None
    admin_email: Optional[str] = None
    plan: Optional[str] = None
    plan_tier: Optional[str] = None
    status: str
    is_active: bool
    max_users: Optional[int] = None
    max_repos: Optional[int] = None
    features: Optional[dict] = None
    created_at: datetime

    class Config:
        from_attributes = True


class OrgUpdate(BaseModel):
    name: Optional[str] = None
    admin_email: Optional[str] = None
    subdomain: Optional[str] = None


class OrgStatsResponse(BaseModel):
    user_count: int
    invitation_count: int
    repo_count: int
    scan_count: int
    finding_count: int
    max_users: Optional[int] = None
    max_repos: Optional[int] = None


@router.get("/organizations/current", response_model=OrgDetailResponse)
async def get_current_organization(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current user's active organization details."""
    if not current_user.organization_id:
        raise HTTPException(400, "No active organization set")
    org = await db.get(Organization, current_user.organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


@router.put("/organizations/current", response_model=OrgDetailResponse)
async def update_current_organization(
    body: OrgUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current organization name/settings. Admin only."""
    if current_user.role not in ("admin", "superadmin", "platform_admin", "org_admin"):
        raise HTTPException(403, "Only admins can update organization settings")
    if not current_user.organization_id:
        raise HTTPException(400, "No active organization set")

    org = await db.get(Organization, current_user.organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    if body.name is not None:
        org.name = body.name
    if body.admin_email is not None:
        org.admin_email = body.admin_email
    if body.subdomain is not None:
        org.subdomain = body.subdomain

    await db.commit()
    await db.refresh(org)
    return org


@router.get("/organizations/current/stats", response_model=OrgStatsResponse)
async def get_current_org_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get usage stats for the current organization (user count, scans, etc.)."""
    org_id = current_user.organization_id
    if not org_id:
        raise HTTPException(400, "No active organization set")

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.models.integration import Integration

    user_count = (await db.execute(
        select(sa_func.count(User.id)).where(User.organization_id == org_id)
    )).scalar() or 0

    invitation_count = (await db.execute(
        select(sa_func.count(UserInvitation.id)).where(
            UserInvitation.organization_id == org_id,
            UserInvitation.status == "pending",
        )
    )).scalar() or 0

    repo_count = (await db.execute(
        select(sa_func.count(Integration.id)).where(Integration.organization_id == org_id)
    )).scalar() or 0

    scan_count = (await db.execute(
        select(sa_func.count(Scan.id)).where(Scan.organization_id == org_id)
    )).scalar() or 0

    finding_count = (await db.execute(
        select(sa_func.count(Finding.id)).where(Finding.organization_id == org_id)
    )).scalar() or 0

    return OrgStatsResponse(
        user_count=user_count,
        invitation_count=invitation_count,
        repo_count=repo_count,
        scan_count=scan_count,
        finding_count=finding_count,
        max_users=getattr(org, "max_users", None),
        max_repos=getattr(org, "max_repos", None),
    )


@router.get("/organizations/current/members", response_model=list[MemberResponse])
async def get_current_org_members(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List all members of the current organization with roles."""
    if not current_user.organization_id:
        raise HTTPException(400, "No active organization set")
    result = await db.execute(
        select(User)
        .where(User.organization_id == current_user.organization_id)
        .order_by(User.created_at.desc())
    )
    return result.scalars().all()


# ─── Super-Admin: Suspend Organization ─────────────────────

@router.post("/organizations/{org_id}/suspend")
async def suspend_organization(
    org_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Suspend an organization. Super-admin only."""
    if current_user.role not in ("admin", "superadmin", "platform_admin"):
        raise HTTPException(403, "Only super-admins can suspend organizations")

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    ensure_tenant_access(current_user, org.tenant_id)
    if org.status == "suspended":
        return {"status": "already_suspended", "organization_id": org_id}

    org.status = "suspended"
    org.is_active = False
    await db.commit()
    return {"status": "suspended", "organization_id": org_id, "name": org.name}


@router.post("/organizations/{org_id}/reactivate")
async def reactivate_organization(
    org_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Reactivate a suspended organization. Super-admin only."""
    if current_user.role not in ("admin", "superadmin", "platform_admin"):
        raise HTTPException(403, "Only super-admins can reactivate organizations")

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    ensure_tenant_access(current_user, org.tenant_id)

    org.status = "active"
    org.is_active = True
    await db.commit()
    return {"status": "reactivated", "organization_id": org_id, "name": org.name}

"""
RBAC enforcement — permission-checking dependency for FastAPI endpoints.

Usage:
    @router.get("/scans")
    async def list_scans(
        user: User = Depends(require_permission("scans", "read")),
    ):
        ...
"""
from typing import Optional

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User
from app.models.rbac import UserRole, RolePermission, Permission, Role
from app.models.group import GroupMember, GroupRole


# Installation-level operators. Everyone else, including the self-registered tenant
# owner whose legacy role string is "platform_admin", is confined to their own tenant.
SUPERUSER_ROLES = ("admin", "superadmin")

# Role strings that can be written to User.role, lowest to highest privilege.
ROLE_RANK = {
    "viewer": 10,
    "auditor": 10,
    "user": 20,
    "member": 20,
    "developer": 20,
    "devops_engineer": 20,
    "security_analyst": 30,
    "security_engineer": 30,
    "security_lead": 40,
    "org_admin": 50,
    "tenant_admin": 60,
    "platform_admin": 60,
    "admin": 100,
    "superadmin": 100,
}


def is_superuser(user: User) -> bool:
    return user.role in SUPERUSER_ROLES


def ensure_tenant_access(user: User, tenant_id: Optional[int]) -> None:
    """Raise 404 unless the user is a superuser or the object belongs to their tenant.

    404 rather than 403 so tenant IDs cannot be enumerated.
    """
    if is_superuser(user):
        return
    if tenant_id is None or user.tenant_id is None or tenant_id != user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


def ensure_can_grant_role(actor: User, new_role: str, target_current_role: Optional[str] = None) -> None:
    """Validate a User.role change: known role, not above the actor, target not above the actor."""
    if new_role not in ROLE_RANK:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown role '{new_role}'. Allowed: {', '.join(sorted(ROLE_RANK))}",
        )
    actor_rank = ROLE_RANK.get(actor.role, 0)
    if ROLE_RANK[new_role] > actor_rank:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot grant a role above your own")
    if target_current_role and ROLE_RANK.get(target_current_role, 0) > actor_rank:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify a user with a higher role")


def ensure_can_invite_as(actor: User, role_slug: Optional[str]) -> None:
    """An invitation may not carry a built-in role above the inviter's own.

    Custom tenant roles (slugs outside ROLE_RANK) confer no installation-level
    privilege and are allowed.
    """
    if role_slug and role_slug in ROLE_RANK and ROLE_RANK[role_slug] > ROLE_RANK.get(actor.role, 0):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot invite a user with a role above your own")


# User.role strings that have no system Role of the same slug.
_ROLE_SLUG_ALIASES = {
    "user": "viewer",
    "member": "viewer",
    "developer": "devops_engineer",
    "security_analyst": "security_engineer",
    "security_lead": "security_engineer",
    "admin": "platform_admin",
    "superadmin": "platform_admin",
}


async def sync_user_role(db: AsyncSession, target: User, role: str, assigned_by: Optional[User] = None) -> None:
    """Set User.role and make the RBAC assignment match it.

    Permissions come from UserRole rows, so changing only the string would leave
    the old grants in place (or grant nothing on promotion).
    """
    from sqlalchemy import delete as sa_delete

    target.role = role
    await db.execute(sa_delete(UserRole).where(UserRole.user_id == target.id))
    slug = _ROLE_SLUG_ALIASES.get(role, role)
    role_row = (await db.execute(
        select(Role).where(Role.slug == slug, Role.is_system == True)  # noqa: E712
    )).scalars().first()
    if role_row:
        db.add(UserRole(
            user_id=target.id,
            role_id=role_row.id,
            tenant_id=target.tenant_id,
            organization_id=target.organization_id,
            assigned_by_id=assigned_by.id if assigned_by else None,
        ))


async def get_user_permissions(
    user_id: int,
    db: AsyncSession,
    tenant_id: Optional[int] = None,
    organization_id: Optional[int] = None,
) -> set[str]:
    """Collect effective permissions: direct roles ∪ group roles.

    Returns set of "resource:action" strings.
    """
    permissions: set[str] = set()

    # 1. Direct role assignments
    q = (
        select(Permission.resource, Permission.action)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    if tenant_id is not None:
        q = q.where(
            (UserRole.tenant_id == tenant_id) | (UserRole.tenant_id.is_(None))
        )
    result = await db.execute(q)
    for resource, action in result.all():
        permissions.add(f"{resource}:{action}")

    # 2. Group role assignments
    q2 = (
        select(Permission.resource, Permission.action)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(GroupRole, GroupRole.role_id == RolePermission.role_id)
        .join(GroupMember, GroupMember.group_id == GroupRole.group_id)
        .where(GroupMember.user_id == user_id)
    )
    result2 = await db.execute(q2)
    for resource, action in result2.all():
        permissions.add(f"{resource}:{action}")

    return permissions


async def ensure_permission(user: User, db: AsyncSession, resource: str, action: str) -> None:
    """Imperative form of require_permission, for use inside a handler."""
    if is_superuser(user):
        return
    perms = await get_user_permissions(
        user_id=user.id, db=db, tenant_id=user.tenant_id, organization_id=user.organization_id,
    )
    if f"{resource}:{action}" in perms or f"{resource}:manage" in perms or "*:*" in perms:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Permission denied: requires {resource}:{action}",
    )


def require_permission(resource: str, action: str):
    """FastAPI dependency that checks the current user has resource:action permission.

    Platform admins (legacy role='admin' with no tenant restrictions) bypass checks.
    """
    # Only create/read/update/delete/manage/export exist as permissions. Endpoints
    # written against "execute" or "write" could otherwise be passed by nobody
    # but admins.
    action = {"execute": "create", "write": "update"}.get(action, action)

    async def _check(
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        # Legacy admin bypass — platform-level admin always allowed
        if current_user.role in ("admin", "superadmin"):
            return current_user

        perms = await get_user_permissions(
            user_id=current_user.id,
            db=db,
            tenant_id=current_user.tenant_id,
            organization_id=current_user.organization_id,
        )

        # Check exact match or wildcard ("*:*" = super admin)
        if (
            f"{resource}:{action}" in perms
            or f"{resource}:manage" in perms
            or "*:*" in perms
        ):
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: requires {resource}:{action}",
        )

    return _check


def require_role(role_slug: str):
    """Dependency that checks user has a specific role (by slug)."""

    async def _check(
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        if current_user.role in ("admin", "superadmin"):
            return current_user

        q = (
            select(Role.slug)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == current_user.id)
            .where(Role.slug == role_slug)
        )
        result = await db.execute(q)
        if result.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: requires role '{role_slug}'",
            )
        return current_user

    return _check


def require_tenant_admin():
    """Shortcut: user must be tenant_admin or platform_admin."""
    return require_role("tenant_admin")


def require_platform_admin():
    """Shortcut: user must be platform_admin."""
    return require_role("platform_admin")

"""RBAC API — roles, permissions, user-role assignments."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from typing import List
import re

from app.core.database import get_db
from app.core.rbac import require_permission, ensure_tenant_access, is_superuser
from app.core.audit import write_audit_log
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.models.user import User
from app.schemas.enterprise import (
    PermissionResponse, RoleCreate, RoleUpdate, RoleResponse,
    RoleDetailResponse, UserRoleAssign,
)

router = APIRouter()


async def _get_role(db: AsyncSession, role_id: int, user) -> Role:
    """Load a role; custom roles of another tenant are reported as missing."""
    role = (await db.execute(select(Role).where(Role.id == role_id))).scalar_one_or_none()
    if not role:
        raise HTTPException(404, "Role not found")
    if not role.is_system:
        ensure_tenant_access(user, role.tenant_id)
    return role


@router.get("/permissions", response_model=List[PermissionResponse])
async def list_permissions(
    user=Depends(require_permission("roles", "read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Permission).order_by(Permission.resource, Permission.action))
    return result.scalars().all()


async def _resolve_permission_ids(db: AsyncSession, permission_ids, permissions) -> set[int]:
    """Permission IDs named either directly or as resource/action pairs."""
    ids = set(permission_ids or [])
    if ids:
        known = set((await db.execute(select(Permission.id).where(Permission.id.in_(ids)))).scalars().all())
        if ids - known:
            raise HTTPException(400, f"Unknown permission IDs: {sorted(ids - known)}")
    for ref in permissions or []:
        pid = (await db.execute(
            select(Permission.id).where(Permission.resource == ref.resource, Permission.action == ref.action)
        )).scalar_one_or_none()
        if pid is None:
            raise HTTPException(400, f"Unknown permission '{ref.resource}:{ref.action}'")
        ids.add(pid)
    return ids


@router.get("/", response_model=List[RoleDetailResponse])
async def list_roles(
    user=Depends(require_permission("roles", "read")),
    db: AsyncSession = Depends(get_db),
):
    q = select(Role).order_by(Role.is_system.desc(), Role.name)
    if not is_superuser(user):
        q = q.where((Role.tenant_id == user.tenant_id) | (Role.is_system == True))
    roles = (await db.execute(q)).scalars().all()

    perm_rows = (await db.execute(
        select(RolePermission.role_id, Permission)
        .join(Permission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id.in_([r.id for r in roles]))
    )).all() if roles else []
    perms_by_role: dict[int, list] = {}
    for role_id, perm in perm_rows:
        perms_by_role.setdefault(role_id, []).append(perm)

    return [
        {
            "id": r.id, "name": r.name, "slug": r.slug, "description": r.description,
            "is_system": r.is_system, "created_at": r.created_at,
            "permissions": perms_by_role.get(r.id, []),
        }
        for r in roles
    ]


@router.post("/", response_model=RoleResponse, status_code=201)
async def create_role(
    data: RoleCreate,
    request: Request,
    user=Depends(require_permission("roles", "create")),
    db: AsyncSession = Depends(get_db),
):
    if not data.name or not data.name.strip():
        raise HTTPException(status_code=400, detail="Role name cannot be empty")
    slug = data.slug or re.sub(r"[^a-z0-9_]", "_", data.name.lower())
    role = Role(
        name=data.name, slug=slug, description=data.description,
        tenant_id=user.tenant_id, is_system=False,
    )
    db.add(role)
    await db.flush()

    for pid in await _resolve_permission_ids(db, data.permission_ids, data.permissions):
        db.add(RolePermission(role_id=role.id, permission_id=pid))
    await write_audit_log(
        db, action="create", resource_type="role", resource_id=role.id,
        details={"name": data.name}, user=user, request=request,
    )
    await db.commit()
    await db.refresh(role)
    return role


@router.get("/{role_id}", response_model=RoleDetailResponse)
async def get_role(
    role_id: int,
    user=Depends(require_permission("roles", "read")),
    db: AsyncSession = Depends(get_db),
):
    role = await _get_role(db, role_id, user)

    perms_result = await db.execute(
        select(Permission)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role_id)
    )
    role_dict = {
        "id": role.id, "name": role.name, "slug": role.slug,
        "description": role.description, "is_system": role.is_system,
        "created_at": role.created_at,
        "permissions": perms_result.scalars().all(),
    }
    return role_dict


@router.put("/{role_id}", response_model=RoleResponse, include_in_schema=False)
@router.patch("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: int,
    data: RoleUpdate,
    user=Depends(require_permission("roles", "update")),
    db: AsyncSession = Depends(get_db),
):
    role = await _get_role(db, role_id, user)
    if role.is_system:
        raise HTTPException(400, "Cannot modify system roles")

    if data.name:
        role.name = data.name
    if data.description is not None:
        role.description = data.description
    if data.permission_ids is not None or data.permissions is not None:
        new_ids = await _resolve_permission_ids(db, data.permission_ids, data.permissions)
        await db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        for pid in new_ids:
            db.add(RolePermission(role_id=role_id, permission_id=pid))
    await db.commit()
    await db.refresh(role)
    return role


@router.delete("/{role_id}", status_code=204)
async def delete_role(
    role_id: int,
    request: Request,
    user=Depends(require_permission("roles", "delete")),
    db: AsyncSession = Depends(get_db),
):
    role = await _get_role(db, role_id, user)
    if role.is_system:
        raise HTTPException(400, "Cannot delete system roles")
    await write_audit_log(
        db, action="delete", resource_type="role", resource_id=role.id,
        details={"name": role.name}, user=user, request=request,
    )
    await db.delete(role)
    await db.commit()


# ─── User-Role Assignments ───────────────────────────────
@router.post("/assign", status_code=201)
async def assign_role(
    data: UserRoleAssign,
    user=Depends(require_permission("roles", "manage")),
    db: AsyncSession = Depends(get_db),
):
    # Target user and role must both be visible to the caller's tenant
    target = (await db.execute(select(User).where(User.id == data.user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "User not found")
    ensure_tenant_access(user, target.tenant_id)
    await _get_role(db, data.role_id, user)

    existing = await db.execute(
        select(UserRole).where(
            UserRole.user_id == data.user_id,
            UserRole.role_id == data.role_id,
            UserRole.tenant_id == user.tenant_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Role already assigned")

    ur = UserRole(
        user_id=data.user_id, role_id=data.role_id,
        tenant_id=user.tenant_id, organization_id=data.organization_id,
    )
    db.add(ur)
    await db.commit()
    return {"status": "assigned"}


@router.delete("/assign/{user_id}/{role_id}", status_code=204)
async def revoke_role(
    user_id: int,
    role_id: int,
    user=Depends(require_permission("roles", "manage")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
            UserRole.tenant_id == user.tenant_id,
        )
    )
    ur = result.scalar_one_or_none()
    if not ur:
        raise HTTPException(404, "Role assignment not found")
    await db.delete(ur)
    await db.commit()

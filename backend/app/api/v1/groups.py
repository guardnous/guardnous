"""Group management API — CRUD for logical user groupings with role inheritance."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from typing import List
import re

from app.core.database import get_db
from app.core.rbac import require_permission, ensure_tenant_access, is_superuser
from app.models.group import Group, GroupMember, GroupRole
from app.models.rbac import Role
from app.models.user import User
from app.schemas.enterprise import (
    GroupCreate, GroupUpdate, GroupResponse, GroupDetailResponse, GroupMemberAdd, GroupRoleAssign,
)

router = APIRouter()


async def _get_group(db: AsyncSession, group_id: int, user) -> Group:
    """Load a group, hiding groups that belong to another tenant."""
    group = (await db.execute(select(Group).where(Group.id == group_id))).scalar_one_or_none()
    if not group:
        raise HTTPException(404, "Group not found")
    ensure_tenant_access(user, group.tenant_id)
    return group


async def _ensure_user_in_tenant(db: AsyncSession, user_id: int, user) -> None:
    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    ensure_tenant_access(user, target.tenant_id)


async def _ensure_role_assignable(db: AsyncSession, role_id: int, user) -> None:
    role = await db.get(Role, role_id)
    if not role:
        raise HTTPException(404, "Role not found")
    if not role.is_system:
        ensure_tenant_access(user, role.tenant_id)


@router.get("/", response_model=List[GroupResponse])
async def list_groups(
    user=Depends(require_permission("groups", "read")),
    db: AsyncSession = Depends(get_db),
):
    q = select(Group).order_by(Group.name)
    if not is_superuser(user):
        q = q.where(Group.tenant_id == user.tenant_id)
    groups = (await db.execute(q)).scalars().all()
    ids = [g.id for g in groups]
    member_counts = dict((await db.execute(
        select(GroupMember.group_id, func.count(GroupMember.id))
        .where(GroupMember.group_id.in_(ids)).group_by(GroupMember.group_id)
    )).all()) if ids else {}
    role_counts = dict((await db.execute(
        select(GroupRole.group_id, func.count(GroupRole.id))
        .where(GroupRole.group_id.in_(ids)).group_by(GroupRole.group_id)
    )).all()) if ids else {}
    out = []
    for g in groups:
        item = GroupResponse.model_validate(g)
        item.member_count = member_counts.get(g.id, 0)
        item.role_count = role_counts.get(g.id, 0)
        out.append(item)
    return out


@router.get("/{group_id}", response_model=GroupDetailResponse)
async def get_group(
    group_id: int,
    user=Depends(require_permission("groups", "read")),
    db: AsyncSession = Depends(get_db),
):
    """Group with its members and assigned roles."""
    group = await _get_group(db, group_id, user)
    members = (await db.execute(
        select(User).join(GroupMember, GroupMember.user_id == User.id).where(GroupMember.group_id == group_id)
    )).scalars().all()
    roles = (await db.execute(
        select(Role).join(GroupRole, GroupRole.role_id == Role.id).where(GroupRole.group_id == group_id)
    )).scalars().all()
    # Built from the plain columns: validating the ORM object directly would
    # lazy-load Group.members, which is not possible on an async session.
    base = GroupResponse.model_validate(group).model_dump()
    base.update(member_count=len(members), role_count=len(roles))
    return GroupDetailResponse(
        **base,
        members=[{"id": u.id, "user_id": u.id, "email": u.email, "full_name": u.full_name} for u in members],
        roles=[{"id": r.id, "role_id": r.id, "name": r.name, "slug": r.slug} for r in roles],
    )


@router.post("/", response_model=GroupResponse, status_code=201)
async def create_group(
    data: GroupCreate,
    user=Depends(require_permission("groups", "create")),
    db: AsyncSession = Depends(get_db),
):
    slug = data.slug or re.sub(r"[^a-z0-9_-]", "-", data.name.lower())
    group = Group(
        name=data.name, slug=slug, description=data.description,
        tenant_id=user.tenant_id,
    )
    db.add(group)
    await db.commit()
    await db.refresh(group)
    return group


@router.patch("/{group_id}", response_model=GroupResponse)
async def update_group(
    group_id: int,
    data: GroupUpdate,
    user=Depends(require_permission("groups", "update")),
    db: AsyncSession = Depends(get_db),
):
    group = await _get_group(db, group_id, user)
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(group, field, value)
    await db.commit()
    await db.refresh(group)
    return group


@router.delete("/{group_id}", status_code=204)
async def delete_group(
    group_id: int,
    user=Depends(require_permission("groups", "delete")),
    db: AsyncSession = Depends(get_db),
):
    group = await _get_group(db, group_id, user)
    await db.delete(group)
    await db.commit()


# ─── Group Members ────────────────────────────────────────
@router.get("/{group_id}/members")
async def list_members(
    group_id: int,
    user=Depends(require_permission("groups", "read")),
    db: AsyncSession = Depends(get_db),
):
    await _get_group(db, group_id, user)
    result = await db.execute(
        select(User)
        .join(GroupMember, GroupMember.user_id == User.id)
        .where(GroupMember.group_id == group_id)
    )
    users = result.scalars().all()
    return [{"id": u.id, "email": u.email, "full_name": u.full_name} for u in users]


@router.post("/{group_id}/members", status_code=201)
async def add_member(
    group_id: int,
    data: GroupMemberAdd,
    user=Depends(require_permission("groups", "update")),
    db: AsyncSession = Depends(get_db),
):
    await _get_group(db, group_id, user)
    await _ensure_user_in_tenant(db, data.user_id, user)
    existing = await db.execute(
        select(GroupMember).where(
            GroupMember.group_id == group_id,
            GroupMember.user_id == data.user_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "User already in group")
    db.add(GroupMember(group_id=group_id, user_id=data.user_id, added_by_id=user.id))
    await db.commit()
    return {"status": "added"}


@router.delete("/{group_id}/members/{user_id}", status_code=204)
async def remove_member(
    group_id: int,
    user_id: int,
    user=Depends(require_permission("groups", "update")),
    db: AsyncSession = Depends(get_db),
):
    await _get_group(db, group_id, user)
    result = await db.execute(
        select(GroupMember).where(
            GroupMember.group_id == group_id,
            GroupMember.user_id == user_id,
        )
    )
    gm = result.scalar_one_or_none()
    if not gm:
        raise HTTPException(404, "Member not found in group")
    await db.delete(gm)
    await db.commit()


# ─── Group Roles ──────────────────────────────────────────
@router.post("/{group_id}/roles", status_code=201)
async def assign_group_role(
    group_id: int,
    data: GroupRoleAssign,
    user=Depends(require_permission("groups", "manage")),
    db: AsyncSession = Depends(get_db),
):
    await _get_group(db, group_id, user)
    await _ensure_role_assignable(db, data.role_id, user)
    existing = await db.execute(
        select(GroupRole).where(
            GroupRole.group_id == group_id,
            GroupRole.role_id == data.role_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Role already assigned to group")
    db.add(GroupRole(group_id=group_id, role_id=data.role_id))
    await db.commit()
    return {"status": "role assigned to group"}


@router.delete("/{group_id}/roles/{role_id}", status_code=204)
async def revoke_group_role(
    group_id: int,
    role_id: int,
    user=Depends(require_permission("groups", "manage")),
    db: AsyncSession = Depends(get_db),
):
    await _get_group(db, group_id, user)
    result = await db.execute(
        select(GroupRole).where(
            GroupRole.group_id == group_id,
            GroupRole.role_id == role_id,
        )
    )
    gr = result.scalar_one_or_none()
    if not gr:
        raise HTTPException(404, "Group role assignment not found")
    await db.delete(gr)
    await db.commit()

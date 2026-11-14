"""
Multi-tenant data isolation utilities.

Provides query helpers that enforce organization-level data scoping
across all database operations, plus plan-limit enforcement.
"""
from __future__ import annotations

from typing import Optional, Type, TypeVar

from fastapi import HTTPException
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import Base

T = TypeVar("T", bound=Base)


def org_scoped_query(
    query: Select,
    model: Type[T],
    org_id: int,
) -> Select:
    """Add ``organization_id == org_id`` filter to an existing SELECT.

    Usage::

        stmt = select(Finding)
        stmt = org_scoped_query(stmt, Finding, ctx.organization_id)
        results = await db.execute(stmt)
    """
    return query.filter(model.organization_id == org_id)  # type: ignore[attr-defined]


def org_scoped_select(
    model: Type[T],
    org_id: int,
) -> Select:
    """Return a new ``select(model)`` already filtered by organization.

    Usage::

        stmt = org_scoped_select(Finding, ctx.organization_id)
        results = await db.execute(stmt)
    """
    return select(model).filter(model.organization_id == org_id)  # type: ignore[attr-defined]


async def get_org_entity(
    db: AsyncSession,
    model: Type[T],
    entity_id: int,
    org_id: int,
) -> Optional[T]:
    """Fetch a single entity by PK, enforcing org isolation.

    Returns ``None`` if not found *or* if it belongs to a different org.
    """
    stmt = (
        select(model)
        .filter(
            model.id == entity_id,  # type: ignore[attr-defined]
            model.organization_id == org_id,  # type: ignore[attr-defined]
        )
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def count_org_entities(
    db: AsyncSession,
    model: Type[T],
    org_id: int,
) -> int:
    """Count all entities of *model* belonging to *org_id*."""

    stmt = (
        select(func.count())
        .select_from(model)
        .filter(model.organization_id == org_id)  # type: ignore[attr-defined]
    )
    result = await db.execute(stmt)
    return result.scalar_one()


async def check_plan_limit(
    db: AsyncSession,
    org_id: int,
    resource_model: Type[T],
    limit_field: str,
) -> None:
    """Raise ``HTTPException(403)`` if the org has reached its plan limit.

    *limit_field* is the attribute name on :class:`Organization` that holds the
    cap (e.g. ``"max_users"``, ``"max_repos"``).

    The current count is derived from *resource_model* rows whose
    ``organization_id == org_id``.
    """
    from app.models.organization import Organization

    org_result = await db.execute(
        select(Organization).filter(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    limit = getattr(org, limit_field, None)
    if limit is None:
        return  # no cap configured

    current_count = await count_org_entities(db, resource_model, org_id)
    if current_count >= limit:
        raise HTTPException(
            status_code=403,
            detail=f"Plan limit reached: {limit_field.replace('max_', '')} "
                   f"({current_count}/{limit}). Upgrade your plan to add more.",
        )

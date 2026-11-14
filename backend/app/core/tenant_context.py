"""
Tenant context — extracts and validates tenant from the current request.

Provides dependencies that inject TenantContext into endpoints.
"""
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User
from app.models.tenant import Tenant


@dataclass
class TenantContext:
    """Immutable tenant context for the current request."""
    tenant_id: int
    tenant_slug: str
    organization_id: Optional[int]
    user_id: int
    is_platform_admin: bool


async def get_tenant_context(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> TenantContext:
    """Extract tenant context from the authenticated user.

    Platform admins can override tenant via X-Tenant-Id header.
    """
    is_platform_admin = current_user.role == "admin"

    # Allow platform admins to switch tenant context via header
    header_tenant_id = request.headers.get("X-Tenant-Id")
    if header_tenant_id and is_platform_admin:
        tenant_id = int(header_tenant_id)
        result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
        tenant = result.scalar_one_or_none()
        if not tenant:
            raise HTTPException(status_code=404, detail="Organization not found")
    elif current_user.tenant_id:
        tenant_id = current_user.tenant_id
        result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
        tenant = result.scalar_one_or_none()
        if not tenant:
            raise HTTPException(status_code=404, detail="User's organization not found")
    else:
        # Legacy user without tenant — create a context with org as tenant stand-in
        return TenantContext(
            tenant_id=0,
            tenant_slug="default",
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            is_platform_admin=is_platform_admin,
        )

    return TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        is_platform_admin=is_platform_admin,
    )

"""Audit log API — immutable action log for compliance."""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.audit_log import AuditLog
from app.schemas.enterprise import AuditLogResponse

router = APIRouter()


@router.get("/logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    resource_type: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user=Depends(require_permission("audit_logs", "read")),
    db: AsyncSession = Depends(get_db),
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc())

    if user.role != "admin" and user.tenant_id:
        q = q.where(AuditLog.tenant_id == user.tenant_id)
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    if action:
        q = q.where(AuditLog.action == action)
    if user_id:
        q = q.where(AuditLog.user_id == user_id)

    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()

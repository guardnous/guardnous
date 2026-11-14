"""API for agent audit trail — read-only access to tool call history and decisions."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.agent_audit import AgentAuditEntry

router = APIRouter(prefix="/agent-audit", tags=["agent-audit"])


class AuditEntryOut(BaseModel):
    id: int
    conversation_id: int | None = None
    turn_index: int | None = None
    entry_type: str
    agent_id: str | None = None
    tool_name: str | None = None
    tool_result_preview: str | None = None
    reasoning: str | None = None
    guardrail_flags: list | None = None
    duration_ms: int | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


async def _may_read_everyones(db: AsyncSession, user) -> bool:
    """Reading other people's agent activity is an audit right. Everyone else sees only their own."""
    from app.services.agents.runtime import has_permission, user_permissions

    return has_permission(await user_permissions(db, user), "audit_logs", "read")


@router.get("/conversation/{conversation_id}", response_model=list[AuditEntryOut])
async def get_conversation_audit(
    conversation_id: int,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = (
        select(AgentAuditEntry)
        .where(
            AgentAuditEntry.organization_id == user.organization_id,
            AgentAuditEntry.conversation_id == conversation_id,
        )
        .order_by(AgentAuditEntry.created_at.asc())
    )
    if not await _may_read_everyones(db, user):
        stmt = stmt.where(AgentAuditEntry.user_id == user.id)
    rows = (await db.execute(stmt)).scalars().all()
    return rows


@router.get("/recent", response_model=list[AuditEntryOut])
async def recent_audit(
    limit: int = Query(50, le=200),
    entry_type: str | None = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = (
        select(AgentAuditEntry)
        .where(AgentAuditEntry.organization_id == user.organization_id)
    )
    if not await _may_read_everyones(db, user):
        stmt = stmt.where(AgentAuditEntry.user_id == user.id)
    if entry_type:
        stmt = stmt.where(AgentAuditEntry.entry_type == entry_type)
    stmt = stmt.order_by(AgentAuditEntry.created_at.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return rows

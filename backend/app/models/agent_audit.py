"""Persistent audit trail for agent tool calls and decisions."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text, JSON, ForeignKey
from app.core.database import Base


class AgentAuditEntry(Base):
    __tablename__ = "agent_audit_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    conversation_id = Column(Integer, ForeignKey("agent_conversations.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    turn_index = Column(Integer, nullable=True)
    entry_type = Column(String(50), nullable=False, default="tool_call")  # tool_call, decision, delegation, guardrail
    agent_id = Column(String(100), nullable=True)
    tool_name = Column(String(100), nullable=True)
    tool_args_hash = Column(String(32), nullable=True)
    tool_result_preview = Column(Text, nullable=True)
    reasoning = Column(Text, nullable=True)
    guardrail_flags = Column(JSON, nullable=True, default=list)
    token_estimate = Column(Integer, nullable=True, default=0)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

"""Organization Knowledge Base — custom runbooks, playbooks, and infrastructure knowledge.

Organizations can upload their own knowledge (runbooks, infrastructure docs, custom playbooks,
known-issue patterns) that gets injected into the agent context for org-specific triage.
"""
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Index,
)
from sqlalchemy.sql import func
from app.core.database import Base


class KnowledgeEntry(Base):
    """A single knowledge base entry — runbook, playbook, pattern, or doc."""

    __tablename__ = "knowledge_entries"
    __table_args__ = (
        Index("ix_knowledge_org_category", "organization_id", "category"),
        Index("ix_knowledge_org_active", "organization_id", "is_active"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=False)
    category = Column(String(100), nullable=False, default="general")
    entry_type = Column(String(50), nullable=False, default="runbook")
    tags = Column(String(1000), default="")
    priority = Column(Integer, default=0)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(String(255), default="system")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Valid categories
    CATEGORIES = [
        "runbook", "playbook", "infrastructure", "known_issue",
        "escalation", "compliance", "architecture", "custom_rule",
    ]

    # Valid entry types
    ENTRY_TYPES = [
        "runbook", "playbook", "pattern", "document", "sop", "checklist",
    ]

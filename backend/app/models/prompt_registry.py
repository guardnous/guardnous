"""Prompt Registry model — versioned, DB-backed prompt management."""
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Text, Boolean, Index
from sqlalchemy.sql import func
from app.core.database import Base


class PromptTemplate(Base):
    """A versioned prompt template stored in the database."""
    __tablename__ = "prompt_templates"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    slug = Column(String(200), nullable=False)  # e.g. "triage_system", "router_classify", "remediation_explain"
    version = Column(Integer, nullable=False, default=1)
    content = Column(Text, nullable=False)  # the actual prompt text with {variable} placeholders
    description = Column(String(500))
    variables = Column(JSON, default=list)  # list of expected variable names
    is_active = Column(Boolean, default=True)  # only one active version per slug per org
    tags = Column(JSON, default=list)  # categorization: ["agent", "triage", "security"]
    metrics = Column(JSON, default=dict)  # usage stats: {"calls": 0, "avg_tokens": 0, "avg_latency_ms": 0}
    created_by = Column(String(200))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_prompt_org_slug_version", "organization_id", "slug", "version", unique=True),
        Index("ix_prompt_org_slug_active", "organization_id", "slug", "is_active"),
    )

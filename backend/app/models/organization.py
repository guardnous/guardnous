import secrets

from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Organization(Base):
    """Organization — acts as Business Unit within a Tenant.

    Hierarchy: Tenant → Organization (BU) → Scans/Findings/Integrations
    """
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    subdomain = Column(String(255), unique=True, index=True)
    admin_email = Column(String(255))
    plan = Column(String(50), default="free")
    status = Column(String(50), default="active")
    features = Column(JSON, default=list)

    # Legacy VCS fields — kept for backward compat; use integrations table
    vcs_type = Column(String(50))
    vcs_token_encrypted = Column(Text)
    vcs_refresh_token_encrypted = Column(Text)
    vcs_username = Column(String(255))
    vcs_repositories = Column(JSON, default=list)
    # Generated for every new org; webhooks are rejected when this is empty
    webhook_secret = Column(String(255), default=lambda: secrets.token_hex(32))
    schema_name = Column(String(255))

    plan_tier = Column(String(30), default="free")  # free, pro, enterprise
    max_users = Column(Integer, default=50)
    max_repos = Column(Integer, default=100)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="organizations")
    users = relationship("User", back_populates="organization")
    member_associations = relationship("UserOrganization", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")
    findings = relationship("Finding", back_populates="organization")
    reports = relationship("Report", back_populates="organization")
    onboarding_tokens = relationship("OnboardingToken", back_populates="organization")
    integrations = relationship("Integration", back_populates="organization")
    notifications = relationship("Notification", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")

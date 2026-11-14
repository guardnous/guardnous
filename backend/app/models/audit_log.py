"""
Audit log — immutable record of all significant actions.
"""
from sqlalchemy import Column, Index, Integer, String, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_org_action", "organization_id", "action"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)  # e.g. user.created, scan.started
    resource_type = Column(String(100), nullable=True, index=True)  # users, scans, roles, ...
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, default=dict)  # before/after snapshot
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    organization = relationship("Organization", back_populates="audit_logs")

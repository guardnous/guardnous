"""
User invitation model — supports email invites and bulk import tracking.
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class UserInvitation(Base):
    """Tracks pending user invitations and bulk import records."""
    __tablename__ = "user_invitations"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)
    role_slug = Column(String(100), default="viewer")
    token = Column(String(255), unique=True, nullable=False, index=True)
    status = Column(String(50), default="pending")  # pending, accepted, expired, revoked
    source = Column(String(50), default="manual")  # manual, csv_import, excel_import
    metadata_ = Column("metadata", JSON, default=dict)  # bulk import row info
    invited_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    accepted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    invited_by = relationship("User", foreign_keys=[invited_by_id])

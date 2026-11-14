"""
In-app notification model — stores user-facing notifications for the bell icon.
"""
from sqlalchemy import Column, Index, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_org_user", "organization_id", "user_id"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=True)
    category = Column(String(50), nullable=False, default="info")  # info, success, warning, error
    is_read = Column(Boolean, default=False, index=True)
    link = Column(String(500), nullable=True)  # optional deep-link path e.g. /scans/5
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    organization = relationship("Organization", back_populates="notifications")

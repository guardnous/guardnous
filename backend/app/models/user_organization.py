"""UserOrganization — many-to-many junction between User and Organization.

A user belongs to a Tenant and can be assigned to multiple Organizations (BUs)
within that tenant. The user's `organization_id` on the User table represents
their *active/default* org for data scoping. This junction table tracks all
memberships.
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class UserOrganization(Base):
    __tablename__ = "user_organizations"
    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_user_org_membership"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    role_in_org = Column(String(50), default="member")  # member, admin, viewer
    added_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    joined_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", foreign_keys=[user_id], back_populates="org_memberships")
    organization = relationship("Organization", back_populates="member_associations")
    added_by_user = relationship("User", foreign_keys=[added_by])

"""
Group models — logical user grouping within a tenant (SRE, Security, etc.).
Groups inherit roles via union model: a user's effective permissions =
  direct_roles ∪ group_roles.
"""
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, ForeignKey, UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Group(Base):
    """Logical user group scoped to a tenant."""
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("tenant_id", "slug", name="uq_group_tenant_slug"),
    )

    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")
    group_roles = relationship("GroupRole", back_populates="group", cascade="all, delete-orphan")


class GroupMember(Base):
    """M2M: User ↔ Group."""
    __tablename__ = "group_members"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    added_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="uq_group_member"),
    )

    group = relationship("Group", back_populates="members")
    user = relationship("User", back_populates="group_memberships", foreign_keys=[user_id])
    added_by = relationship("User", foreign_keys=[added_by_id])


class GroupRole(Base):
    """M2M: Group ↔ Role — all group members inherit these roles."""
    __tablename__ = "group_roles"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("group_id", "role_id", name="uq_group_role"),
    )

    group = relationship("Group", back_populates="group_roles")
    role = relationship("Role")

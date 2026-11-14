"""
RBAC models — Roles, Permissions, and scoped assignments.

Permission model: resource × action (e.g., scans:create, findings:read).
Roles aggregate permissions. UserRole scopes a role to tenant + optional org (BU).
"""
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, ForeignKey, UniqueConstraint, JSON,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Permission(Base):
    """Atomic permission: resource + action."""
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    resource = Column(String(100), nullable=False, index=True)
    action = Column(String(50), nullable=False)
    description = Column(String(500))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_permission_resource_action"),
    )

    role_permissions = relationship("RolePermission", back_populates="permission")


class Role(Base):
    """Role definition — system (predefined) or custom (per-tenant)."""
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    name = Column(String(100), nullable=False)
    slug = Column(String(100), nullable=False, index=True)
    description = Column(Text)
    is_system = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    allowed_agents = Column(JSON, nullable=True, default=list)  # e.g. ["security_analyst", "compliance_advisor"]
    allowed_tools = Column(JSON, nullable=True, default=list)   # e.g. ["list_findings", "get_scan_results"]
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    role_permissions = relationship(
        "RolePermission", back_populates="role", cascade="all, delete-orphan",
    )
    user_roles = relationship("UserRole", back_populates="role")


class RolePermission(Base):
    """M2M: which permissions a role grants."""
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )

    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")


class UserRole(Base):
    """Scoped role assignment: user has role X within tenant Y / org Z."""
    __tablename__ = "user_roles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())
    assigned_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "user_id", "role_id", "tenant_id", "organization_id",
            name="uq_user_role_scope",
        ),
    )

    user = relationship("User", back_populates="user_roles", foreign_keys=[user_id])
    role = relationship("Role", back_populates="user_roles")
    assigned_by = relationship("User", foreign_keys=[assigned_by_id])

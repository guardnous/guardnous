from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", "tenant_id", name="uq_user_email_per_tenant"),
    )

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), default="viewer")  # legacy — kept for backward compat
    is_active = Column(Boolean, default=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    status = Column(String(50), default="active")  # invited, active, deactivated
    invited_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Two-Factor Authentication (TOTP)
    totp_secret = Column(String(64), nullable=True)  # base32-encoded TOTP secret
    totp_enabled = Column(Boolean, default=False)     # user opted in (or admin enforced)
    totp_confirmed = Column(Boolean, default=False)   # first code verified after setup
    backup_codes = Column(Text, nullable=True)        # JSON array of hashed one-time codes

    # Email verification
    email_verified = Column(Boolean, default=False)    # set True after click-through verification

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    organization = relationship("Organization", back_populates="users")
    tenant = relationship("Tenant", back_populates="users")
    invited_by = relationship("User", remote_side="User.id", foreign_keys=[invited_by_id])
    user_roles = relationship("UserRole", back_populates="user", foreign_keys="UserRole.user_id")
    group_memberships = relationship("GroupMember", back_populates="user", foreign_keys="GroupMember.user_id")
    org_memberships = relationship("UserOrganization", back_populates="user", foreign_keys="UserOrganization.user_id")

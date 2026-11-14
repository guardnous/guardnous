"""
Tenant model — top-level multi-tenant entity.

Hierarchy: Platform → Tenant → Organization (acts as Business Unit) → Scans/Findings/etc.
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Tenant(Base):
    """Top-level customer account (e.g., SAP, Microsoft)."""
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    domain = Column(String(255), unique=True, nullable=True, index=True)
    logo_url = Column(String(500), nullable=True)
    plan = Column(String(50), default="free")  # free, professional, enterprise
    status = Column(String(50), default="active")  # pending, active, trial, suspended, deactivated
    settings = Column(JSON, default=dict)
    max_users = Column(Integer, default=25)
    max_organizations = Column(Integer, default=10)  # business units
    max_scans_per_month = Column(Integer, default=500)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    organizations = relationship("Organization", back_populates="tenant")
    users = relationship("User", back_populates="tenant")

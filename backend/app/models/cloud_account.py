"""Cloud Account model — stores provider credentials for resource discovery."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, JSON,
    ForeignKey,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class CloudAccount(Base):
    """A connected cloud account (AWS, Azure, GCP) for resource discovery.

    Credentials are encrypted at rest using Fernet (same pattern as Integration).
    Only read-only credentials should ever be stored.
    """
    __tablename__ = "cloud_accounts"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Provider identity
    provider = Column(String(20), nullable=False, index=True)  # aws, azure, gcp
    name = Column(String(255), nullable=False)                 # human label: "Production AWS"
    account_identifier = Column(String(255), nullable=False)   # AWS account ID, Azure subscription ID, GCP project ID

    # Encrypted credentials (Fernet)
    credentials_encrypted = Column(Text, nullable=True)
    # JSON schema of what's stored (for UI guidance), e.g.:
    # AWS:   {"role_arn": "...", "external_id": "..."}
    # Azure: {"tenant_id": "...", "client_id": "...", "client_secret": "..."}
    # GCP:   {"service_account_json": "..."}

    # Connection state
    status = Column(String(30), default="pending")  # pending, connected, error, disabled
    last_error = Column(Text, nullable=True)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    resources_count = Column(Integer, default=0)

    # Sync configuration
    sync_enabled = Column(Boolean, default=True)
    sync_interval_hours = Column(Integer, default=6)  # how often to auto-discover
    resource_types_filter = Column(JSON, default=list)  # empty = discover all

    # Metadata
    regions = Column(JSON, default=list)  # which regions to scan; empty = all
    tags = Column(JSON, default=dict)     # arbitrary metadata

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    organization = relationship("Organization", backref="cloud_accounts")

from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    vcs_type = Column(String(50), nullable=False)  # github, gitlab, azure
    access_token_encrypted = Column(Text)  # encrypted OAuth access token
    refresh_token_encrypted = Column(Text)  # encrypted refresh token
    token_expires_at = Column(DateTime(timezone=True))

    # Authentication method and provider base URL
    auth_method = Column(String(50), default="oauth")  # oauth, pat, app_password, github_app
    base_url = Column(String(500), nullable=True)  # e.g. https://gitlab.example.com/api/v4

    # GitHub App installation ID (enterprise flow)
    installation_id = Column(Integer, nullable=True)

    # VCS account info
    account_name = Column(String(255))  # GitHub username or org name
    account_url = Column(String(500))  # e.g. https://github.com/org
    avatar_url = Column(String(500))

    # Repository configuration
    repositories = Column(JSON, default=list)  # [{"full_name": "org/repo", "enabled": true, ...}]
    removed_repos = Column(JSON, default=list)  # ["org/repo", ...] hidden from the live-fetched repo list
    webhook_id = Column(String(255))  # webhook ID from VCS provider

    # Scan settings
    scan_on_push = Column(Boolean, default=True)
    scan_on_pr = Column(Boolean, default=True)
    auto_fix_prs = Column(Boolean, default=False)
    scan_frequency = Column(String(50), default="on_push")  # on_push, daily, weekly, manual

    is_active = Column(Boolean, default=True)

    # CI/CD API Key (hashed — raw key shown only once at creation)
    api_key_hash = Column(String, nullable=True, index=True)
    api_key_prefix = Column(String(12), nullable=True)
    api_key_name = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    organization = relationship("Organization", back_populates="integrations")

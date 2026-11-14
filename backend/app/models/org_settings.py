"""Organization-level settings: general prefs + notification prefs."""
from sqlalchemy import Column, Integer, String, Boolean, JSON, ForeignKey, DateTime
from sqlalchemy.sql import func
from app.core.database import Base


class OrgSettings(Base):
    __tablename__ = "org_settings"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), unique=True, nullable=False, index=True)

    # General
    platform_name = Column(String(255), default="GuardNous")
    timezone = Column(String(100), default="UTC")
    date_format = Column(String(50), default="YYYY-MM-DD")
    session_timeout = Column(Integer, default=30)  # minutes
    dark_mode_default = Column(String(20), default="system")  # system | light | dark
    language = Column(String(20), default="en")
    data_retention_days = Column(Integer, default=90)
    enforce_2fa = Column(Boolean, default=False)
    auto_remediation = Column(Boolean, default=False)
    risk_threshold = Column(String(20), default="high")  # critical | high | medium | low
    scan_concurrency = Column(Integer, default=3)
    log_level = Column(String(20), default="INFO")  # DEBUG, VERBOSE, INFO, WARNING, ERROR, CRITICAL

    # SMTP configuration
    smtp_enabled = Column(Boolean, default=False)
    smtp_host = Column(String(255), default="")
    smtp_port = Column(Integer, default=587)
    smtp_user = Column(String(255), default="")
    smtp_password_encrypted = Column(String(1024), default="")  # Fernet-encrypted
    smtp_from_email = Column(String(255), default="")
    smtp_from_name = Column(String(255), default="GuardNous")
    smtp_use_tls = Column(Boolean, default=True)

    # Notification prefs (JSON blob for flexibility)
    notification_prefs = Column(JSON, default=dict)

    # Plugin enabled-state persistence: {plugin_slug: bool}
    plugin_settings = Column(JSON, default=dict)

    # First-login setup wizard completed flag
    setup_completed = Column(Boolean, default=False, nullable=False, server_default="false")

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

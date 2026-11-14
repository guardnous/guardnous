from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.sql import func
from app.core.database import Base


class ServiceAccount(Base):
    """A non-human bot identity used to author automated remediation pull requests.

    The service account carries a hashed API token (shown once at creation) plus the
    git author name/email that remediation commits are attributed to. This lets the
    platform open auto-fix PRs "from our end" with a consistent, auditable bot identity
    instead of a human user's personal token.
    """

    __tablename__ = "service_accounts"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    name = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)

    # Git identity used for commit/PR attribution
    bot_username = Column(String(120), nullable=False, default="guardnous-bot")
    bot_email = Column(String(255), nullable=False, default="bot@guardnous.local")

    # Hashed access token (sha256 of the raw `gn_` token). Raw token shown once only.
    token_hash = Column(String(128), nullable=True, index=True)
    token_prefix = Column(String(16), nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

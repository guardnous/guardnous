from sqlalchemy import Column, DateTime, Integer, JSON, String, Text
from sqlalchemy.sql import func

from app.core.database import Base


class OidcSigningKey(Base):
    """Key GuardNous signs its identity tokens with. The private half is stored encrypted."""

    __tablename__ = "oidc_signing_keys"

    id = Column(Integer, primary_key=True)
    kid = Column(String(64), nullable=False, unique=True)
    public_jwk = Column(JSON, nullable=False)
    private_pem_encrypted = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

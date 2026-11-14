from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base


class LLMConfig(Base):
    """Per-organization "bring your own model" configuration."""

    __tablename__ = "llm_configs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True)
    provider = Column(String(30), nullable=False, default="mock")  # mock|openai|azure|anthropic|ollama
    model = Column(String(160))
    base_url = Column(String(500))
    api_version = Column(String(40))
    api_key_encrypted = Column(Text)
    temperature = Column(Float, default=0.2)
    max_tokens = Column(Integer, default=1200)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

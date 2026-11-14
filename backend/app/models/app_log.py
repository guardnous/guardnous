"""Application log — structured, queryable log entries persisted to DB."""
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, Index
from sqlalchemy.sql import func
from app.core.database import Base


class AppLog(Base):
    __tablename__ = "app_logs"

    id = Column(Integer, primary_key=True, index=True)
    level = Column(String(20), nullable=False, index=True)          # DEBUG, INFO, WARNING, ERROR, CRITICAL
    category = Column(String(50), nullable=False, index=True)       # AUTH, SCAN, REPORT, INTEGRATION, ...
    message = Column(Text, nullable=False)
    source = Column(String(200), nullable=True)                     # module/function origin
    user_id = Column(Integer, nullable=True, index=True)
    user_email = Column(String(255), nullable=True)
    organization_id = Column(Integer, nullable=True, index=True)
    request_method = Column(String(10), nullable=True)              # GET, POST, PUT, DELETE
    request_path = Column(String(500), nullable=True)
    request_ip = Column(String(45), nullable=True)
    status_code = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)              # extra structured data
    traceback = Column(Text, nullable=True)                         # stack trace for errors
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    __table_args__ = (
        Index("ix_app_logs_level_created", "level", "created_at"),
        Index("ix_app_logs_category_created", "category", "created_at"),
    )

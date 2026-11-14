"""Scheduled scan configurations for automated recurring scans."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, JSON, ForeignKey
from app.core.database import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    scan_type = Column(String(50), nullable=False, default="full")  # full, iac, cloud, container, secret
    cron_expression = Column(String(100), nullable=False, default="0 2 * * *")  # daily at 2am
    config_json = Column(JSON, nullable=True, default=dict)  # additional scan params
    enabled = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(30), nullable=True)   # queued | failed
    last_error = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

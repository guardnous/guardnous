"""Report schedule model — cron-driven recurring report generation + email delivery."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Text
from app.core.database import Base


class ReportSchedule(Base):
    __tablename__ = "report_schedules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    report_type = Column(String(50), nullable=False, default="security_posture")
    format = Column(String(10), nullable=False, default="pdf")
    cron_expression = Column(String(100), nullable=False, default="0 8 * * 1")  # Weekly Mon 8am
    recipients = Column(JSON, nullable=False, default=list)  # ["email@example.com", ...]
    scan_ids = Column(JSON, nullable=True, default=list)  # Filter to specific scans (empty = all)
    enabled = Column(Boolean, nullable=False, default=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(30), nullable=True)   # sent | generated | failed
    last_error = Column(Text, nullable=True)
    last_report_id = Column(Integer, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

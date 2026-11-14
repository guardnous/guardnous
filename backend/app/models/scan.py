from sqlalchemy import Column, Index, Integer, String, DateTime, JSON, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(200), nullable=False)  # terraform, cloudformation, bicep, kubernetes, dockerfile, ansible, helm, secrets, full
    status = Column(String(50), default="pending")  # pending, running, completed, failed, cancelled, timed_out
    source = Column(Text)  # file content or repo URL
    file_name = Column(String(500))
    cloud_provider = Column(String(50))  # aws, gcp, azure, multi
    risk_score = Column(Integer)  # 0-100
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    metadata_ = Column("metadata", JSON, default=dict)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Job tracking fields — 14-stage enterprise pipeline
    stage = Column(String(50), default="queued")
    progress = Column(Integer, default=0)  # 0-100
    repository_url = Column(String(1000))
    repository_name = Column(String(500))
    account_name = Column(String(255))
    error_message = Column(Text)
    files_scanned = Column(Integer, default=0)
    files_total = Column(Integer, default=0)
    # Link to auto-generated report
    report_id = Column(Integer, ForeignKey("reports.id", ondelete="SET NULL"), nullable=True)

    # Enterprise stage columns
    secrets_found = Column(Integer, default=0)
    dependencies_analyzed = Column(Integer, default=0)
    policies_evaluated = Column(Integer, default=0)
    policies_passed = Column(Integer, default=0)
    policies_failed = Column(Integer, default=0)
    compliance_frameworks = Column(JSON, default=dict)
    notifications_sent = Column(Boolean, default=False)
    stage_details = Column(JSON, default=dict)  # per-stage timing/metadata
    cancelled_by = Column(String(255), nullable=True)
    timeout_seconds = Column(Integer, default=3600)

    # Scheduled/recurring scan support
    scheduled = Column(Boolean, default=False, index=True)
    integration_id = Column(Integer, nullable=True)
    repository = Column(String(500), nullable=True, index=True)

    __table_args__ = (
        Index('ix_scans_org_status', 'organization_id', 'status'),
        Index('ix_scans_org_created', 'organization_id', 'created_at'),
    )

    organization = relationship("Organization", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    report = relationship("Report", foreign_keys=[report_id])

from sqlalchemy import Column, Index, Integer, String, DateTime, JSON, ForeignKey, Text, Boolean, event, select
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(100), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Column(String(100), index=True)  # iac, secrets, cve
    cloud_provider = Column(String(50), index=True)  # aws, gcp, azure
    resource_type = Column(String(200))
    resource_name = Column(String(500))
    file_path = Column(String(500))
    line_number = Column(Integer)
    code_snippet = Column(Text)
    remediation = Column(Text)
    cve_id = Column(String(50), index=True)
    is_fixed = Column(Boolean, default=False)
    is_ignored = Column(Boolean, default=False)
    detected_by = Column(String(100), nullable=True, index=True)  # checkov, trivy, semgrep, gitleaks, tfsec, etc.
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # ── Triage workflow fields ──
    status = Column(
        String(30), default="open", index=True,
    )  # open, triaged, in_progress, resolved, false_positive
    assigned_to = Column(String(255), nullable=True, index=True)
    notes = Column(JSON, default=list)  # [{author, text, created_at}, ...]
    false_positive_reason = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=True)  # earliest appearance; see app/services/sla.py

    __table_args__ = (
        Index('ix_findings_scan_severity', 'scan_id', 'severity'),
        Index('ix_findings_scan_id', 'scan_id'),
        Index('ix_findings_org_severity', 'organization_id', 'severity'),
        Index('ix_findings_org_status', 'organization_id', 'status'),
    )

    organization = relationship("Organization", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")


@event.listens_for(Finding, "before_insert")
def _inherit_organization_from_scan(mapper, connection, target):
    """A finding always belongs to its scan's organization.

    organization_id is denormalized onto findings for org-scoped queries; set
    it here so every code path that creates a finding is covered.
    """
    if target.organization_id is None and target.scan_id is not None:
        from app.models.scan import Scan

        target.organization_id = connection.execute(
            select(Scan.organization_id).where(Scan.id == target.scan_id)
        ).scalar()

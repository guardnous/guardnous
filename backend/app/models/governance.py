"""Enterprise Governance models — compliance frameworks, policies, risk acceptance."""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ComplianceFramework(Base):
    """Compliance framework definition (SOC2, ISO27001, PCI-DSS, HIPAA, CIS)."""
    __tablename__ = "compliance_frameworks"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    name = Column(String(100), nullable=False)  # SOC2, ISO27001, PCI-DSS, HIPAA, CIS
    version = Column(String(50), default="latest")
    description = Column(Text)
    is_enabled = Column(Boolean, default=True)

    total_controls = Column(Integer, default=0)
    passing_controls = Column(Integer, default=0)
    failing_controls = Column(Integer, default=0)
    not_applicable = Column(Integer, default=0)

    last_assessed = Column(DateTime(timezone=True), nullable=True)
    compliance_score = Column(Float, default=0.0)  # 0-100%
    reference_url = Column(String(500), nullable=True)  # official standard URL

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    controls = relationship("ComplianceControl", back_populates="framework", cascade="all, delete-orphan")


class ComplianceControl(Base):
    """Individual compliance control within a framework."""
    __tablename__ = "compliance_controls"

    id = Column(Integer, primary_key=True, index=True)
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    control_id = Column(String(50), nullable=False)  # e.g., CC6.1, A.8.1
    title = Column(String(500), nullable=False)
    description = Column(Text)
    category = Column(String(200))  # e.g., "Access Control", "Data Protection"

    status = Column(String(50), default="not_assessed")  # passing, failing, not_assessed, not_applicable, partial
    severity = Column(String(20), default="medium")
    automated = Column(Boolean, default=True)  # can be automatically checked

    # Evidence
    evidence = Column(JSON, default=list)  # [{type, source, timestamp, details}]
    last_checked = Column(DateTime(timezone=True), nullable=True)

    # Mapping to findings
    related_finding_ids = Column(JSON, default=list)
    remediation_notes = Column(Text, nullable=True)
    reference_url = Column(String(500), nullable=True)  # link to official control doc
    finding_categories = Column(JSON, default=list)  # which finding categories this control checks

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    framework = relationship("ComplianceFramework", back_populates="controls")


class SecurityPolicy(Base):
    """Organization security policy."""
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    description = Column(Text)
    policy_type = Column(String(100), nullable=False)  # access_control, encryption, network, data_protection, incident_response
    severity = Column(String(20), default="medium")  # critical, high, medium, low

    # Policy definition
    rules = Column(JSON, default=list)  # [{condition, action, target}]
    is_enabled = Column(Boolean, default=True)
    is_enforced = Column(Boolean, default=False)  # enforce vs monitor-only
    is_builtin = Column(Boolean, default=False, server_default="false", nullable=False)  # shipped with GuardNous

    # Repo scoping — null/empty = all repos, otherwise list of repo full_names
    target_repos = Column(JSON, nullable=True)  # ["org/repo1", "org/repo2"] or null for all

    # Stats
    violations_count = Column(Integer, default=0)
    last_evaluated = Column(DateTime(timezone=True), nullable=True)
    resources_in_scope = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    violations = relationship("PolicyViolation", back_populates="policy", cascade="all, delete-orphan")


class PolicyViolation(Base):
    """Policy violation instance."""
    __tablename__ = "policy_violations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    policy_id = Column(Integer, ForeignKey("security_policies.id"), nullable=False, index=True)

    resource_type = Column(String(100))
    resource_id = Column(String(500))
    resource_name = Column(String(255))
    cloud_provider = Column(String(50))

    violation_details = Column(JSON, default=dict)
    severity = Column(String(20), nullable=False)
    status = Column(String(50), default="open")  # open, resolved, accepted, exempted

    # Risk acceptance
    accepted_by = Column(String(255), nullable=True)
    accepted_at = Column(DateTime(timezone=True), nullable=True)
    acceptance_reason = Column(Text, nullable=True)
    acceptance_expires = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    policy = relationship("SecurityPolicy", back_populates="violations")


class RiskException(Base):
    """Risk acceptance / exception record."""
    __tablename__ = "risk_exceptions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    title = Column(String(500), nullable=False)
    description = Column(Text)
    risk_type = Column(String(100))  # finding, policy_violation, compliance_gap
    reference_id = Column(Integer, nullable=True)  # finding_id or violation_id

    severity = Column(String(20), nullable=False)
    justification = Column(Text, nullable=False)
    compensating_controls = Column(Text, nullable=True)

    status = Column(String(50), default="pending")  # pending, approved, rejected, expired
    requested_by = Column(String(255), nullable=False)
    approved_by = Column(String(255), nullable=True)

    # Link to specific policy + resource for evaluation-aware exemptions
    policy_id = Column(Integer, ForeignKey("security_policies.id", ondelete="SET NULL"), nullable=True)
    resource_id = Column(String(1000), nullable=True)
    resource_name = Column(String(500), nullable=True)
    resource_type = Column(String(200), nullable=True)
    expiry_date = Column(DateTime(timezone=True), nullable=True)

    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

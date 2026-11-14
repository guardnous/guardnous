"""IAM Threat Intelligence models — identity inventory, privilege analysis, threat detection."""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class IdentityType(str, enum.Enum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    ROLE = "role"
    GROUP = "group"
    FEDERATED = "federated"
    API_KEY = "api_key"


class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Identity(Base):
    """Cloud identity (user, service account, role, group) from any provider."""
    __tablename__ = "iam_identities"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)

    cloud_provider = Column(String(50), nullable=False)  # aws, azure, gcp
    identity_type = Column(String(50), nullable=False)  # user, service_account, role, group
    external_id = Column(String(500), nullable=False)  # ARN, UPN, etc
    display_name = Column(String(255))
    email = Column(String(255), nullable=True)

    # Status
    is_active = Column(Boolean, default=True)
    last_activity = Column(DateTime(timezone=True), nullable=True)
    created_externally = Column(DateTime(timezone=True), nullable=True)
    days_inactive = Column(Integer, default=0)

    # Risk scoring
    risk_score = Column(Float, default=0.0)  # 0-100
    risk_level = Column(String(20), default="info")
    risk_factors = Column(JSON, default=list)  # [{factor, score, details}]

    # Permissions summary
    permissions_count = Column(Integer, default=0)
    admin_access = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, nullable=True)
    has_console_access = Column(Boolean, nullable=True)
    has_programmatic_access = Column(Boolean, nullable=True)

    # Access keys / credentials
    access_keys = Column(JSON, default=list)  # [{key_id, status, last_used, age_days}]
    credential_age_days = Column(Integer, default=0)

    # Policy/role attachments
    attached_policies = Column(JSON, default=list)  # [{name, arn, type}]
    group_memberships = Column(JSON, default=list)  # [group_name, ...]
    inline_policies = Column(JSON, default=list)  # [{name, document}]

    # Raw data
    raw_data = Column(JSON, default=dict)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    threats = relationship("IAMThreat", back_populates="identity", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="source_identity", foreign_keys="AttackPath.source_identity_id")


class IAMThreat(Base):
    """Detected IAM threat or anomaly."""
    __tablename__ = "iam_threats"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    identity_id = Column(Integer, ForeignKey("iam_identities.id"), nullable=False)

    threat_type = Column(String(100), nullable=False)  # privilege_escalation, credential_exposure, dormant_admin, etc
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    confidence = Column(Float, default=0.8)  # 0-1

    # Detection details
    detection_method = Column(String(100))  # rule_based, ml, behavioral
    evidence = Column(JSON, default=dict)
    mitre_tactic = Column(String(100), nullable=True)  # T1078, T1098, etc
    mitre_technique = Column(String(100), nullable=True)

    # Resolution
    status = Column(String(50), default="open")  # open, investigating, resolved, false_positive
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(255), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Remediation
    remediation_steps = Column(JSON, default=list)  # [{step, description, automated}]
    auto_remediable = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    identity = relationship("Identity", back_populates="threats")


class AttackPath(Base):
    """Privilege escalation / lateral movement attack path."""
    __tablename__ = "iam_attack_paths"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    complexity = Column(String(20), default="medium")  # low, medium, high

    source_identity_id = Column(Integer, ForeignKey("iam_identities.id"), nullable=False)
    target_resource = Column(String(500))  # what they can reach
    path_steps = Column(JSON, default=list)  # [{step_num, action, resource, description}]

    risk_score = Column(Float, default=0.0)
    is_exploitable = Column(Boolean, default=True)
    status = Column(String(50), default="open")

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    source_identity = relationship("Identity", back_populates="attack_paths", foreign_keys=[source_identity_id])


class IAMScanResult(Base):
    """Result of an IAM security scan."""
    __tablename__ = "iam_scan_results"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)

    cloud_provider = Column(String(50), nullable=False)
    scan_type = Column(String(50), default="full")  # full, incremental, quick
    status = Column(String(50), default="running")  # running, completed, failed

    identities_scanned = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    attack_paths_found = Column(Integer, default=0)
    duration_seconds = Column(Float, nullable=True)

    summary = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

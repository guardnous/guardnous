"""Cloud Resource Inventory — stores actual cloud resource configurations for policy evaluation."""
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Text, Boolean, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class CloudResource(Base):
    """A cloud resource with its actual configuration state.

    This is the foundation of resource-driven policy evaluation.
    Each row represents one real cloud resource (S3 bucket, Security Group, IAM policy, etc.)
    with its full configuration stored as JSONB for condition evaluation.
    """
    __tablename__ = "cloud_resources"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    # Identity
    provider = Column(String(20), nullable=False, index=True)          # aws, azure, gcp
    resource_type = Column(String(200), nullable=False, index=True)    # aws_s3_bucket, azurerm_storage_account
    resource_id = Column(String(1000), nullable=False)                 # ARN, Azure resource ID, GCP self_link
    resource_name = Column(String(500), nullable=False)                # human-readable name
    region = Column(String(100), nullable=True)                        # us-east-1, eastus, us-central1
    account_id = Column(String(100), nullable=True)                    # AWS account ID, Azure subscription, GCP project

    # The actual resource configuration — THIS is what policies evaluate against
    config = Column(JSON, nullable=False, default=dict)

    # Metadata
    tags = Column(JSON, default=dict)
    status = Column(String(50), default="active")                      # active, deleted, unknown
    source = Column(String(100), default="scan")                       # scan, api_sync, terraform_state, manual

    # Tracking
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_synced = Column(DateTime(timezone=True), server_default=func.now())
    last_evaluated = Column(DateTime(timezone=True), nullable=True)
    config_hash = Column(String(64), nullable=True)                    # SHA-256 of config — detect drift

    __table_args__ = (
        Index("ix_cloud_resources_org_provider", "organization_id", "provider"),
        Index("ix_cloud_resources_org_type", "organization_id", "resource_type"),
        Index("ix_cloud_resources_provider_type", "provider", "resource_type"),
        Index("uq_cloud_resources_identity", "organization_id", "provider", "resource_id", unique=True),
    )


class Assessment(Base):
    """A point-in-time compliance assessment run.

    Each assessment captures the full evaluation state — policies evaluated,
    resources checked, violations found, compliance scores. This enables
    trend tracking, regression detection, and audit trails.
    """
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    # Assessment metadata
    assessment_type = Column(String(50), nullable=False, default="full")  # full, incremental, policy_only, resource_only
    status = Column(String(30), nullable=False, default="running")        # running, completed, failed, cancelled
    triggered_by = Column(String(255), nullable=True)                     # user email or "scheduled"

    # Scope
    providers_evaluated = Column(JSON, default=list)      # ["aws", "azure"]
    resource_types_evaluated = Column(JSON, default=list)  # ["aws_s3_bucket", ...]
    policies_evaluated = Column(Integer, default=0)
    resources_evaluated = Column(Integer, default=0)

    # Results summary
    total_checks = Column(Integer, default=0)             # total (policy, resource) pairs evaluated
    passed = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    errors = Column(Integer, default=0)
    exempted = Column(Integer, default=0)
    compliance_score = Column(Integer, default=0)          # 0-100

    # Violation deltas vs previous assessment
    new_violations = Column(Integer, default=0)
    resolved_violations = Column(Integer, default=0)
    total_violations = Column(Integer, default=0)

    # Timing
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    results = relationship("AssessmentResult", back_populates="assessment", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assessments_org_status", "organization_id", "status"),
        Index("ix_assessments_org_created", "organization_id", "created_at"),
    )


class CloudChange(Base):
    """A change GuardNous made to a cloud resource, with what is needed to undo it."""

    __tablename__ = "cloud_changes"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    run_id = Column(Integer, nullable=True)                     # agent run that carried it out
    rule_id = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    provider = Column(String(20), nullable=False)
    account_id = Column(String(100), nullable=False)
    region = Column(String(100), nullable=True)
    resource_id = Column(String(1000), nullable=False)
    resource_name = Column(String(500), nullable=False)
    target = Column(JSON, nullable=False, default=dict)         # identifiers the cloud API needs
    before = Column(JSON, nullable=True)                        # state read just before the change
    after = Column(JSON, nullable=True)                         # state read just after
    status = Column(String(30), nullable=False, default="applied")   # applied, rolled_back
    requested_by = Column(String(255), nullable=True)
    approved_by = Column(String(255), nullable=True)
    rolled_back_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    rolled_back_at = Column(DateTime(timezone=True), nullable=True)


class AssessmentResult(Base):
    """Individual evaluation result — one per (policy, resource) pair.

    This is the evidence record. It stores exactly WHAT was checked,
    what the expected and actual values were, and whether it passed or failed.
    This is what auditors need for SOC2/ISO27001 compliance.
    """
    __tablename__ = "assessment_results"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    # What was evaluated
    policy_id = Column(Integer, ForeignKey("security_policies.id", ondelete="SET NULL"), nullable=True)
    policy_name = Column(String(255), nullable=False)
    policy_severity = Column(String(20), nullable=False)

    resource_id = Column(Integer, ForeignKey("cloud_resources.id", ondelete="SET NULL"), nullable=True)
    resource_identifier = Column(String(1000), nullable=False)     # ARN/Azure ID — preserved even if resource deleted
    resource_type = Column(String(200), nullable=False)
    resource_name = Column(String(500), nullable=False)
    provider = Column(String(20), nullable=False)

    # Result
    status = Column(String(20), nullable=False)                    # PASS, FAIL, ERROR, NOT_APPLICABLE, EXEMPTED
    is_exempted = Column(Boolean, default=False)
    exemption_id = Column(Integer, ForeignKey("risk_exceptions.id", ondelete="SET NULL"), nullable=True)

    # Evidence — THE KEY DIFFERENTIATOR
    evidence = Column(JSON, nullable=False, default=list)
    # [
    #   {"field": "config.public_access_block.block_public_acls",
    #    "operator": "eq", "expected": true, "actual": false, "result": "FAIL"},
    #   {"field": "config.encryption.sse_algorithm",
    #    "operator": "exists", "expected": true, "actual": "AES256", "result": "PASS"}
    # ]

    # Remediation
    remediation = Column(Text, nullable=True)
    auto_fixable = Column(Boolean, default=False)

    evaluated_at = Column(DateTime(timezone=True), server_default=func.now())

    assessment = relationship("Assessment", back_populates="results")

    __table_args__ = (
        Index("ix_assessment_results_assessment", "assessment_id"),
        Index("ix_assessment_results_status", "assessment_id", "status"),
        Index("ix_assessment_results_policy", "policy_id"),
        Index("ix_assessment_results_resource", "resource_id"),
    )

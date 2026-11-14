"""Governance Engine: cloud_resources, assessments, assessment_results + policy enhancements

Revision ID: 021
Revises: 020
Create Date: 2026-11-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Cloud Resources table ──
    op.create_table(
        "cloud_resources",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("resource_type", sa.String(200), nullable=False),
        sa.Column("resource_id", sa.String(1000), nullable=False),
        sa.Column("resource_name", sa.String(500), nullable=False),
        sa.Column("region", sa.String(100), nullable=True),
        sa.Column("account_id", sa.String(100), nullable=True),
        sa.Column("config", JSON, nullable=False, server_default="{}"),
        sa.Column("tags", JSON, server_default="{}"),
        sa.Column("status", sa.String(50), server_default="active"),
        sa.Column("source", sa.String(100), server_default="scan"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_synced", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_evaluated", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_cloud_resources_org_provider", "cloud_resources", ["organization_id", "provider"])
    op.create_index("ix_cloud_resources_org_type", "cloud_resources", ["organization_id", "resource_type"])
    op.create_index("ix_cloud_resources_provider_type", "cloud_resources", ["provider", "resource_type"])
    op.create_index(
        "uq_cloud_resources_identity", "cloud_resources",
        ["organization_id", "provider", "resource_id"], unique=True,
    )

    # ── Assessments table ──
    op.create_table(
        "assessments",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_type", sa.String(50), nullable=False, server_default="full"),
        sa.Column("status", sa.String(30), nullable=False, server_default="running"),
        sa.Column("triggered_by", sa.String(255), nullable=True),
        sa.Column("providers_evaluated", JSON, server_default="[]"),
        sa.Column("resource_types_evaluated", JSON, server_default="[]"),
        sa.Column("policies_evaluated", sa.Integer(), server_default="0"),
        sa.Column("resources_evaluated", sa.Integer(), server_default="0"),
        sa.Column("total_checks", sa.Integer(), server_default="0"),
        sa.Column("passed", sa.Integer(), server_default="0"),
        sa.Column("failed", sa.Integer(), server_default="0"),
        sa.Column("errors", sa.Integer(), server_default="0"),
        sa.Column("exempted", sa.Integer(), server_default="0"),
        sa.Column("compliance_score", sa.Integer(), server_default="0"),
        sa.Column("new_violations", sa.Integer(), server_default="0"),
        sa.Column("resolved_violations", sa.Integer(), server_default="0"),
        sa.Column("total_violations", sa.Integer(), server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_assessments_org_status", "assessments", ["organization_id", "status"])
    op.create_index("ix_assessments_org_created", "assessments", ["organization_id", "created_at"])

    # ── Assessment Results table ──
    op.create_table(
        "assessment_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("policy_id", sa.Integer(), sa.ForeignKey("security_policies.id", ondelete="SET NULL"), nullable=True),
        sa.Column("policy_name", sa.String(255), nullable=False),
        sa.Column("policy_severity", sa.String(20), nullable=False),
        sa.Column("resource_id", sa.Integer(), sa.ForeignKey("cloud_resources.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resource_identifier", sa.String(1000), nullable=False),
        sa.Column("resource_type", sa.String(200), nullable=False),
        sa.Column("resource_name", sa.String(500), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("is_exempted", sa.Boolean(), server_default="false"),
        sa.Column("exemption_id", sa.Integer(), sa.ForeignKey("risk_exceptions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("evidence", JSON, nullable=False, server_default="[]"),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("auto_fixable", sa.Boolean(), server_default="false"),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_assessment_results_assessment", "assessment_results", ["assessment_id"])
    op.create_index("ix_assessment_results_status", "assessment_results", ["assessment_id", "status"])
    op.create_index("ix_assessment_results_policy", "assessment_results", ["policy_id"])
    op.create_index("ix_assessment_results_resource", "assessment_results", ["resource_id"])

    # ── Enhance risk_exceptions with policy/resource linking ──
    op.add_column("risk_exceptions", sa.Column("policy_id", sa.Integer(), sa.ForeignKey("security_policies.id", ondelete="SET NULL"), nullable=True))
    op.add_column("risk_exceptions", sa.Column("resource_id", sa.String(1000), nullable=True))
    op.add_column("risk_exceptions", sa.Column("resource_name", sa.String(500), nullable=True))
    op.add_column("risk_exceptions", sa.Column("resource_type", sa.String(200), nullable=True))
    op.add_column("risk_exceptions", sa.Column("expiry_date", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("risk_exceptions", "expiry_date")
    op.drop_column("risk_exceptions", "resource_type")
    op.drop_column("risk_exceptions", "resource_name")
    op.drop_column("risk_exceptions", "resource_id")
    op.drop_column("risk_exceptions", "policy_id")
    op.drop_table("assessment_results")
    op.drop_table("assessments")
    op.drop_table("cloud_resources")

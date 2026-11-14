"""Reconcile databases built by earlier migrations with the models.

Adds the indexes migration 021 left out, and makes deleting a finding remove
the agent insights that reference it (the constraint had no ON DELETE rule, so
deleting a scan that had insights failed).

Revision ID: 023
Revises: 022
Create Date: 2026-11-12
"""
from alembic import op

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None

_INDEXES = [
    ("ix_assessments_id", "assessments", "id"),
    ("ix_assessments_organization_id", "assessments", "organization_id"),
    ("ix_assessment_results_id", "assessment_results", "id"),
    ("ix_assessment_results_assessment_id", "assessment_results", "assessment_id"),
    ("ix_assessment_results_organization_id", "assessment_results", "organization_id"),
    ("ix_cloud_resources_id", "cloud_resources", "id"),
    ("ix_cloud_resources_organization_id", "cloud_resources", "organization_id"),
    ("ix_cloud_resources_provider", "cloud_resources", "provider"),
    ("ix_cloud_resources_resource_type", "cloud_resources", "resource_type"),
    ("ix_audit_logs_org_action", "audit_logs", "organization_id, action"),
    ("ix_notifications_org_user", "notifications", "organization_id, user_id"),
]


def upgrade() -> None:
    for name, table, columns in _INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})")

    op.execute("ALTER TABLE agent_insights DROP CONSTRAINT IF EXISTS agent_insights_finding_id_fkey")
    op.execute(
        "ALTER TABLE agent_insights ADD CONSTRAINT agent_insights_finding_id_fkey "
        "FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE"
    )

    op.execute("UPDATE agent_messages SET status = 'completed' WHERE status IS NULL")
    op.execute("ALTER TABLE agent_messages ALTER COLUMN status SET DEFAULT 'completed'")
    op.execute("ALTER TABLE agent_messages ALTER COLUMN status SET NOT NULL")

    # Findings saved before organization_id was populated on insert
    op.execute(
        "UPDATE findings SET organization_id = "
        "(SELECT s.organization_id FROM scans s WHERE s.id = findings.scan_id) "
        "WHERE organization_id IS NULL"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE agent_insights DROP CONSTRAINT IF EXISTS agent_insights_finding_id_fkey")
    op.execute(
        "ALTER TABLE agent_insights ADD CONSTRAINT agent_insights_finding_id_fkey "
        "FOREIGN KEY (finding_id) REFERENCES findings (id)"
    )
    for name, _table, _columns in _INDEXES[:9]:
        op.execute(f"DROP INDEX IF EXISTS {name}")

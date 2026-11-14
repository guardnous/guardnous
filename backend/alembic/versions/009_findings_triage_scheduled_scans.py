"""Add findings triage workflow columns and scheduled scan support.

Revision ID: 009
Revises: 008
Create Date: 2025-01-15
"""
from alembic import op
import sqlalchemy as sa

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade():
    # ── Findings triage workflow (Gap 2) ──
    op.add_column("findings", sa.Column("status", sa.String(30), server_default="open", index=True))
    op.add_column("findings", sa.Column("assigned_to", sa.String(255), nullable=True, index=True))
    op.add_column("findings", sa.Column("notes", sa.JSON(), server_default="[]"))
    op.add_column("findings", sa.Column("false_positive_reason", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("sla_deadline", sa.DateTime(timezone=True), nullable=True))

    # ── Scheduled/recurring scans (Gap 5) ──
    op.add_column("scans", sa.Column("scheduled", sa.Boolean(), server_default="false", index=True))
    op.add_column("scans", sa.Column("integration_id", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("repository", sa.String(500), nullable=True, index=True))


def downgrade():
    op.drop_column("findings", "sla_deadline")
    op.drop_column("findings", "resolved_at")
    op.drop_column("findings", "false_positive_reason")
    op.drop_column("findings", "notes")
    op.drop_column("findings", "assigned_to")
    op.drop_column("findings", "status")

    op.drop_column("scans", "repository")
    op.drop_column("scans", "integration_id")
    op.drop_column("scans", "scheduled")

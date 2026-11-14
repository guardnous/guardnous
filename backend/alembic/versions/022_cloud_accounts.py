"""cloud_accounts table for real cloud connector integration

Revision ID: 022_cloud_accounts
Revises: 021_governance_engine_cloud_resources
Create Date: 2026-11-09
"""
from alembic import op
import sqlalchemy as sa

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cloud_accounts",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("provider", sa.String(20), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("account_identifier", sa.String(255), nullable=False),
        sa.Column("credentials_encrypted", sa.Text(), nullable=True),
        sa.Column("status", sa.String(30), server_default="pending"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resources_count", sa.Integer(), server_default="0"),
        sa.Column("sync_enabled", sa.Boolean(), server_default=sa.text("true")),
        sa.Column("sync_interval_hours", sa.Integer(), server_default="6"),
        sa.Column("resource_types_filter", sa.JSON(), server_default="[]"),
        sa.Column("regions", sa.JSON(), server_default="[]"),
        sa.Column("tags", sa.JSON(), server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("cloud_accounts")

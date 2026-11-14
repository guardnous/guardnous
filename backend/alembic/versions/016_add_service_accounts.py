"""Add service_accounts table (bot identities for automated remediation PRs).

A service account is a non-human identity that authors auto-fix pull requests
with a consistent git author name/email and a hashed access token (shown once).
"""
from alembic import op
import sqlalchemy as sa

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_accounts",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, index=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("bot_username", sa.String(length=120), nullable=False, server_default="guardnous-bot"),
        sa.Column("bot_email", sa.String(length=255), nullable=False, server_default="bot@guardnous.local"),
        sa.Column("token_hash", sa.String(length=128), nullable=True, index=True),
        sa.Column("token_prefix", sa.String(length=16), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("service_accounts")

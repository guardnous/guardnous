"""Add role_slug column to user_invitations

Revision ID: 007
Revises: 006
"""
from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    # Idempotent: only add if missing
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'user_invitations' AND column_name = 'role_slug'"
        )
    )
    if not result.fetchone():
        op.add_column(
            "user_invitations",
            sa.Column("role_slug", sa.String(100), server_default="viewer"),
        )


def downgrade() -> None:
    op.drop_column("user_invitations", "role_slug")

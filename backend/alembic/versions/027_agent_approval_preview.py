"""Approvals carry the exact change being approved (e.g. a diff).

Revision ID: 027
Revises: 026
Create Date: 2026-11-13
"""
from alembic import op

revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE agent_approvals ADD COLUMN IF NOT EXISTS preview TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE agent_approvals DROP COLUMN IF EXISTS preview")

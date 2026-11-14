"""Mark policies that ship with GuardNous, separately from whether they are enforced.

The UI used is_enforced to mean "built-in". Existing rows cannot be told apart
reliably, so they stay false; loading the built-in policies again marks new ones.

Revision ID: 025
Revises: 024
Create Date: 2026-11-12
"""
from alembic import op

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE security_policies ADD COLUMN IF NOT EXISTS is_builtin BOOLEAN NOT NULL DEFAULT false"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE security_policies DROP COLUMN IF EXISTS is_builtin")

"""Add plugin_settings JSON column to org_settings for persistent plugin enable-state.

Plugin enabled/disabled toggles were previously held only in an in-memory
registry dict and were lost on every API restart. This column persists the
per-org plugin enabled map: {plugin_slug: bool}.
"""
from alembic import op
import sqlalchemy as sa

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "org_settings",
        sa.Column("plugin_settings", sa.JSON(), nullable=True, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("org_settings", "plugin_settings")

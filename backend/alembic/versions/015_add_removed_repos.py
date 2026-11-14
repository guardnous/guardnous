"""Add removed_repos JSON column to integrations.

The repo list is live-fetched from the VCS provider (all repos the installation
can see). Deleting a repo previously removed its onboarding + scan data but the
repo immediately reappeared in the list because it still exists in the account,
making "delete" look broken. This column tracks full_names the user has removed
so they are filtered out of the live-fetched list (restorable).
"""
from alembic import op
import sqlalchemy as sa

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "integrations",
        sa.Column("removed_repos", sa.JSON(), nullable=True, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("integrations", "removed_repos")

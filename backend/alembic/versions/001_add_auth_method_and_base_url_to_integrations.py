"""add auth_method and base_url to integrations

Revision ID: 001
Revises: None
Create Date: 2026-03-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "integrations",
        sa.Column("auth_method", sa.String(50), server_default="oauth", nullable=True),
    )
    op.add_column(
        "integrations",
        sa.Column("base_url", sa.String(500), nullable=True),
    )
    # Backfill existing rows that have NULL auth_method
    op.execute("UPDATE integrations SET auth_method = 'oauth' WHERE auth_method IS NULL")


def downgrade() -> None:
    op.drop_column("integrations", "base_url")
    op.drop_column("integrations", "auth_method")

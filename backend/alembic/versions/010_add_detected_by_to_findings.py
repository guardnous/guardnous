"""Add detected_by column to findings for scanner attribution.

Revision ID: 010
Revises: 009
"""

from alembic import op
import sqlalchemy as sa

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("detected_by", sa.String(100), nullable=True))
    op.create_index("ix_findings_detected_by", "findings", ["detected_by"])


def downgrade() -> None:
    op.drop_index("ix_findings_detected_by", table_name="findings")
    op.drop_column("findings", "detected_by")

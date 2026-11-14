"""Add source, epss_score, epss_percentile to cves table.

Revision ID: 008
Revises: 007
Create Date: 2025-01-01
"""
from alembic import op
import sqlalchemy as sa

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if "cves" not in inspector.get_table_names():
        return

    existing_cols = {c["name"] for c in inspector.get_columns("cves")}

    if "source" not in existing_cols:
        op.add_column("cves", sa.Column("source", sa.String(20), server_default="nvd"))
        op.create_index("ix_cves_source", "cves", ["source"])

    if "epss_score" not in existing_cols:
        op.add_column("cves", sa.Column("epss_score", sa.Float(), nullable=True))

    if "epss_percentile" not in existing_cols:
        op.add_column("cves", sa.Column("epss_percentile", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_index("ix_cves_source", table_name="cves")
    op.drop_column("cves", "epss_percentile")
    op.drop_column("cves", "epss_score")
    op.drop_column("cves", "source")

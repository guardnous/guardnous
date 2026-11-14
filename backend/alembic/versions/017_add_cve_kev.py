"""Add CISA KEV (Known Exploited Vulnerabilities) flags to cves.

Adds `is_kev` and `kev_date_added` so CVEs present in the CISA Known Exploited
Vulnerabilities catalog can be flagged and prioritized. KEV items have confirmed
active exploitation in the wild and outrank CVSS/EPSS for remediation urgency.
"""
from alembic import op
import sqlalchemy as sa

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cves", sa.Column("is_kev", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("cves", sa.Column("kev_date_added", sa.String(length=20), nullable=True))
    op.create_index("ix_cves_is_kev", "cves", ["is_kev"])


def downgrade() -> None:
    op.drop_index("ix_cves_is_kev", table_name="cves")
    op.drop_column("cves", "kev_date_added")
    op.drop_column("cves", "is_kev")

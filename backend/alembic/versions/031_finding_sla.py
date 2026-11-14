"""When a finding was first seen, so its SLA clock survives rescans.

Deadlines of existing findings are filled in at application startup
(app.services.sla.backfill_at_startup): "first seen" depends on which scans
are of the same target, which is not practical to express in portable SQL.

Revision ID: 031
Revises: 030
Create Date: 2026-11-14
"""
import sqlalchemy as sa
from alembic import op

revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None


def _columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("findings")}


def upgrade() -> None:
    if "first_seen_at" not in _columns():
        op.add_column("findings", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    if "first_seen_at" in _columns():
        op.drop_column("findings", "first_seen_at")

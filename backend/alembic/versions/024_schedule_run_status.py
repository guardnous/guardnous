"""Record the outcome of the last run on scan and report schedules.

Revision ID: 024
Revises: 023
Create Date: 2026-11-12
"""
from alembic import op

revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("scan_schedules", "report_schedules"):
        op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS last_status VARCHAR(30)")
        op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS last_error TEXT")
    op.execute("ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS last_report_id INTEGER")


def downgrade() -> None:
    op.execute("ALTER TABLE report_schedules DROP COLUMN IF EXISTS last_report_id")
    for table in ("scan_schedules", "report_schedules"):
        op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS last_error")
        op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS last_status")

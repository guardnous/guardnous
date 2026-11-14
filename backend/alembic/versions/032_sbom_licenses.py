"""Dependency inventories of scans (for SBOM export) and a cache of package licences.

Revision ID: 032
Revises: 031
Create Date: 2026-11-14
"""
import sqlalchemy as sa
from alembic import op

revision = "032"
down_revision = "031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())

    if "scan_dependency_inventories" not in existing:
        op.create_table(
            "scan_dependency_inventories",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id", ondelete="CASCADE"),
                      nullable=False, unique=True),
            sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("components", sa.JSON, nullable=False),
            sa.Column("component_count", sa.Integer, nullable=False, server_default="0"),
            sa.Column("licenses", sa.JSON, nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index(
            "ix_scan_dependency_inventories_organization_id",
            "scan_dependency_inventories", ["organization_id"],
        )

    if "package_licenses" not in existing:
        op.create_table(
            "package_licenses",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("system", sa.String(20), nullable=False),
            sa.Column("name", sa.String(300), nullable=False),
            sa.Column("version", sa.String(100), nullable=False),
            sa.Column("licenses", sa.JSON, nullable=False),
            sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("system", "name", "version", name="uq_package_licenses_package"),
        )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS package_licenses")
    op.execute("DROP TABLE IF EXISTS scan_dependency_inventories")

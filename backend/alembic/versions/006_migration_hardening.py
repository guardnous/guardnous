"""migration hardening — add missing columns, fix schema drift

Revision ID: 006
Revises: 005
Create Date: 2026-09-14

Idempotent: safe to run on both fresh installs (005 already has the columns)
and existing databases (005 was missing them, may have been manually added).
"""
from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    """Check if a column already exists (PostgreSQL)."""
    conn = op.get_bind()
    result = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = :t AND column_name = :c"
    ), {"t": table, "c": column})
    return result.fetchone() is not None


def upgrade() -> None:
    # ─── 1. Add missing timestamp columns ─────────────────
    if not _column_exists("permissions", "created_at"):
        op.add_column("permissions", sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
        ))

    if not _column_exists("roles", "updated_at"):
        op.add_column("roles", sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
        ))

    if not _column_exists("groups", "updated_at"):
        op.add_column("groups", sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
        ))

    if not _column_exists("group_roles", "assigned_at"):
        op.add_column("group_roles", sa.Column(
            "assigned_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
        ))

    # ─── 2. Fix user_invitations schema drift ─────────────
    # Migration 005 originally had role_slug/bulk_import_batch_id
    # but model has role_id/full_name/metadata
    if _column_exists("user_invitations", "role_slug"):
        op.drop_column("user_invitations", "role_slug")
    if _column_exists("user_invitations", "bulk_import_batch_id"):
        op.drop_column("user_invitations", "bulk_import_batch_id")

    if not _column_exists("user_invitations", "role_id"):
        op.add_column("user_invitations", sa.Column(
            "role_id", sa.Integer, sa.ForeignKey("roles.id"),
        ))
    if not _column_exists("user_invitations", "full_name"):
        op.add_column("user_invitations", sa.Column(
            "full_name", sa.String(255),
        ))
    if not _column_exists("user_invitations", "metadata"):
        op.add_column("user_invitations", sa.Column(
            "metadata", sa.JSON, server_default="{}",
        ))

    # ─── 3. Fix audit_logs.resource_id type ───────────────
    # Migration 005 originally had String(255), model has Integer
    # Alter only if it's varchar (old migration created it as String)
    conn = op.get_bind()
    result = conn.execute(sa.text(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_name = 'audit_logs' AND column_name = 'resource_id'"
    ))
    row = result.fetchone()
    if row and row[0] == "character varying":
        op.alter_column(
            "audit_logs", "resource_id",
            type_=sa.Integer,
            postgresql_using="resource_id::integer",
        )

    # ─── 4. Fix audit_logs.resource_type nullability ──────
    # Migration had nullable=False but model allows NULL
    if _column_exists("audit_logs", "resource_type"):
        op.alter_column("audit_logs", "resource_type", nullable=True)

    # ─── 5. Ensure admin user_roles seed exists ───────────
    existing = conn.execute(sa.text(
        "SELECT 1 FROM user_roles ur "
        "JOIN users u ON ur.user_id = u.id "
        "WHERE u.role IN ('admin', 'superadmin') AND ur.role_id = 1 "
        "LIMIT 1"
    )).fetchone()

    if not existing:
        admin_users = conn.execute(sa.text(
            "SELECT id FROM users WHERE role IN ('admin', 'superadmin')"
        )).fetchall()
        for row in admin_users:
            # Check if mapping already exists for this user
            exists = conn.execute(sa.text(
                "SELECT 1 FROM user_roles WHERE user_id = :uid AND role_id = 1"
            ), {"uid": row[0]}).fetchone()
            if not exists:
                conn.execute(sa.text(
                    "INSERT INTO user_roles (user_id, role_id, tenant_id) "
                    "VALUES (:uid, 1, 1000)"
                ), {"uid": row[0]})


def downgrade() -> None:
    # Downgrade is best-effort; columns added idempotently
    pass

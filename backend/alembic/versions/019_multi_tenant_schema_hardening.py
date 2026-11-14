"""Add organization_id to findings, notifications, audit_logs; add org limits.

Ensures every data table that stores org-specific data has a direct
organization_id FK for efficient tenant-scoped queries — no need to join
through parent tables.  Also adds max_users / max_repos to organizations.
"""
from alembic import op
import sqlalchemy as sa

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Organization limits ──────────────────────────────────────────
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.add_column(
            sa.Column("max_users", sa.Integer(), nullable=True, server_default="50")
        )
        batch_op.add_column(
            sa.Column("max_repos", sa.Integer(), nullable=True, server_default="100")
        )
        batch_op.add_column(
            sa.Column(
                "plan_tier",
                sa.String(30),
                nullable=True,
                server_default="free",
            )
        )

    # ── Findings: add organization_id ────────────────────────────────
    # Back-fill from scan.organization_id via a correlated sub-select.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=True,
                index=True,
            )
        )

    # Back-fill existing findings from their scan's organization_id
    op.execute(
        """
        UPDATE findings
        SET organization_id = (
            SELECT scans.organization_id
            FROM scans
            WHERE scans.id = findings.scan_id
        )
        WHERE organization_id IS NULL
        """
    )

    # ── Notifications: add organization_id ───────────────────────────
    with op.batch_alter_table("notifications") as batch_op:
        batch_op.add_column(
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=True,
                index=True,
            )
        )

    # Back-fill from user's organization_id
    op.execute(
        """
        UPDATE notifications
        SET organization_id = (
            SELECT users.organization_id
            FROM users
            WHERE users.id = notifications.user_id
        )
        WHERE organization_id IS NULL
        """
    )

    # ── Audit logs: add organization_id ──────────────────────────────
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="SET NULL"),
                nullable=True,
                index=True,
            )
        )

    # ── Composite indexes for common multi-tenant queries ────────────
    op.create_index(
        "ix_findings_org_severity",
        "findings",
        ["organization_id", "severity"],
    )
    op.create_index(
        "ix_findings_org_status",
        "findings",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_notifications_org_user",
        "notifications",
        ["organization_id", "user_id"],
    )
    op.create_index(
        "ix_audit_logs_org_action",
        "audit_logs",
        ["organization_id", "action"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_logs_org_action", table_name="audit_logs")
    op.drop_index("ix_notifications_org_user", table_name="notifications")
    op.drop_index("ix_findings_org_status", table_name="findings")
    op.drop_index("ix_findings_org_severity", table_name="findings")

    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.drop_column("organization_id")

    with op.batch_alter_table("notifications") as batch_op:
        batch_op.drop_column("organization_id")

    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("organization_id")

    with op.batch_alter_table("organizations") as batch_op:
        batch_op.drop_column("plan_tier")
        batch_op.drop_column("max_repos")
        batch_op.drop_column("max_users")

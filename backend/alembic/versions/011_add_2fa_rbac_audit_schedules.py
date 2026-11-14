"""Add 2FA columns, RBAC agent access, agent audit, scan schedules, report schedules.

Revision ID: 011
Revises: 010
"""

from alembic import op
import sqlalchemy as sa

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Users: 2FA columns ---
    op.add_column("users", sa.Column("totp_secret", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("users", sa.Column("totp_confirmed", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("users", sa.Column("backup_codes", sa.Text(), nullable=True))

    # --- Roles: RBAC agent/tool access ---
    op.add_column("roles", sa.Column("allowed_agents", sa.JSON(), nullable=True))
    op.add_column("roles", sa.Column("allowed_tools", sa.JSON(), nullable=True))

    # --- Agent Audit Entries ---
    op.create_table(
        "agent_audit_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("input_summary", sa.Text(), nullable=True),
        sa.Column("output_summary", sa.Text(), nullable=True),
        sa.Column("tool_calls", sa.JSON(), nullable=True),
        sa.Column("delegated_to", sa.JSON(), nullable=True),
        sa.Column("guardrail_flags", sa.JSON(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), server_default="success", nullable=False),
    )
    op.create_index("ix_agent_audit_timestamp", "agent_audit_entries", ["timestamp"])
    op.create_index("ix_agent_audit_agent_id", "agent_audit_entries", ["agent_id"])
    op.create_index("ix_agent_audit_user_id", "agent_audit_entries", ["user_id"])

    # --- Scan Schedules ---
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("cron_expr", sa.String(100), nullable=False),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("target_repos", sa.JSON(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- Report Schedules ---
    op.create_table(
        "report_schedules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("cron_expr", sa.String(100), nullable=False),
        sa.Column("report_type", sa.String(50), server_default="full", nullable=False),
        sa.Column("format", sa.String(20), server_default="pdf", nullable=False),
        sa.Column("recipients", sa.JSON(), nullable=True),
        sa.Column("filters", sa.JSON(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("report_schedules")
    op.drop_table("scan_schedules")
    op.drop_index("ix_agent_audit_user_id", table_name="agent_audit_entries")
    op.drop_index("ix_agent_audit_agent_id", table_name="agent_audit_entries")
    op.drop_index("ix_agent_audit_timestamp", table_name="agent_audit_entries")
    op.drop_table("agent_audit_entries")
    op.drop_column("roles", "allowed_tools")
    op.drop_column("roles", "allowed_agents")
    op.drop_column("users", "backup_codes")
    op.drop_column("users", "totp_confirmed")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret")

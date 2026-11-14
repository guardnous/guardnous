"""Durable agent runs, their steps, and the approvals they wait on.

Revision ID: 026
Revises: 025
Create Date: 2026-11-12
"""
from alembic import op

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS agent_runs (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            parent_run_id INTEGER REFERENCES agent_runs(id) ON DELETE CASCADE,
            agent_id VARCHAR(100) NOT NULL,
            goal TEXT NOT NULL,
            trigger VARCHAR(20) NOT NULL DEFAULT 'user',
            status VARCHAR(30) NOT NULL DEFAULT 'queued',
            result TEXT,
            error TEXT,
            messages JSON,
            pending_outputs JSON,
            provider VARCHAR(50),
            model VARCHAR(120),
            step_count INTEGER NOT NULL DEFAULT 0,
            max_steps INTEGER NOT NULL DEFAULT 12,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            cancel_requested BOOLEAN NOT NULL DEFAULT false,
            task_id VARCHAR(255),
            created_at TIMESTAMPTZ DEFAULT now(),
            started_at TIMESTAMPTZ,
            heartbeat_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS agent_steps (
            id SERIAL PRIMARY KEY,
            run_id INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL,
            kind VARCHAR(20) NOT NULL,
            tool_name VARCHAR(100),
            risk VARCHAR(20),
            arguments JSON,
            output TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'ok',
            duration_ms INTEGER,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS agent_approvals (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
            tool_call_id VARCHAR(120) NOT NULL,
            tool_name VARCHAR(100) NOT NULL,
            risk VARCHAR(20) NOT NULL,
            arguments JSON,
            summary TEXT,
            reasoning TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            decided_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            decision_note TEXT,
            created_at TIMESTAMPTZ DEFAULT now(),
            expires_at TIMESTAMPTZ,
            decided_at TIMESTAMPTZ
        )
    """)
    for name, table, cols in (
        ("ix_agent_runs_id", "agent_runs", "id"),
        ("ix_agent_runs_organization_id", "agent_runs", "organization_id"),
        ("ix_agent_runs_user_id", "agent_runs", "user_id"),
        ("ix_agent_runs_parent_run_id", "agent_runs", "parent_run_id"),
        ("ix_agent_runs_status", "agent_runs", "status"),
        ("ix_agent_steps_id", "agent_steps", "id"),
        ("ix_agent_steps_run_id", "agent_steps", "run_id"),
        ("ix_agent_approvals_id", "agent_approvals", "id"),
        ("ix_agent_approvals_organization_id", "agent_approvals", "organization_id"),
        ("ix_agent_approvals_run_id", "agent_approvals", "run_id"),
        ("ix_agent_approvals_status", "agent_approvals", "status"),
    ):
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({cols})")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS agent_approvals")
    op.execute("DROP TABLE IF EXISTS agent_steps")
    op.execute("DROP TABLE IF EXISTS agent_runs")

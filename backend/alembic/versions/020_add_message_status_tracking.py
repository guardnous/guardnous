"""Add status and task_id to agent_messages for server-side processing

Revision ID: 020
Revises: 019
"""

from alembic import op
import sqlalchemy as sa

revision = "020"
down_revision = "019"


def upgrade():
    op.add_column("agent_messages", sa.Column("status", sa.String(20), server_default="completed", nullable=False))
    op.add_column("agent_messages", sa.Column("task_id", sa.String(255), nullable=True))


def downgrade():
    op.drop_column("agent_messages", "task_id")
    op.drop_column("agent_messages", "status")

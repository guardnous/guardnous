"""add agentic layer tables: conversations, messages, insights

Revision ID: 003
Revises: 002
Create Date: 2026-08-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_conversations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_conversations_organization_id", "agent_conversations", ["organization_id"])
    op.create_index("ix_agent_conversations_user_id", "agent_conversations", ["user_id"])

    op.create_table(
        "agent_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("conversation_id", sa.Integer(), sa.ForeignKey("agent_conversations.id"), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("tool_trace", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_messages_conversation_id", "agent_messages", ["conversation_id"])

    op.create_table(
        "agent_insights",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.Column("provider", sa.String(length=50), nullable=True),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_insights_organization_id", "agent_insights", ["organization_id"])
    op.create_index("ix_agent_insights_finding_id", "agent_insights", ["finding_id"])
    op.create_index("ix_agent_insights_kind", "agent_insights", ["kind"])


def downgrade() -> None:
    op.drop_table("agent_insights")
    op.drop_table("agent_messages")
    op.drop_table("agent_conversations")

"""add per-organization llm_configs (bring your own model)

Revision ID: 004
Revises: 003
Create Date: 2026-08-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "llm_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider", sa.String(length=30), nullable=False, server_default="mock"),
        sa.Column("model", sa.String(length=160), nullable=True),
        sa.Column("base_url", sa.String(length=500), nullable=True),
        sa.Column("api_version", sa.String(length=40), nullable=True),
        sa.Column("api_key_encrypted", sa.Text(), nullable=True),
        sa.Column("temperature", sa.Float(), nullable=True, server_default="0.2"),
        sa.Column("max_tokens", sa.Integer(), nullable=True, server_default="1200"),
        sa.Column("enabled", sa.Boolean(), nullable=True, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_llm_configs_organization_id", "llm_configs", ["organization_id"], unique=True)


def downgrade() -> None:
    op.drop_table("llm_configs")

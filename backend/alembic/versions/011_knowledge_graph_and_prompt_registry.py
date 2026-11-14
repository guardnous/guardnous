"""Add knowledge graph (kg_nodes, kg_edges) and prompt_templates tables.

Revision ID: 011
Revises: 010
"""

from alembic import op
import sqlalchemy as sa

revision = "011b"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Knowledge Graph Nodes ────────────────────────────────
    op.create_table(
        "kg_nodes",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_id", sa.String(500), nullable=False),
        sa.Column("entity_type", sa.String(100), nullable=False),
        sa.Column("label", sa.String(500), nullable=False),
        sa.Column("properties", sa.JSON, server_default="{}"),
        sa.Column("severity", sa.String(20)),
        sa.Column("source", sa.String(100)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_kg_nodes_org_entity", "kg_nodes", ["organization_id", "entity_id"], unique=True)
    op.create_index("ix_kg_nodes_org_type", "kg_nodes", ["organization_id", "entity_type"])
    op.create_index("ix_kg_nodes_entity_type", "kg_nodes", ["entity_type"])

    # ── Knowledge Graph Edges ────────────────────────────────
    op.create_table(
        "kg_edges",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer, sa.ForeignKey("kg_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("kg_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship", sa.String(100), nullable=False),
        sa.Column("weight", sa.Float, server_default="1.0"),
        sa.Column("properties", sa.JSON, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_kg_edges_org_rel", "kg_edges", ["organization_id", "relationship"])
    op.create_index("ix_kg_edges_source", "kg_edges", ["source_id"])
    op.create_index("ix_kg_edges_target", "kg_edges", ["target_id"])

    # ── Prompt Templates ─────────────────────────────────────
    op.create_table(
        "prompt_templates",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("slug", sa.String(200), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("description", sa.String(500)),
        sa.Column("variables", sa.JSON, server_default="[]"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("tags", sa.JSON, server_default="[]"),
        sa.Column("metrics", sa.JSON, server_default="{}"),
        sa.Column("created_by", sa.String(200)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_prompt_org_slug_version", "prompt_templates", ["organization_id", "slug", "version"], unique=True)
    op.create_index("ix_prompt_org_slug_active", "prompt_templates", ["organization_id", "slug", "is_active"])


def downgrade() -> None:
    op.drop_table("prompt_templates")
    op.drop_table("kg_edges")
    op.drop_table("kg_nodes")

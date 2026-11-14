"""Fix agent_insights.finding_id FK to CASCADE on delete.

The original FK had no ondelete action, defaulting to RESTRICT.  This
prevented deleting findings (and therefore repos) when agent insights
existed for those findings.
"""
from alembic import op

revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agent_insights") as batch_op:
        batch_op.drop_constraint(
            "agent_insights_finding_id_fkey", type_="foreignkey"
        )
        batch_op.create_foreign_key(
            "agent_insights_finding_id_fkey",
            "findings",
            ["finding_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("agent_insights") as batch_op:
        batch_op.drop_constraint(
            "agent_insights_finding_id_fkey", type_="foreignkey"
        )
        batch_op.create_foreign_key(
            "agent_insights_finding_id_fkey",
            "findings",
            ["finding_id"],
            ["id"],
        )

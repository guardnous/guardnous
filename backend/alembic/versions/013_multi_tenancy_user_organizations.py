"""Multi-tenancy: user_organizations junction table, tenant-scoped email uniqueness.

Changes:
1. Create `user_organizations` junction table (many-to-many User↔Organization)
2. Backfill `tenant_id` on all users from their organization's tenant
3. Drop old `uq_user_email_per_org` constraint, add `uq_user_email_per_tenant`
4. Backfill `user_organizations` from existing `users.organization_id`
"""
from alembic import op
import sqlalchemy as sa

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Create junction table
    op.create_table(
        "user_organizations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("role_in_org", sa.String(50), server_default="member"),
        sa.Column("added_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("joined_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "organization_id", name="uq_user_org_membership"),
    )

    # 2. Backfill tenant_id on users from their organization's tenant
    op.execute("""
        UPDATE users
        SET tenant_id = (
            SELECT o.tenant_id FROM organizations o WHERE o.id = users.organization_id
        )
        WHERE tenant_id IS NULL AND organization_id IS NOT NULL
    """)

    # 3. Drop old email uniqueness constraint (per-org), add per-tenant
    # Try to drop — may not exist in all environments
    try:
        op.drop_constraint("uq_user_email_per_org", "users", type_="unique")
    except Exception:
        pass
    # Also try dropping legacy global unique if it exists
    try:
        op.drop_constraint("users_email_key", "users", type_="unique")
    except Exception:
        pass

    # Create per-tenant uniqueness (email unique within a tenant)
    op.create_unique_constraint("uq_user_email_per_tenant", "users", ["email", "tenant_id"])

    # 4. Backfill user_organizations from existing user→org relationships
    op.execute("""
        INSERT INTO user_organizations (user_id, organization_id, role_in_org, joined_at)
        SELECT u.id, u.organization_id, u.role, u.created_at
        FROM users u
        WHERE u.organization_id IS NOT NULL
        ON CONFLICT (user_id, organization_id) DO NOTHING
    """)


def downgrade() -> None:
    op.drop_constraint("uq_user_email_per_tenant", "users", type_="unique")
    op.create_unique_constraint("uq_user_email_per_org", "users", ["email", "organization_id"])
    op.drop_table("user_organizations")

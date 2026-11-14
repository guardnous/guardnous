"""Multi-tenant email isolation: email unique per org, not globally.

Also creates OrgSettings rows for any existing orgs missing them.
"""
from alembic import op
import sqlalchemy as sa

revision = "012"
down_revision = ("011", "011b")
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Drop the global unique constraint on users.email
    #    (PostgreSQL names it automatically as "users_email_key" or similar)
    op.execute("""
        DO $$
        DECLARE
            constraint_name text;
        BEGIN
            SELECT conname INTO constraint_name
            FROM pg_constraint
            WHERE conrelid = 'users'::regclass
              AND contype = 'u'
              AND array_length(conkey, 1) = 1
              AND conkey[1] = (
                  SELECT attnum FROM pg_attribute
                  WHERE attrelid = 'users'::regclass AND attname = 'email'
              );
            IF constraint_name IS NOT NULL THEN
                EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', constraint_name);
            END IF;
        END $$;
    """)

    # 2. Add composite unique constraint (email + organization_id)
    op.create_unique_constraint(
        "uq_user_email_per_org",
        "users",
        ["email", "organization_id"],
    )

    # 3. Ensure OrgSettings rows exist for all orgs (setup_completed=false)
    op.execute("""
        INSERT INTO org_settings (organization_id, platform_name, setup_completed)
        SELECT o.id, 'GuardNous', false
        FROM organizations o
        LEFT JOIN org_settings os ON os.organization_id = o.id
        WHERE os.id IS NULL;
    """)


def downgrade() -> None:
    op.drop_constraint("uq_user_email_per_org", "users", type_="unique")
    op.create_unique_constraint("users_email_key", "users", ["email"])

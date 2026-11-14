"""Record of changes made to cloud resources, with the state needed to undo them.

Revision ID: 028
Revises: 027
Create Date: 2026-11-13
"""
from alembic import op

revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS cloud_changes (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
            run_id INTEGER,
            rule_id VARCHAR(100) NOT NULL,
            action VARCHAR(100) NOT NULL,
            provider VARCHAR(20) NOT NULL,
            account_id VARCHAR(100) NOT NULL,
            region VARCHAR(100),
            resource_id VARCHAR(1000) NOT NULL,
            resource_name VARCHAR(500) NOT NULL,
            target JSON NOT NULL,
            before JSON,
            after JSON,
            status VARCHAR(30) NOT NULL DEFAULT 'applied',
            requested_by VARCHAR(255),
            approved_by VARCHAR(255),
            rolled_back_by VARCHAR(255),
            created_at TIMESTAMPTZ DEFAULT now(),
            rolled_back_at TIMESTAMPTZ
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_cloud_changes_id ON cloud_changes (id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cloud_changes_organization_id ON cloud_changes (organization_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS cloud_changes")

"""Signing keys for the GuardNous OIDC issuer (secretless cloud connections).

Revision ID: 029
Revises: 028
Create Date: 2026-11-13
"""
from alembic import op

revision = "029"
down_revision = "028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS oidc_signing_keys (
            id SERIAL PRIMARY KEY,
            kid VARCHAR(64) NOT NULL UNIQUE,
            public_jwk JSON NOT NULL,
            private_pem_encrypted TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS oidc_signing_keys")

"""Files in chat: attachments from the user and downloads made by the assistant.

Revision ID: 030
Revises: 029
Create Date: 2026-11-13
"""
from alembic import op

revision = "030"
down_revision = "029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS chat_files (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            message_id INTEGER REFERENCES agent_messages(id) ON DELETE CASCADE,
            kind VARCHAR(20) NOT NULL,
            filename VARCHAR(255) NOT NULL,
            content_type VARCHAR(120),
            size_bytes INTEGER NOT NULL DEFAULT 0,
            text TEXT,
            truncated BOOLEAN NOT NULL DEFAULT false,
            data BYTEA,
            created_at TIMESTAMPTZ DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_files_organization_id ON chat_files (organization_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_files_user_id ON chat_files (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_files_message_id ON chat_files (message_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS chat_files")

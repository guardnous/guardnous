"""enterprise multi-tenancy, RBAC, groups, invitations, audit

Revision ID: 005
Revises: 004
Create Date: 2026-09-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None

# 12 resources × 6 actions = 72 permissions
RESOURCES = [
    "tenants", "organizations", "users", "groups", "roles",
    "scans", "findings", "reports", "integrations", "agents",
    "settings", "audit_logs",
]
ACTIONS = ["create", "read", "update", "delete", "manage", "export"]

SYSTEM_ROLES = {
    "platform_admin": {
        "name": "Platform Admin",
        "description": "Full access across all tenants",
        "permissions": "*",  # all
    },
    "tenant_admin": {
        "name": "Tenant Admin",
        "description": "Full access within their tenant",
        "permissions": "*",
    },
    "org_admin": {
        "name": "Organization Admin",
        "description": "Full access within their organization/BU",
        "permissions": [
            "users:*", "groups:*", "scans:*", "findings:*", "reports:*",
            "integrations:*", "agents:*", "settings:read", "settings:update",
            "audit_logs:read",
        ],
    },
    "security_engineer": {
        "name": "Security Engineer",
        "description": "Scan management and finding triage",
        "permissions": [
            "scans:create", "scans:read", "scans:update", "scans:delete",
            "findings:read", "findings:update",
            "reports:create", "reports:read", "reports:update",
            "agents:create", "agents:read", "agents:update",
            "integrations:read",
        ],
    },
    "devops_engineer": {
        "name": "DevOps Engineer",
        "description": "CI/CD integration and scan execution",
        "permissions": [
            "scans:create", "scans:read",
            "findings:read",
            "reports:read",
            "integrations:create", "integrations:read", "integrations:update", "integrations:delete",
        ],
    },
    "auditor": {
        "name": "Auditor",
        "description": "Read-only access with export capability",
        "permissions": [
            f"{r}:read" for r in RESOURCES
        ] + [f"{r}:export" for r in RESOURCES],
    },
    "viewer": {
        "name": "Viewer",
        "description": "Dashboard read-only",
        "permissions": [
            "scans:read", "findings:read", "reports:read", "agents:read",
        ],
    },
}


def upgrade() -> None:
    # ─── 1. Tenants ───────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(255), unique=True, nullable=False),
        sa.Column("domain", sa.String(255)),
        sa.Column("logo_url", sa.Text),
        sa.Column("plan", sa.String(50), server_default="free"),
        sa.Column("status", sa.String(50), server_default="active"),
        sa.Column("settings", JSON, server_default="{}"),
        sa.Column("max_users", sa.Integer, server_default="50"),
        sa.Column("max_organizations", sa.Integer, server_default="10"),
        sa.Column("max_scans_per_month", sa.Integer, server_default="1000"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 2. Permissions ───────────────────────────────────
    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("resource", sa.String(100), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("resource", "action", name="uq_permission_resource_action"),
    )

    # ─── 3. Roles ─────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id", ondelete="CASCADE")),
        sa.Column("is_system", sa.Boolean, server_default="false"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_roles_tenant_id", "roles", ["tenant_id"])

    # ─── 4. Role-Permission mapping ───────────────────────
    op.create_table(
        "role_permissions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("roles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("permission_id", sa.Integer, sa.ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )

    # ─── 5. User-Role assignments ─────────────────────────
    op.create_table(
        "user_roles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("roles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id", ondelete="CASCADE")),
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id", ondelete="CASCADE")),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("assigned_by_id", sa.Integer, sa.ForeignKey("users.id")),
        sa.UniqueConstraint("user_id", "role_id", "tenant_id", "organization_id", name="uq_user_role_scope"),
    )

    # ─── 6. Groups ────────────────────────────────────────
    op.create_table(
        "groups",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id", ondelete="CASCADE")),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "slug", name="uq_group_tenant_slug"),
    )

    op.create_table(
        "group_members",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("group_id", sa.Integer, sa.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("added_by_id", sa.Integer, sa.ForeignKey("users.id")),
        sa.UniqueConstraint("group_id", "user_id", name="uq_group_member"),
    )

    op.create_table(
        "group_roles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("group_id", sa.Integer, sa.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("roles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("group_id", "role_id", name="uq_group_role"),
    )

    # ─── 7. Invitations ──────────────────────────────────
    op.create_table(
        "user_invitations",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id", ondelete="CASCADE")),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255)),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("roles.id")),
        sa.Column("token", sa.String(255), unique=True, nullable=False),
        sa.Column("status", sa.String(50), server_default="pending"),
        sa.Column("source", sa.String(50), server_default="manual"),
        sa.Column("metadata", JSON, server_default="{}"),
        sa.Column("invited_by_id", sa.Integer, sa.ForeignKey("users.id")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_user_invitations_email", "user_invitations", ["email"])
    op.create_index("ix_user_invitations_token", "user_invitations", ["token"])

    # ─── 8. Audit Log ────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id", ondelete="SET NULL")),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100)),
        sa.Column("resource_id", sa.Integer),
        sa.Column("details", JSON),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("user_agent", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_tenant_id", "audit_logs", ["tenant_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # ─── 9. Add columns to existing tables ────────────────
    op.add_column("users", sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id", ondelete="SET NULL")))
    op.add_column("users", sa.Column("status", sa.String(50), server_default="active"))
    op.add_column("users", sa.Column("invited_by_id", sa.Integer, sa.ForeignKey("users.id")))
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True)))
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    op.add_column("organizations", sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id", ondelete="SET NULL")))
    op.create_index("ix_organizations_tenant_id", "organizations", ["tenant_id"])

    # ─── 10. Seed permissions (72 rows) ───────────────────
    conn = op.get_bind()
    perm_table = sa.table(
        "permissions",
        sa.column("id", sa.Integer),
        sa.column("resource", sa.String),
        sa.column("action", sa.String),
        sa.column("description", sa.Text),
    )
    perm_rows = []
    perm_id = 1
    perm_id_map = {}
    for resource in RESOURCES:
        for action in ACTIONS:
            perm_rows.append({
                "id": perm_id,
                "resource": resource,
                "action": action,
                "description": f"{action.title()} {resource}",
            })
            perm_id_map[f"{resource}:{action}"] = perm_id
            perm_id += 1
    conn.execute(perm_table.insert(), perm_rows)

    # ─── 11. Seed system roles ────────────────────────────
    role_table = sa.table(
        "roles",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("slug", sa.String),
        sa.column("description", sa.Text),
        sa.column("is_system", sa.Boolean),
    )
    rp_table = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )

    role_id = 1
    for slug, cfg in SYSTEM_ROLES.items():
        conn.execute(role_table.insert().values(
            id=role_id, name=cfg["name"], slug=slug,
            description=cfg["description"], is_system=True,
        ))
        # Assign permissions
        if cfg["permissions"] == "*":
            for pid in perm_id_map.values():
                conn.execute(rp_table.insert().values(role_id=role_id, permission_id=pid))
        else:
            for perm_str in cfg["permissions"]:
                if perm_str.endswith(":*"):
                    resource = perm_str.split(":")[0]
                    for action in ACTIONS:
                        key = f"{resource}:{action}"
                        if key in perm_id_map:
                            conn.execute(rp_table.insert().values(
                                role_id=role_id, permission_id=perm_id_map[key]
                            ))
                elif perm_str in perm_id_map:
                    conn.execute(rp_table.insert().values(
                        role_id=role_id, permission_id=perm_id_map[perm_str]
                    ))
        role_id += 1

    # ─── 12. Migrate existing data ────────────────────────
    # Create a "Default" tenant and assign existing orgs/users to it
    tenant_t = sa.table(
        "tenants",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("slug", sa.String),
        sa.column("plan", sa.String),
    )
    conn.execute(tenant_t.insert().values(
        id=1000, name="Default", slug="default", plan="enterprise",
    ))

    # Update existing orgs and users
    conn.execute(sa.text("UPDATE organizations SET tenant_id = 1000 WHERE tenant_id IS NULL"))
    conn.execute(sa.text("UPDATE users SET tenant_id = 1000 WHERE tenant_id IS NULL"))
    conn.execute(sa.text("UPDATE users SET status = 'active' WHERE status IS NULL"))

    # ─── 13. Assign platform_admin role to existing admin/superadmin users ─
    user_roles_t = sa.table(
        "user_roles",
        sa.column("user_id", sa.Integer),
        sa.column("role_id", sa.Integer),
        sa.column("tenant_id", sa.Integer),
    )
    admin_users = conn.execute(
        sa.text("SELECT id FROM users WHERE role IN ('admin', 'superadmin')")
    ).fetchall()
    for row in admin_users:
        conn.execute(user_roles_t.insert().values(
            user_id=row[0], role_id=1, tenant_id=1000,  # role_id=1 = platform_admin
        ))


def downgrade() -> None:
    op.drop_index("ix_organizations_tenant_id", "organizations")
    op.drop_column("organizations", "tenant_id")
    op.drop_index("ix_users_tenant_id", "users")
    op.drop_column("users", "last_login_at")
    op.drop_column("users", "invited_by_id")
    op.drop_column("users", "status")
    op.drop_column("users", "tenant_id")
    op.drop_table("audit_logs")
    op.drop_table("user_invitations")
    op.drop_table("group_roles")
    op.drop_table("group_members")
    op.drop_table("groups")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("permissions")
    op.drop_table("tenants")

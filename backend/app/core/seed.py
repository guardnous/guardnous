"""
Startup seed — ensures required base data exists on every boot.

Idempotent: checks existence before inserting.  Runs after Alembic migrations.
"""
import logging
import secrets
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import async_session

logger = logging.getLogger(__name__)

RESOURCES = [
    "tenants", "organizations", "users", "groups", "roles",
    "scans", "findings", "reports", "integrations", "agents",
    "settings", "audit_logs",
]
ACTIONS = ["create", "read", "update", "delete", "manage", "export"]

SYSTEM_ROLES = {
    "platform_admin": {
        "name": "Platform Admin",
        "description": "Full access across all organizations",
        "permissions": "*",
    },
    "tenant_admin": {
        "name": "Organization Admin",
        "description": "Full access within their organization",
        "permissions": "*",
    },
    "org_admin": {
        "name": "Team Admin",
        "description": "Full access within their team",
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
            "scans:create", "scans:read", "scans:update", "scans:delete", "scans:export",
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
            "integrations:create", "integrations:read", "integrations:update",
            "integrations:delete",
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


async def ensure_seed_data() -> None:
    """Run on every startup — idempotent inserts for required base data."""
    async with async_session() as db:
        try:
            # Enterprise stage columns on scans table (idempotent)
            await _migrate_scan_columns(db)

            await _seed_default_tenant(db)
            perm_map = await _seed_permissions(db)
            await _seed_system_roles(db, perm_map)
            await _seed_admin_user(db)
            await _seed_admin_role_assignment(db)
            await _backfill_finding_organizations(db)
            await _sync_builtin_policy_rules(db)
            await db.commit()
            logger.info("Seed data verified / applied successfully")
        except Exception:
            await db.rollback()
            logger.exception("Seed data error — rolling back")
            raise


async def _sync_builtin_policy_rules(db: AsyncSession) -> None:
    """Give built-in policies the matching rules that ship with this version.

    Organizations keep their own enabled/enforced settings; only the rule
    definitions are replaced, so a fix to a built-in policy reaches everyone.
    """
    from sqlalchemy import select

    from app.models.governance import SecurityPolicy
    from app.services.security.policy_engine import BUILT_IN_BY_ID, builtin_policy_rules

    policies = (await db.execute(
        select(SecurityPolicy).where(SecurityPolicy.is_builtin == True)  # noqa: E712
    )).scalars().all()
    updated = 0
    for policy in policies:
        rules = policy.rules if isinstance(policy.rules, list) else []
        definition = BUILT_IN_BY_ID.get(rules[0].get("policy_id")) if rules and isinstance(rules[0], dict) else None
        if definition and policy.rules != builtin_policy_rules(definition):
            policy.rules = builtin_policy_rules(definition)
            updated += 1
    if updated:
        logger.info("Updated matching rules on %d built-in policies", updated)


async def _backfill_finding_organizations(db: AsyncSession) -> None:
    """Give findings saved without an organization their scan's organization.

    Findings created before the Finding before_insert hook existed have a NULL
    organization_id and are invisible to org-scoped queries.
    """
    result = await db.execute(text(
        "UPDATE findings SET organization_id = "
        "(SELECT s.organization_id FROM scans s WHERE s.id = findings.scan_id) "
        "WHERE organization_id IS NULL"
    ))
    if result.rowcount:
        logger.info("Back-filled organization_id on %d findings", result.rowcount)


async def _migrate_scan_columns(db: AsyncSession) -> None:
    """Add enterprise stage columns to scans table if missing."""
    _COLS = [
        ("secrets_found", "INTEGER DEFAULT 0"),
        ("dependencies_analyzed", "INTEGER DEFAULT 0"),
        ("policies_evaluated", "INTEGER DEFAULT 0"),
        ("policies_passed", "INTEGER DEFAULT 0"),
        ("policies_failed", "INTEGER DEFAULT 0"),
        ("compliance_frameworks", "JSON"),
        ("notifications_sent", "BOOLEAN DEFAULT FALSE"),
        ("stage_details", "JSON"),
        ("cancelled_by", "VARCHAR(255)"),
        ("timeout_seconds", "INTEGER DEFAULT 3600"),
    ]
    for col_name, col_type in _COLS:
        try:
            await db.execute(text(
                f"ALTER TABLE scans ADD COLUMN IF NOT EXISTS {col_name} {col_type}"
            ))
        except Exception:
            pass  # column already exists or DB doesn't support IF NOT EXISTS
    await db.flush()


async def _seed_default_tenant(db: AsyncSession) -> None:
    row = (await db.execute(text("SELECT 1 FROM tenants WHERE id = 1000"))).fetchone()
    if not row:
        await db.execute(text(
            "INSERT INTO tenants (id, name, slug, plan, status, max_users, max_organizations, max_scans_per_month, is_active) "
            "VALUES (1000, 'Default', 'default', 'enterprise', 'active', 1000, 100, 10000, true)"
        ))
        logger.info("Seeded Default organization (id=1000)")


async def _seed_permissions(db: AsyncSession) -> dict[str, int]:
    """Ensure 72 permissions exist; return {resource:action → id} map."""
    perm_map: dict[str, int] = {}
    for resource in RESOURCES:
        for action in ACTIONS:
            key = f"{resource}:{action}"
            row = (await db.execute(text(
                "SELECT id FROM permissions WHERE resource = :r AND action = :a"
            ), {"r": resource, "a": action})).fetchone()
            if row:
                perm_map[key] = row[0]
            else:
                result = await db.execute(text(
                    "INSERT INTO permissions (resource, action, description) "
                    "VALUES (:r, :a, :d) RETURNING id"
                ), {"r": resource, "a": action, "d": f"{action.title()} {resource}"})
                perm_map[key] = result.fetchone()[0]
    return perm_map


async def _seed_system_roles(db: AsyncSession, perm_map: dict[str, int]) -> None:
    """Ensure 7 system roles and their permission mappings exist."""
    role_id = 0
    for slug, cfg in SYSTEM_ROLES.items():
        role_id += 1
        row = (await db.execute(text(
            "SELECT id FROM roles WHERE slug = :s AND is_system = true"
        ), {"s": slug})).fetchone()

        if not row:
            result = await db.execute(text(
                "INSERT INTO roles (id, name, slug, description, is_system) "
                "VALUES (:id, :n, :s, :d, true) RETURNING id"
            ), {"id": role_id, "n": cfg["name"], "s": slug, "d": cfg["description"]})
            rid = result.fetchone()[0]
        else:
            rid = row[0]

        # Resolve permission keys
        perm_ids: set[int] = set()
        if cfg["permissions"] == "*":
            perm_ids = set(perm_map.values())
        else:
            for perm_str in cfg["permissions"]:
                if perm_str.endswith(":*"):
                    resource = perm_str.split(":")[0]
                    for action in ACTIONS:
                        k = f"{resource}:{action}"
                        if k in perm_map:
                            perm_ids.add(perm_map[k])
                elif perm_str in perm_map:
                    perm_ids.add(perm_map[perm_str])

        # Insert missing role-permission mappings
        existing = (await db.execute(text(
            "SELECT permission_id FROM role_permissions WHERE role_id = :rid"
        ), {"rid": rid})).fetchall()
        existing_ids = {r[0] for r in existing}
        for pid in perm_ids - existing_ids:
            await db.execute(text(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (:rid, :pid)"
            ), {"rid": rid, "pid": pid})

    # Reset sequences after explicit-ID inserts to avoid duplicate key errors
    # Sequences only exist on PostgreSQL
    if db.get_bind().dialect.name != "postgresql":
        return
    for seq, table in [
        ("roles_id_seq", "roles"),
        ("permissions_id_seq", "permissions"),
        ("tenants_id_seq", "tenants"),
    ]:
        await db.execute(text(
            f"SELECT setval('{seq}', COALESCE((SELECT MAX(id) FROM {table}), 1))"
        ))
    logger.info("Reset auto-increment sequences for roles, permissions, organizations")


async def _seed_admin_user(db: AsyncSession) -> None:
    """Skip admin seeding — the setup wizard creates the first admin interactively.

    Only seeds if GUARDNOUS_SEED_ADMIN=true env var is set (for dev/CI).
    """
    import os
    if os.getenv("GUARDNOUS_SEED_ADMIN", "").lower() not in ("1", "true", "yes"):
        logger.info("Skipping admin seed — setup wizard will create the first admin")
        return

    from app.core.security import get_password_hash

    admin_email = "admin@guardnous.com"
    # Only the Default tenant's account is the seeded admin. The same email
    # registered in another tenant must never be promoted.
    row = (await db.execute(text(
        "SELECT id FROM users WHERE email = :e AND tenant_id = 1000"
    ), {"e": admin_email})).fetchone()
    if row:
        await db.execute(text(
            "UPDATE users SET role = 'superadmin' "
            "WHERE email = :e AND tenant_id = 1000 AND role != 'superadmin'"
        ), {"e": admin_email})
        # An admin seeded by an earlier version has no status or flags (the insert
        # skipped the column defaults). Fill only what is missing; never overwrite.
        await db.execute(text(
            "UPDATE users SET status = COALESCE(status, 'active'), "
            "totp_enabled = COALESCE(totp_enabled, false), "
            "totp_confirmed = COALESCE(totp_confirmed, false), "
            "email_verified = COALESCE(email_verified, true) "
            "WHERE email = :e AND tenant_id = 1000 AND (status IS NULL OR totp_enabled IS NULL "
            "OR totp_confirmed IS NULL OR email_verified IS NULL)"
        ), {"e": admin_email})
        return

    # Ensure demo org exists
    org_row = (await db.execute(text(
        "SELECT id FROM organizations WHERE slug = 'demo'"
    ))).fetchone()
    if not org_row:
        result = await db.execute(text(
            "INSERT INTO organizations (name, slug, subdomain, admin_email, plan, status, schema_name, webhook_secret, tenant_id, is_active) "
            "VALUES ('GuardNous Demo', 'demo', 'demo', :email, 'enterprise', 'active', 'tenant_demo', :secret, 1000, true) "
            "RETURNING id"
        ), {"email": admin_email, "secret": secrets.token_hex(32)})
        org_id = result.fetchone()[0]
        logger.info("Seeded demo team (id=%s)", org_id)
    else:
        org_id = org_row[0]

    from app.core.config import settings

    password = settings.INITIAL_ADMIN_PASSWORD
    generated = not password
    if generated:
        password = generate_admin_password()

    await db.execute(text(
        # Raw SQL skips the model's column defaults, so every flag is set here.
        # The seeded address has no mailbox, so it is marked verified.
        "INSERT INTO users (email, hashed_password, full_name, role, organization_id, is_active, tenant_id, "
        "status, totp_enabled, totp_confirmed, email_verified) "
        "VALUES (:email, :pw, 'Admin User', 'superadmin', :org_id, true, :tid, 'active', false, false, true)"
    ), {"email": admin_email, "pw": get_password_hash(password), "org_id": org_id, "tid": 1000})
    logger.info("Seeded admin user: %s", admin_email)
    if generated:
        # The only place this password ever appears. A configured password is never logged.
        logger.warning(
            "\n"
            "==================== INITIAL ADMIN PASSWORD ====================\n"
            "  Email:    %s\n"
            "  Password: %s\n"
            "  This password is shown only once. Sign in and change it now.\n"
            "  Set INITIAL_ADMIN_PASSWORD to choose the password yourself.\n"
            "================================================================",
            admin_email, password,
        )


def generate_admin_password() -> str:
    """A random password that also passes the registration complexity rule."""
    # token_urlsafe may lack a digit, a capital or a symbol; the suffix guarantees one of each.
    return secrets.token_urlsafe(18) + "".join(
        secrets.choice(group) for group in ("abcdefghijkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%*?")
    )


async def _seed_admin_role_assignment(db: AsyncSession) -> None:
    """Ensure admin/superadmin users have platform_admin role."""
    admin_users = (await db.execute(text(
        "SELECT id FROM users WHERE role IN ('admin', 'superadmin')"
    ))).fetchall()

    for row in admin_users:
        uid = row[0]
        exists = (await db.execute(text(
            "SELECT 1 FROM user_roles WHERE user_id = :uid AND role_id = 1"
        ), {"uid": uid})).fetchone()
        if not exists:
            await db.execute(text(
                "INSERT INTO user_roles (user_id, role_id, tenant_id) "
                "VALUES (:uid, 1, 1000)"
            ), {"uid": uid})
            logger.info("Assigned platform_admin role to user %s", uid)

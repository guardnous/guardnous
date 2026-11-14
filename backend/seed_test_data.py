"""Reset the database and load a small, realistic test data set.

    python seed_test_data.py --reset        # wipe everything, then seed
    python seed_test_data.py                # seed only (fails if the users exist)

DEVELOPMENT ONLY. ``--reset`` deletes every row in every table.

Everything is created through the application's own API and scanners, so the
findings, compliance results and policy violations are real output for the
bundled sample IaC files, not hand-written rows. Nothing is created for
features that need outside credentials (VCS integrations, cloud accounts).
"""
import argparse
import asyncio
import os
import sys
from pathlib import Path

os.environ["RATE_LIMIT_ENABLED"] = "false"  # the seeder logs in many times

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import select, text  # noqa: E402

# One password for every seeded account: SEED_PASSWORD if set, otherwise a random
# one that is printed at the end. No fixed default, so a seeded installation never
# has accounts with a password that is written in the repository.
PASSWORD = os.environ.get("SEED_PASSWORD") or ("Gn#" + __import__("secrets").token_urlsafe(15) + "9a")
SAMPLES = Path(__file__).parent / "sample_files"

SUPERADMIN = ("root@guardnous-platform.test", "Platform Root")
PLATFORM_APPROVER = ("approver@guardnous-platform.test", "Platform Approver")

TENANTS = [
    {
        "name": "Acme Corp",
        "org": "Acme Security",
        "admin": ("admin@acme-corp.test", "Alice Admin"),
        "members": [
            ("lead@acme-corp.test", "Liam Lead", "security_lead"),
            ("analyst@acme-corp.test", "Ana Analyst", "security_analyst"),
            ("dev@acme-corp.test", "Dev Developer", "developer"),
            ("viewer@acme-corp.test", "Vera Viewer", "viewer"),
        ],
        "scans": [
            ("terraform", "insecure.tf"),
            ("terraform", "complex_infra.tf"),
            ("cloudformation", "insecure.yaml"),
            ("bicep", "insecure.bicep"),
        ],
    },
    {
        "name": "Globex",
        "org": "Globex SecOps",
        "admin": ("admin@globex.test", "Gary Globex"),
        "members": [("analyst@globex.test", "Gina Analyst", "security_analyst")],
        "scans": [("cloudformation", "complex_infra.yaml")],
    },
]


async def reset_database() -> None:
    from app.core.database import async_session

    async with async_session() as db:
        tables = (await db.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
        ))).scalars().all()
        await db.execute(text(
            "TRUNCATE TABLE " + ", ".join(f'"{t}"' for t in tables) + " RESTART IDENTITY CASCADE"
        ))
        await db.commit()
    print(f"reset: truncated {len(tables)} tables")


async def login(client: AsyncClient, email: str) -> dict:
    resp = await client.post("/api/v1/auth/login", data={"username": email, "password": PASSWORD})
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def add_member(tenant_id: int, org_id: int, email: str, full_name: str, role: str) -> None:
    from app.core.database import async_session
    from app.core.rbac import sync_user_role
    from app.core.security import get_password_hash
    from app.models.rbac import UserRole
    from app.models.user import User
    from app.models.user_organization import UserOrganization

    async with async_session() as db:
        user = User(
            email=email, hashed_password=get_password_hash(PASSWORD), full_name=full_name,
            role=role, organization_id=org_id, tenant_id=tenant_id, status="active", email_verified=True,
        )
        db.add(user)
        await db.flush()
        await sync_user_role(db, user, role)
        db.add(UserOrganization(user_id=user.id, organization_id=org_id, role_in_org="member"))
        await db.flush()
        granted = (await db.execute(select(UserRole).where(UserRole.user_id == user.id))).scalars().first()
        if not granted:
            raise RuntimeError(f"no system role '{role}' exists, {email} would have no permissions")
        await db.commit()


async def create_superadmin() -> None:
    """Installation superuser, in the built-in Default tenant (id 1000)."""
    from app.core.database import async_session
    from app.core.rbac import sync_user_role
    from app.core.security import get_password_hash
    from app.models.org_settings import OrgSettings
    from app.models.organization import Organization
    from app.models.user import User
    from app.models.user_organization import UserOrganization

    email, full_name = SUPERADMIN
    async with async_session() as db:
        org = Organization(name="GuardNous Platform", slug="guardnous-platform", tenant_id=1000,
                           admin_email=email, plan_tier="enterprise")
        db.add(org)
        await db.flush()
        user = User(
            email=email, hashed_password=get_password_hash(PASSWORD), full_name=full_name,
            role="superadmin", organization_id=org.id, tenant_id=1000, status="active", email_verified=True,
        )
        db.add(user)
        await db.flush()
        await sync_user_role(db, user, "superadmin")
        db.add(UserOrganization(user_id=user.id, organization_id=org.id, role_in_org="admin"))
        db.add(OrgSettings(organization_id=org.id, setup_completed=True))
        await db.commit()
        org_id = org.id
    # A second admin in the same organization, so external agent actions the
    # superadmin requests have someone else to approve them.
    await add_member(1000, org_id, PLATFORM_APPROVER[0], PLATFORM_APPROVER[1], "platform_admin")


async def finish_setup(org_id: int, admin_email: str) -> None:
    """Mark the first-login wizard done and the admin's email verified."""
    from app.core.database import async_session
    from app.models.org_settings import OrgSettings
    from app.models.user import User

    async with async_session() as db:
        row = (await db.execute(select(OrgSettings).where(OrgSettings.organization_id == org_id))).scalar_one()
        row.setup_completed = True
        user = (await db.execute(select(User).where(User.email == admin_email))).scalar_one()
        user.email_verified = True
        await db.commit()


def check(resp, what: str):
    if resp.status_code >= 400:
        raise RuntimeError(f"{what} failed: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json() if resp.content else None


async def seed_tenant(client: AsyncClient, spec: dict) -> dict:
    admin_email, admin_name = spec["admin"]
    user = check(await client.post("/api/v1/auth/register", json={
        "email": admin_email, "password": PASSWORD, "full_name": admin_name,
        "organization_name": spec["org"], "tenant_name": spec["name"],
    }), f"register {admin_email}")
    tenant_id, org_id = user["tenant_id"], user["organization_id"]
    await finish_setup(org_id, admin_email)
    for email, full_name, role in spec["members"]:
        await add_member(tenant_id, org_id, email, full_name, role)

    headers = await login(client, admin_email)
    findings = 0
    for scan_type, file_name in spec["scans"]:
        scan = check(await client.post("/api/v1/scans", headers=headers, json={
            "scan_type": scan_type, "file_name": file_name, "source": (SAMPLES / file_name).read_text(),
        }), f"scan {file_name}")
        if scan["status"] != "completed":
            raise RuntimeError(f"scan of {file_name} ended as {scan['status']}")
        findings += scan["findings_count"]

    check(await client.post("/api/v1/governance/frameworks/seed", headers=headers), "load frameworks")
    check(await client.post("/api/v1/governance/policies/seed", headers=headers), "load policies")
    custom = check(await client.post("/api/v1/governance/policies", headers=headers, json={
        "name": "No hardcoded secrets",
        "description": "Any finding in the secrets category violates this policy.",
        "severity": "critical", "is_enforced": True,
        "rules": [{"categories": ["secrets"]}],
    }), "create policy")
    evaluation = check(await client.post("/api/v1/governance/policies/evaluate", headers=headers), "evaluate policies")

    notes = []
    # A pending exception requested by the analyst, for an admin to approve or reject.
    analyst = next((m[0] for m in spec["members"] if m[2] == "security_analyst"), None)
    if analyst:
        resp = await client.post("/api/v1/governance/exceptions", headers=await login(client, analyst), json={
            "title": "Legacy deploy key in sample repo", "severity": "high",
            "justification": "Key is scoped to a sandbox account and is being rotated this sprint.",
            "compensating_controls": "Sandbox account has no production access.",
            "policy_id": custom["id"],
        })
        notes.append("pending exception requested by the analyst" if resp.status_code < 400
                     else f"exception not created (HTTP {resp.status_code}: {resp.text[:120]})")

    resp = await client.post("/api/v1/report-schedules", headers=headers, json={
        "name": "Weekly security report", "report_type": "security",
        "cron_expression": "0 8 * * 1", "recipients": [admin_email],
    })
    check(resp, "create report schedule")

    return {"tenant": spec["name"], "tenant_id": tenant_id, "org_id": org_id,
            "scans": len(spec["scans"]), "findings": findings,
            "violations": (evaluation or {}).get("violations_created", evaluation), "notes": notes}


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="delete ALL data first")
    args = parser.parse_args()

    from app.core.config import settings
    from app.core.migrations import bootstrap_schema
    from app.core.seed import ensure_seed_data
    from app.main import app

    if settings.ENVIRONMENT == "production":
        print("refusing to run with ENVIRONMENT=production", file=sys.stderr)
        return 2
    print(f"database: {settings.DATABASE_URL.split('@')[-1]}")

    print(f"schema: {bootstrap_schema()}")
    if args.reset:
        await reset_database()
    await ensure_seed_data()  # default tenant, permissions, system roles
    await create_superadmin()

    results = []
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://seed") as client:
        for spec in TENANTS:
            results.append(await seed_tenant(client, spec))

    print("\nSeeded:")
    for r in results:
        print(f"  {r['tenant']:<10} tenant={r['tenant_id']} org={r['org_id']} "
              f"scans={r['scans']} findings={r['findings']} violations={r['violations']}")
        for note in r["notes"]:
            print(f"             - {note}")
    print(f"\nPassword for every account: {PASSWORD}\n")
    print(f"  {'installation superadmin':<26} {SUPERADMIN[0]}")
    print(f"  {'platform approver':<26} {PLATFORM_APPROVER[0]}")
    for spec in TENANTS:
        print(f"  {spec['name'] + ' tenant admin':<26} {spec['admin'][0]}")
        for email, _name, role in spec["members"]:
            print(f"  {spec['name'] + ' ' + role:<26} {email}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

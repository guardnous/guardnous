"""One-time seed script: create a demo organization and its administrator.

The password comes from the ADMIN_PASSWORD environment variable. There is no
default: a password that is printed in a repository is known to everyone.
Normal installations do not need this script; the application creates the
administrator itself (see INITIAL_ADMIN_PASSWORD in .env.example).
"""
import asyncio
import os
import secrets
import sys

from app.core.database import async_session
from app.core.security import get_password_hash
from app.models.organization import Organization
from app.models.user import User


async def seed():
    password = os.environ.get("ADMIN_PASSWORD", "")
    if len(password) < 12:
        sys.exit("Set ADMIN_PASSWORD (at least 12 characters) before running this script.")
    async with async_session() as db:
        org = Organization(
            name="GuardNous Demo",
            slug="demo",
            subdomain="demo",
            admin_email="admin@guardnous.com",
            plan="enterprise",
            status="active",
            schema_name="tenant_demo",
            webhook_secret=secrets.token_hex(32),
        )
        db.add(org)
        await db.flush()
        await db.refresh(org)

        user = User(
            email="admin@guardnous.com",
            hashed_password=get_password_hash(password),
            full_name="Admin User",
            role="superadmin",
            organization_id=org.id,
        )
        db.add(user)
        await db.commit()
        print(f"OK  org_id={org.id}  user_id={user.id}")
        print("Administrator: admin@guardnous.com (password: the value of ADMIN_PASSWORD)")


if __name__ == "__main__":
    asyncio.run(seed())

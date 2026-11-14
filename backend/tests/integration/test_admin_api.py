"""Integration tests for admin API endpoints."""
import pytest
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test.db"
os.environ["DATABASE_URL_SYNC"] = "sqlite:///test.db"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["SUPER_ADMIN_EMAIL"] = "admin@guardnous.com"

from httpx import AsyncClient, ASGITransport
from app.main import app


# Database setup and RBAC seeding come from the autouse fixture in tests/conftest.py.


@pytest.fixture
def admin_headers():
    """Headers with a super admin token."""
    # First register via API then use token
    return {}


PASSWORD = "TestPassword123!"


async def _register_and_login(client: AsyncClient, email: str) -> str:
    resp = await client.post("/api/v1/auth/register", json={
        "email": email,
        "password": PASSWORD,
        "full_name": "Test User",
    })
    assert resp.status_code == 201, resp.text
    login_resp = await client.post("/api/v1/auth/login", data={
        "username": email,
        "password": PASSWORD,
    })
    return login_resp.json()["access_token"]


async def _register_and_get_token(client: AsyncClient) -> str:
    """Register a user, make them an installation superuser, and return a token."""
    from sqlalchemy import update
    from app.core.database import async_session
    from app.models.user import User

    token = await _register_and_login(client, "root@guardnous-test.com")
    async with async_session() as db:
        await db.execute(
            update(User).where(User.email == "root@guardnous-test.com").values(role="superadmin")
        )
        await db.commit()
    return token


class TestAdminOrganizations:
    @pytest.mark.asyncio
    async def test_create_organization(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_get_token(client)
            headers = {"Authorization": f"Bearer {token}"}

            resp = await client.post("/api/admin/organizations", json={
                "name": "Palo Alto Networks",
                "subdomain": "paloalto",
                "admin_email": "admin@paloalto.com",
                "plan": "enterprise",
            }, headers=headers)

            assert resp.status_code == 201
            data = resp.json()
            assert data["name"] == "Palo Alto Networks"
            assert data["subdomain"] == "paloalto"
            assert data["status"] == "pending"
            assert data["schema_name"] == "tenant_paloalto"

    @pytest.mark.asyncio
    async def test_create_duplicate_subdomain(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_get_token(client)
            headers = {"Authorization": f"Bearer {token}"}

            await client.post("/api/admin/organizations", json={
                "name": "Org A", "subdomain": "test-org", "admin_email": "a@test.com",
            }, headers=headers)

            resp = await client.post("/api/admin/organizations", json={
                "name": "Org B", "subdomain": "test-org", "admin_email": "b@test.com",
            }, headers=headers)

            assert resp.status_code == 400
            assert "already exists" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_organizations(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_get_token(client)
            headers = {"Authorization": f"Bearer {token}"}

            await client.post("/api/admin/organizations", json={
                "name": "Org 1", "subdomain": "org1", "admin_email": "a@org1.com",
            }, headers=headers)
            await client.post("/api/admin/organizations", json={
                "name": "Org 2", "subdomain": "org2", "admin_email": "a@org2.com",
            }, headers=headers)

            resp = await client.get("/api/admin/organizations", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            # total includes the admin's own org + 2 new orgs
            assert data["total"] >= 2

    @pytest.mark.asyncio
    async def test_non_admin_rejected(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # A self-registered user is not an installation superuser, even
            # when they register with the well-known admin address.
            token = await _register_and_login(client, "admin@guardnous.com")
            headers = {"Authorization": f"Bearer {token}"}

            resp = await client.post("/api/admin/organizations", json={
                "name": "Test", "subdomain": "test", "admin_email": "x@test.com",
            }, headers=headers)

            assert resp.status_code == 403


class TestOnboarding:
    @pytest.mark.asyncio
    async def test_create_and_use_onboarding_token(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_get_token(client)
            headers = {"Authorization": f"Bearer {token}"}

            # Create org
            org_resp = await client.post("/api/admin/organizations", json={
                "name": "Acme Corp",
                "subdomain": "acme",
                "admin_email": "admin@acme.com",
            }, headers=headers)
            org_id = org_resp.json()["id"]

            # Generate onboarding token
            token_resp = await client.post(
                f"/api/admin/organizations/{org_id}/onboarding-token",
                headers=headers,
            )
            assert token_resp.status_code == 201
            onboarding_token = token_resp.json()["token"]
            assert token_resp.json()["onboarding_url"]

            # Validate token (public, no auth)
            validate_resp = await client.get(f"/api/admin/onboarding/validate/{onboarding_token}")
            assert validate_resp.status_code == 200
            assert validate_resp.json()["valid"] is True
            assert validate_resp.json()["organization_name"] == "Acme Corp"

            # Complete onboarding
            complete_resp = await client.post("/api/admin/onboarding/complete", json={
                "token": onboarding_token,
                "password": "AcmeAdmin123!",
                "full_name": "Acme Admin",
                "vcs_type": "github",
            })
            assert complete_resp.status_code == 200
            assert complete_resp.json()["success"] is True
            assert complete_resp.json()["access_token"]

            # Token should now be invalid
            validate_resp2 = await client.get(f"/api/admin/onboarding/validate/{onboarding_token}")
            assert validate_resp2.json()["valid"] is False

    @pytest.mark.asyncio
    async def test_invalid_onboarding_token(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/admin/onboarding/validate/fake-token-12345")
            assert resp.status_code == 200
            assert resp.json()["valid"] is False

    @pytest.mark.asyncio
    async def test_complete_with_invalid_token(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/admin/onboarding/complete", json={
                "token": "fake-token",
                "password": "Test12345",
                "full_name": "Nobody",
            })
            assert resp.status_code == 400

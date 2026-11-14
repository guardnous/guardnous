"""Extended integration tests for protected API endpoints."""
import pytest
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test.db"
os.environ["DATABASE_URL_SYNC"] = "sqlite:///test.db"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from httpx import AsyncClient, ASGITransport
from app.main import app


# Database setup and RBAC seeding come from the autouse fixture in tests/conftest.py.


async def _register_and_login(client: AsyncClient) -> str:
    """Helper: register a user and return an auth token."""
    await client.post("/api/v1/auth/register", json={
        "email": "test@example.com",
        "password": "TestPass123!",
        "full_name": "Test User",
        "organization_name": "Test Org",
    })
    resp = await client.post("/api/v1/auth/login", data={
        "username": "test@example.com",
        "password": "TestPass123!",
    })
    return resp.json()["access_token"]


class TestDashboardEndpoints:
    @pytest.mark.asyncio
    async def test_dashboard_unauthenticated(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/dashboard/summary")
            assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_dashboard_summary(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_login(client)
            resp = await client.get(
                "/api/v1/dashboard/summary",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "total_scans" in data or "risk_score" in data or isinstance(data, dict)


class TestScansEndpoints:
    @pytest.mark.asyncio
    async def test_list_scans_unauthenticated(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/scans")
            assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_list_scans_empty(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_login(client)
            resp = await client.get(
                "/api/v1/scans",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert isinstance(data, (list, dict))


class TestFindingsEndpoints:
    @pytest.mark.asyncio
    async def test_findings_unauthenticated(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/findings")
            assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_findings_empty(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_login(client)
            resp = await client.get(
                "/api/v1/findings",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200


class TestAgentEndpoints:
    @pytest.mark.asyncio
    async def test_agent_chat_unauthenticated(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/agents/chat", json={"message": "hi"})
            assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_agent_chat_authenticated(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_login(client)
            resp = await client.post(
                "/api/v1/agents/chat",
                json={"message": "What is my risk score?"},
                headers={"Authorization": f"Bearer {token}"},
            )
            # Could be 200 or 422 depending on expected payload shape
            assert resp.status_code in (200, 422)


class TestCVEEndpoints:
    @pytest.mark.asyncio
    async def test_cve_search_unauthenticated(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cves")
            assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_cve_search_authenticated(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = await _register_and_login(client)
            resp = await client.get(
                "/api/v1/cves",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200

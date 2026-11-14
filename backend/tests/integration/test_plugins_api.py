"""Integration tests for the Plugins API."""
import pytest
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test.db"
os.environ["DATABASE_URL_SYNC"] = "sqlite:///test.db"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from httpx import AsyncClient, ASGITransport
from app.main import app


# Database setup and RBAC seeding come from the autouse fixture in tests/conftest.py.


async def get_auth_headers(client: AsyncClient) -> dict:
    await client.post("/api/v1/auth/register", json={
        "email": "admin@test.com",
        "password": "Test123!",
        "full_name": "Test Admin",
        "organization_name": "Test Org",
    })
    resp = await client.post("/api/v1/auth/login", data={
        "username": "admin@test.com",
        "password": "Test123!",
    })
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestPluginsAPI:
    @pytest.mark.asyncio
    async def test_list_plugins(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/plugins", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert "plugins" in data
            assert "total" in data
            assert data["total"] > 0
            # Check schema fields
            plugin = data["plugins"][0]
            assert "plugin_type" in plugin
            assert plugin["plugin_type"] in ("native", "external")
            assert "severity_levels" in plugin
            assert isinstance(plugin["severity_levels"], list)
            assert "total_rules" in plugin
            assert isinstance(plugin["total_rules"], int)

    @pytest.mark.asyncio
    async def test_get_plugin_detail(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/plugins/native_terraform", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["metadata"]["name"] == "native_terraform"
            assert data["plugin_type"] in ("native", "external")
            assert "severity_levels" in data

    @pytest.mark.asyncio
    async def test_get_plugin_not_found(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/plugins/nonexistent", headers=headers)
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_plugin_health(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/plugins/native_terraform/health", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert "available" in data

    @pytest.mark.asyncio
    async def test_toggle_plugin(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.post(
                "/api/v1/plugins/native_terraform/toggle",
                headers=headers,
                json={"enabled": False},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["name"] == "native_terraform"

    @pytest.mark.asyncio
    async def test_native_vs_external_counts(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/plugins", headers=headers)
            data = resp.json()
            assert data["native_count"] >= 4
            assert data["total"] == data["native_count"] + data["external_count"]

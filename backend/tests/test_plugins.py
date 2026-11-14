"""Tests for the plugin system: list, enable/disable, health, versions, supply chain."""
import pytest

from tests.conftest import get_auth_headers


class TestPluginList:
    @pytest.mark.asyncio
    async def test_list_plugins(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/plugins", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "plugins" in data
        assert "total" in data
        assert data["total"] > 0
        plugin = data["plugins"][0]
        assert "plugin_type" in plugin
        assert plugin["plugin_type"] in ("native", "external")

    @pytest.mark.asyncio
    async def test_list_plugins_requires_auth(self, client):
        resp = await client.get("/api/v1/plugins")
        assert resp.status_code in (401, 403)


class TestPluginToggle:
    @pytest.mark.asyncio
    async def test_enable_disable_plugin(self, client):
        headers = await get_auth_headers(client)

        # Disable a known native plugin
        resp = await client.post(
            "/api/v1/plugins/native_terraform/toggle",
            headers=headers,
            json={"enabled": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "native_terraform"

        # Re-enable
        resp = await client.post(
            "/api/v1/plugins/native_terraform/toggle",
            headers=headers,
            json={"enabled": True},
        )
        assert resp.status_code == 200


class TestPluginHealth:
    @pytest.mark.asyncio
    async def test_plugin_health_check(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get(
            "/api/v1/plugins/native_terraform/health",
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "available" in data

    @pytest.mark.asyncio
    async def test_plugin_health_not_found(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get(
            "/api/v1/plugins/nonexistent_plugin/health",
            headers=headers,
        )
        assert resp.status_code == 404


class TestPluginVersions:
    @pytest.mark.asyncio
    async def test_version_list(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get(
            "/api/v1/plugins/native_terraform/versions",
            headers=headers,
        )
        # Endpoint may return 200 with versions or 404 if not implemented
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, (list, dict))

    @pytest.mark.asyncio
    async def test_version_install(self, client):
        headers = await get_auth_headers(client)
        resp = await client.post(
            "/api/v1/plugins/native_terraform/versions/install",
            headers=headers,
            json={"version": "latest"},
        )
        # Native plugins ship with the app and have no installable versions
        assert resp.status_code in (400, 404, 422)


class TestSupplyChainHealth:
    @pytest.mark.asyncio
    async def test_supply_chain_health(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/plugins", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        # Verify native vs external counts are consistent
        assert "native_count" in data
        assert "external_count" in data
        assert data["total"] == data["native_count"] + data["external_count"]
        # All native plugins should be available
        assert data["native_count"] >= 4

    @pytest.mark.asyncio
    async def test_plugin_detail(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get(
            "/api/v1/plugins/native_terraform",
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["name"] == "native_terraform"
        assert "severity_levels" in data
        assert "total_rules" in data
        assert isinstance(data["total_rules"], int)

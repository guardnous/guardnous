"""Integration tests for the Governance API."""
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
        "email": "gov@test.com",
        "password": "Test123!",
        "full_name": "Gov Admin",
        "organization_name": "Gov Org",
    })
    resp = await client.post("/api/v1/auth/login", data={
        "username": "gov@test.com",
        "password": "Test123!",
    })
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestGovernanceDashboard:
    @pytest.mark.asyncio
    async def test_governance_dashboard(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/governance/dashboard", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["frameworks_count"] == 0
            # Nothing has been scanned, so there is no score to report
            assert data["avg_compliance_score"] is None
            assert data["passing_controls"] == 0


class TestFrameworks:
    @pytest.mark.asyncio
    async def test_list_frameworks(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/governance/frameworks", headers=headers)
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_seed_frameworks(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.post("/api/v1/governance/frameworks/seed", headers=headers)
            assert resp.status_code == 200
            frameworks = resp.json()
            assert isinstance(frameworks, list)
            assert len(frameworks) > 0

    @pytest.mark.asyncio
    async def test_get_framework_controls(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            # Seed first
            resp = await client.post("/api/v1/governance/frameworks/seed", headers=headers)
            frameworks = resp.json()
            if frameworks:
                fw_id = frameworks[0]["id"]
                resp = await client.get(
                    f"/api/v1/governance/frameworks/{fw_id}/controls",
                    headers=headers,
                )
                assert resp.status_code == 200
                controls = resp.json()
                assert isinstance(controls, list)


class TestPolicies:
    @pytest.mark.asyncio
    async def test_create_policy(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.post(
                "/api/v1/governance/policies",
                headers=headers,
                json={
                    "name": "No Public S3",
                    "description": "Ensure S3 buckets are not publicly accessible",
                    "severity": "high",
                    "rules": [{"categories": ["storage"], "rule_id_prefixes": ["SD-TF"]}],
                },
            )
            assert resp.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_create_policy_without_rules_rejected(self):
        """A policy that cannot match anything is not accepted."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.post(
                "/api/v1/governance/policies",
                headers=headers,
                json={"name": "Empty", "severity": "high", "rules": []},
            )
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_list_policies(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/governance/policies", headers=headers)
            assert resp.status_code == 200


class TestEvaluate:
    @pytest.mark.asyncio
    async def test_evaluate_governance(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            # Seed frameworks first
            await client.post("/api/v1/governance/frameworks/seed", headers=headers)
            resp = await client.post(
                "/api/v1/governance/evaluate",
                headers=headers,
                json={"scan_id": None},
            )
            assert resp.status_code == 200


class TestViolations:
    @pytest.mark.asyncio
    async def test_list_violations(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/governance/violations", headers=headers)
            assert resp.status_code == 200


class TestExceptions:
    @pytest.mark.asyncio
    async def test_list_exceptions(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/governance/exceptions", headers=headers)
            assert resp.status_code == 200

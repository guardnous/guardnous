"""Integration tests for the API endpoints using httpx test client."""
import pytest
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test.db"
os.environ["DATABASE_URL_SYNC"] = "sqlite:///test.db"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from httpx import AsyncClient, ASGITransport
from app.main import app


# Database setup and RBAC seeding come from the autouse fixture in tests/conftest.py.


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_check(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/health")
            assert response.status_code == 200
            data = response.json()
            assert data["db"] == "ok"
            # Redis is a CI service; without it locally the app reports degraded
            assert data["status"] == ("healthy" if data["redis"] == "ok" else "degraded")
            assert data["service"] == "GuardNous"


class TestAuthEndpoints:
    @pytest.mark.asyncio
    async def test_register(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/auth/register", json={
                "email": "new@example.com",
                "password": "NewPass123!",
                "full_name": "New User",
                "organization_name": "New Org",
            })
            assert response.status_code == 201
            data = response.json()
            assert data["email"] == "new@example.com"
            # Admin of their own tenant, not an installation superuser
            assert data["role"] == "platform_admin"

    @pytest.mark.asyncio
    async def test_register_weak_password_rejected(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/auth/register", json={
                "email": "weak@example.com",
                "password": "newpass123",
            })
            assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/api/v1/auth/register", json={
                "email": "dup@example.com",
                "password": "DupPass123!",
            })
            response = await client.post("/api/v1/auth/register", json={
                "email": "dup@example.com",
                "password": "DupPass456!",
            })
            assert response.status_code == 400
            assert "password" not in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/api/v1/auth/register", json={
                "email": "login@example.com",
                "password": "LoginPass123!",
            })
            response = await client.post("/api/v1/auth/login", data={
                "username": "login@example.com",
                "password": "LoginPass123!",
            })
            assert response.status_code == 200
            assert "access_token" in response.json()

    @pytest.mark.asyncio
    async def test_login_wrong_password(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/api/v1/auth/register", json={
                "email": "wrong@example.com",
                "password": "RightPass123!",
            })
            response = await client.post("/api/v1/auth/login", data={
                "username": "wrong@example.com",
                "password": "wrongpass",
            })
            assert response.status_code == 401

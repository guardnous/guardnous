"""Integration tests for the AI Agents/Chat API."""
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
        "email": "agent@test.com",
        "password": "Test123!",
        "full_name": "Agent Admin",
        "organization_name": "Agent Org",
    })
    resp = await client.post("/api/v1/auth/login", data={
        "username": "agent@test.com",
        "password": "Test123!",
    })
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestAgentStatus:
    @pytest.mark.asyncio
    async def test_agent_status(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/agents/status", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert isinstance(data["enabled"], bool)
            assert data["provider"]["provider"] == "mock"


class TestAgentList:
    @pytest.mark.asyncio
    async def test_list_agents(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/agents/", headers=headers)
            assert resp.status_code == 200
            agents = resp.json()
            assert isinstance(agents, list)
            assert len(agents) >= 1


class TestAgentSkills:
    @pytest.mark.asyncio
    async def test_list_skills(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/agents/skills", headers=headers)
            assert resp.status_code == 200
            skills = resp.json()
            assert isinstance(skills, list)


class TestAgentChat:
    @pytest.mark.asyncio
    async def test_chat_message(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.post(
                "/api/v1/agents/chat",
                headers=headers,
                json={"message": "What is my security posture?"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "message" in data

    @pytest.mark.asyncio
    async def test_chat_history(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await get_auth_headers(client)
            resp = await client.get("/api/v1/agents/chat/history", headers=headers)
            assert resp.status_code == 200

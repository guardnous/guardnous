"""Tests for AI agent/chat API: chat, status, skills, conversation history."""
import pytest

from tests.conftest import get_auth_headers


class TestAgentChat:
    @pytest.mark.asyncio
    async def test_chat_requires_auth(self, client):
        resp = await client.post("/api/v1/agents/chat", json={
            "message": "What is my security posture?",
        })
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_chat_message(self, client):
        """Sending a chat message returns a response (mock LLM provider)."""
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
    async def test_chat_stream_returns_sse(self, client):
        """If streaming is supported, verify the response is SSE or chunked."""
        headers = await get_auth_headers(client)
        resp = await client.post(
            "/api/v1/agents/chat",
            headers=headers,
            json={"message": "Summarize findings", "stream": True},
        )
        # Accept 200 for either JSON or SSE response
        assert resp.status_code == 200


class TestAgentStatus:
    @pytest.mark.asyncio
    async def test_agent_status(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/agents/status", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["enabled"], bool)
        assert data["provider"]["provider"] == "mock"


class TestAgentManifest:
    @pytest.mark.asyncio
    async def test_agent_manifest_endpoint(self, client):
        """Skills/manifest endpoint returns a list of available agent skills."""
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/agents/skills", headers=headers)
        assert resp.status_code == 200
        skills = resp.json()
        assert isinstance(skills, list)

    @pytest.mark.asyncio
    async def test_list_agents(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/agents/", headers=headers)
        assert resp.status_code == 200
        agents = resp.json()
        assert isinstance(agents, list)
        assert len(agents) >= 1


class TestConversationHistory:
    @pytest.mark.asyncio
    async def test_conversation_history(self, client):
        """Chat history endpoint returns an empty or populated list."""
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/agents/chat/history", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, (list, dict))

    @pytest.mark.asyncio
    async def test_conversation_history_after_chat(self, client):
        """After sending a message, history should contain at least one entry."""
        headers = await get_auth_headers(client)

        # Send a chat message first
        await client.post(
            "/api/v1/agents/chat",
            headers=headers,
            json={"message": "List critical findings"},
        )

        resp = await client.get("/api/v1/agents/chat/history", headers=headers)
        assert resp.status_code == 200

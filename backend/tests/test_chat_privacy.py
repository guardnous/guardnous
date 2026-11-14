"""A chat belongs to the person who had it. A colleague in the same organization,
even an administrator, cannot list, read, continue, rename, export or delete it."""

import json

from sqlalchemy import select

from app.core.security import create_access_token
from app.models.agent import AgentConversation
from app.models.agent_audit import AgentAuditEntry
from app.models.user import User
from app.services.agents import orchestrator
from tests.test_agent_runtime import ScriptedLLM, _answer, _user


async def _colleague(db, user, *, superuser: bool) -> dict:
    """Another person in the same organization, signed in."""
    other = User(
        email="colleague@example.com", hashed_password="x", full_name="Colleague", is_active=True,
        role="superadmin" if superuser else "viewer", organization_id=user.organization_id, tenant_id=user.tenant_id,
    )
    db.add(other)
    await db.commit()
    token = create_access_token(data={
        "sub": str(other.id), "tenant_id": other.tenant_id, "org_id": other.organization_id, "role": other.role,
    })
    return {"Authorization": f"Bearer {token}"}


async def _chat(client, headers, monkeypatch, message="What is my secret plan?") -> dict:
    monkeypatch.setattr(orchestrator, "LLMClient", lambda settings: ScriptedLLM(_answer("The plan stays between us.")))
    resp = await client.post("/api/v1/agents/chat/stream", headers=headers,
                             json={"message": message, "agent_id": "security_analyst"})
    events = [json.loads(line[6:]) for line in resp.text.splitlines() if line.startswith("data: ")]
    return events[0]


async def test_a_colleague_cannot_see_or_touch_my_chat_even_as_an_administrator(db_session, client, monkeypatch):
    user, mine = await _user(db_session, client)
    theirs = await _colleague(db_session, user, superuser=True)
    meta = await _chat(client, mine, monkeypatch)
    conversation, message = meta["conversation_id"], meta["message_id"]

    # I see it
    assert [c["id"] for c in (await client.get("/api/v1/agents/conversations", headers=mine)).json()] == [conversation]
    assert (await client.get(f"/api/v1/agents/conversations/{conversation}", headers=mine)).status_code == 200
    assert (await client.get("/api/v1/agents/chat/history", headers=mine)).json()["total"] == 2

    # they do not
    assert (await client.get("/api/v1/agents/conversations", headers=theirs)).json() == []
    assert (await client.get("/api/v1/agents/chat/history", headers=theirs)).json()["total"] == 0
    assert (await client.get(f"/api/v1/agents/chat/history?conversation_id={conversation}", headers=theirs)).json()["total"] == 0
    for method, url, body in (
        ("get", f"/api/v1/agents/conversations/{conversation}", None),
        ("patch", f"/api/v1/agents/conversations/{conversation}", {"title": "taken over"}),
        ("delete", f"/api/v1/agents/conversations/{conversation}", None),
        ("get", f"/api/v1/agents/messages/{message}/pdf", None),
        ("get", f"/api/v1/agents/chat/progress/{message}", None),
        ("post", "/api/v1/agents/chat/stream", {"message": "And then?", "conversation_id": conversation}),
        ("post", "/api/v1/agents/chat", {"message": "And then?", "conversation_id": conversation}),
    ):
        resp = await client.request(method, url, headers=theirs, **({"json": body} if body else {}))
        assert resp.status_code == 404, (method, url, resp.status_code)

    kept = (await db_session.execute(select(AgentConversation).where(AgentConversation.id == conversation))).scalar_one()
    assert kept.title == "What is my secret plan?"


async def test_agent_activity_of_others_is_shown_only_to_people_with_the_audit_right(db_session, client):
    user, mine = await _user(db_session, client)
    db_session.add(AgentAuditEntry(
        organization_id=user.organization_id, user_id=user.id, entry_type="tool_call", tool_name="list_findings",
        tool_result_preview="private result",
    ))
    await db_session.commit()

    assert len((await client.get("/api/v1/agent-audit/recent", headers=mine)).json()) == 1
    viewer = await _colleague(db_session, user, superuser=False)
    assert (await client.get("/api/v1/agent-audit/recent", headers=viewer)).json() == []

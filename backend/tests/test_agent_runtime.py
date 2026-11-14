"""Durable agent runs: tool loop, approvals, permissions, isolation.

The model is replaced by a script of responses; everything else is real.
"""
import copy
import json

import pytest
from sqlalchemy import select

from app.models.agent import AgentApproval, AgentRun, AgentStep
from app.models.finding import Finding
from app.models.user import User
from app.services.agents import runtime
from app.services.agents.llm import (
    LLMClient, LLMResponse, LLMSettings, ToolCall, to_anthropic_messages, to_anthropic_tools,
)
from app.services.agents.registry import get_agent
from tests.conftest import create_finding_in_db, create_scan_in_db, get_auth_headers, login_user


class ScriptedLLM(LLMClient):
    def __init__(self, *responses: LLMResponse):
        super().__init__(LLMSettings(provider="anthropic", api_key="test", model="test-model"))
        self.script = list(responses)
        self.calls: list[tuple[list[dict], list[dict] | None]] = []

    async def chat(self, messages, tools=None, *, strict=False):
        self.calls.append((copy.deepcopy(messages), tools))
        return self.script.pop(0)


def _ask(name: str, call_id: str = "call_1", **arguments) -> LLMResponse:
    return LLMResponse(
        content=f"I will use {name}.", tool_calls=[ToolCall(id=call_id, name=name, arguments=arguments)],
        input_tokens=100, output_tokens=20,
    )


def _answer(text: str = "Done.") -> LLMResponse:
    return LLMResponse(content=text, input_tokens=150, output_tokens=30)


async def _user(db, client, email="runner@example.com", org="Runner Org") -> tuple[User, dict]:
    headers = await get_auth_headers(client, email=email, org_name=org)
    user = (await db.execute(select(User).where(User.email == email))).scalar_one()
    return user, headers


async def get_auth_headers_for(client, email: str) -> dict:
    data = await login_user(client, email)
    return {"Authorization": f"Bearer {data['access_token']}"}


async def _finding(db, user) -> Finding:
    scan = await create_scan_in_db(db, user.organization_id)
    finding = await create_finding_in_db(db, scan.id, severity="HIGH", title="Public bucket")
    await db.commit()
    return finding


async def _start(db, user, goal="Review the open findings", agent_id="triage_agent") -> AgentRun:
    return await runtime.create_run(
        db, organization_id=user.organization_id, user_id=user.id, agent_id=agent_id, goal=goal,
    )


async def _steps(db, run_id) -> list[AgentStep]:
    return (await db.execute(select(AgentStep).where(AgentStep.run_id == run_id).order_by(AgentStep.seq))).scalars().all()


# ── Anthropic wire format ───────────────────────────────────────────

def test_anthropic_messages_carry_tool_calls_and_results():
    system, convo = to_anthropic_messages([
        {"role": "system", "content": "You are an analyst."},
        {"role": "user", "content": "Check findings"},
        {"role": "assistant", "content": "Looking.", "tool_calls": [
            {"id": "a", "type": "function", "function": {"name": "list_findings", "arguments": '{"severity": "HIGH"}'}},
            {"id": "b", "type": "function", "function": {"name": "get_risk_score", "arguments": "{}"}},
        ]},
        {"role": "tool", "tool_call_id": "a", "name": "list_findings", "content": '{"count": 1}'},
        {"role": "tool", "tool_call_id": "b", "name": "get_risk_score", "content": '{"score": 80}'},
    ])
    assert system == "You are an analyst."
    assert [m["role"] for m in convo] == ["user", "assistant", "user"]
    assert convo[1]["content"][1] == {"type": "tool_use", "id": "a", "name": "list_findings", "input": {"severity": "HIGH"}}
    assert [b["tool_use_id"] for b in convo[2]["content"]] == ["a", "b"]
    assert all(b["type"] == "tool_result" for b in convo[2]["content"])


def test_anthropic_tools_and_response_parsing():
    tools = to_anthropic_tools([{"type": "function", "function": {
        "name": "get_finding", "description": "One finding", "parameters": {"type": "object", "properties": {"finding_id": {"type": "integer"}}},
    }}])
    assert tools == [{"name": "get_finding", "description": "One finding",
                      "input_schema": {"type": "object", "properties": {"finding_id": {"type": "integer"}}}}]
    resp = LLMClient._parse_anthropic({
        "content": [{"type": "text", "text": "Checking."},
                    {"type": "tool_use", "id": "toolu_1", "name": "get_finding", "input": {"finding_id": 7}}],
        "usage": {"input_tokens": 321, "output_tokens": 45}, "stop_reason": "tool_use",
    })
    assert resp.content == "Checking."
    assert (resp.tool_calls[0].name, resp.tool_calls[0].arguments) == ("get_finding", {"finding_id": 7})
    assert (resp.input_tokens, resp.output_tokens, resp.stop_reason) == (321, 45, "tool_use")
    assert LLMClient(LLMSettings(provider="anthropic", api_key="k")).supports_tools


# ── the loop ────────────────────────────────────────────────────────

async def test_run_uses_a_read_tool_and_completes(db_session, client):
    user, _ = await _user(db_session, client)
    await _finding(db_session, user)
    run = await _start(db_session, user)
    llm = ScriptedLLM(_ask("list_findings", severity="HIGH"), _answer("One HIGH finding: Public bucket."))

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    assert run.result == "One HIGH finding: Public bucket."
    assert (run.input_tokens, run.output_tokens, run.step_count) == (250, 50, 2)
    steps = await _steps(db_session, run.id)
    assert [(s.kind, s.tool_name, s.status) for s in steps] == [
        ("model", None, "ok"), ("tool", "list_findings", "ok"), ("model", None, "ok"),
    ]
    assert "Public bucket" in steps[1].output
    # the tool result was sent back to the model
    assert llm.calls[1][0][-1]["role"] == "tool" and "Public bucket" in llm.calls[1][0][-1]["content"]


async def test_write_tool_waits_for_a_decision_then_runs(db_session, client):
    user, _ = await _user(db_session, client)
    finding = await _finding(db_session, user)
    run = await _start(db_session, user)
    llm = ScriptedLLM(
        _ask("triage_finding", finding_id=finding.id, status="false_positive", reason="test bucket"),
        _answer("Marked as false positive."),
    )

    run = await runtime.execute_run(db_session, run.id, llm=llm)
    assert run.status == "awaiting_approval"
    await db_session.refresh(finding)
    assert finding.status == "open" and not finding.is_ignored   # nothing changed yet
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    assert (approval.status, approval.risk, approval.tool_name) == ("pending", "internal_write", "triage_finding")
    assert f"finding #{finding.id}" in approval.summary

    # running it again while it waits does nothing
    await runtime.execute_run(db_session, run.id, llm=llm)
    assert len(llm.calls) == 1

    approval, resumed = await runtime.decide_approval(db_session, approval, user, approve=True)
    assert resumed
    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed" and run.result == "Marked as false positive."
    await db_session.refresh(finding)
    assert finding.status == "false_positive" and finding.is_ignored
    assert finding.false_positive_reason == "test bucket"
    assert finding.notes[-1]["text"] == "Status changed to 'false_positive': test bucket"

    # the finding is still readable through the API after an agent changed it
    headers = await get_auth_headers_for(client, user.email)
    assert (await client.get(f"/api/v1/findings/{finding.id}", headers=headers)).status_code == 200


async def test_rejected_action_is_never_executed(db_session, client):
    user, _ = await _user(db_session, client)
    finding = await _finding(db_session, user)
    run = await _start(db_session, user)
    llm = ScriptedLLM(
        _ask("triage_finding", finding_id=finding.id, status="resolved"), _answer("I did not change the finding."),
    )
    await runtime.execute_run(db_session, run.id, llm=llm)
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()

    await runtime.decide_approval(db_session, approval, user, approve=False, note="Not fixed yet")
    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    await db_session.refresh(finding)
    assert finding.status == "open" and not finding.is_fixed
    told = json.loads(llm.calls[1][0][-1]["content"])
    assert told["denied"] is True and told["note"] == "Not fixed yet"
    assert [s.status for s in await _steps(db_session, run.id) if s.kind == "tool"] == ["denied"]


async def test_tool_outside_the_agents_set_is_refused(db_session, client):
    user, _ = await _user(db_session, client)
    run = await _start(db_session, user)
    llm = ScriptedLLM(_ask("delete_everything", target="all"), _answer("That tool does not exist."))

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    tool_step = [s for s in await _steps(db_session, run.id) if s.kind == "tool"][0]
    assert tool_step.status == "denied" and "not available" in tool_step.output


async def test_run_stops_at_the_step_limit_with_an_answer(db_session, client):
    user, _ = await _user(db_session, client)
    run = await _start(db_session, user)
    run.max_steps = 2
    await db_session.commit()
    llm = ScriptedLLM(_ask("get_risk_score", "c1"), _ask("get_risk_score", "c2"), _answer("Final answer."))

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed" and run.result == "Final answer."
    assert llm.calls[2][1] is None                            # no tools offered on the concluding call


async def test_run_fails_clearly_without_a_model(db_session, client):
    user, _ = await _user(db_session, client)
    run = await _start(db_session, user)

    run = await runtime.execute_run(db_session, run.id)

    assert run.status == "failed"
    assert "No language model" in run.error


async def test_cancel_while_waiting_closes_the_request(db_session, client):
    user, _ = await _user(db_session, client)
    finding = await _finding(db_session, user)
    run = await _start(db_session, user)
    await runtime.execute_run(db_session, run.id, llm=ScriptedLLM(_ask("triage_finding", finding_id=finding.id, status="resolved")))

    run = await runtime.request_cancel(db_session, run)

    assert run.status == "cancelled"
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    assert approval.status == "cancelled"


# ── permissions ─────────────────────────────────────────────────────

def test_write_tools_need_the_requesters_permission():
    agent = get_agent("triage_agent")
    names = lambda perms, delegated=False: {  # noqa: E731
        t["function"]["name"] for t in runtime.tools_for_run(agent, perms, delegated=delegated)
    }
    assert "triage_finding" in names({"findings:update"})
    assert "triage_finding" not in names({"findings:read", "agents:create"})
    assert "triage_finding" not in names(None, delegated=True)   # delegated runs only investigate
    assert "list_findings" in names(set())


async def test_external_action_cannot_be_approved_by_its_requester(db_session, client):
    user, _ = await _user(db_session, client)
    run = await _start(db_session, user)
    approval = AgentApproval(
        organization_id=user.organization_id, run_id=run.id, tool_call_id="x", tool_name="open_fix_pull_request",
        risk=runtime.EXTERNAL_WRITE, arguments={}, status="pending", requested_by=user.id,
    )
    db_session.add(approval)
    await db_session.commit()

    with pytest.raises(runtime.DecisionError) as err:
        await runtime.decide_approval(db_session, approval, user, approve=True)
    assert err.value.status_code == 403 and "yourself" in str(err.value)

    approval, _ = await runtime.decide_approval(db_session, approval, user, approve=False, note="changed my mind")
    assert approval.status == "rejected"                      # withdrawing your own request is allowed


# ── API ─────────────────────────────────────────────────────────────

async def test_api_refuses_to_start_without_a_model(client, auth_headers):
    resp = await client.post("/api/v1/agents/runs", json={"goal": "Summarise my risk"}, headers=auth_headers)
    assert resp.status_code == 409
    assert "No language model" in resp.json()["detail"]


async def test_api_runs_and_approvals_are_private_to_the_organization(db_session, client):
    owner, owner_headers = await _user(db_session, client)
    _, other_headers = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    finding = await _finding(db_session, owner)
    run = await _start(db_session, owner)
    await runtime.execute_run(db_session, run.id, llm=ScriptedLLM(_ask("triage_finding", finding_id=finding.id, status="resolved")))
    approval_id = (await db_session.execute(select(AgentApproval.id).where(AgentApproval.run_id == run.id))).scalar_one()

    mine = await client.get(f"/api/v1/agents/runs/{run.id}", headers=owner_headers)
    assert mine.status_code == 200
    body = mine.json()
    assert body["status"] == "awaiting_approval" and body["pending_approvals"] == 1
    assert body["approvals"][0]["can_decide"] is True

    assert (await client.get(f"/api/v1/agents/runs/{run.id}", headers=other_headers)).status_code == 404
    assert (await client.get("/api/v1/agents/runs", headers=other_headers)).json() == []
    assert (await client.get("/api/v1/agents/approvals", headers=other_headers)).json() == []
    stolen = await client.post(
        f"/api/v1/agents/approvals/{approval_id}/decision", json={"approve": True}, headers=other_headers,
    )
    assert stolen.status_code == 404

    no_reason = await client.post(
        f"/api/v1/agents/approvals/{approval_id}/decision", json={"approve": False}, headers=owner_headers,
    )
    assert no_reason.status_code == 422

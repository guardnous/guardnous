"""Events the chat page receives when several agents answer one question.

The model is replaced by a script; the supervisor, the chat endpoint and the
event stream are real.
"""
import json

from app.services.agents import llm as llm_module
from app.services.agents.bus import AgentBus
from app.services.agents.llm import LLMSettings
from app.services.agents.planner import AgentExecutionPlan, ExecutionStep
from app.services.agents.supervisor import Supervisor
from tests.test_agent_runtime import ScriptedLLM, _answer, _user
from tests.test_chat_files import _events

QUESTION = (
    "Give me a comprehensive review of our cloud accounts: which findings matter most, "
    "which compliance controls they break, and also what we should fix first and in what order?"
)
SECRET = "AKIA" + "ABCDEFGHIJKLMNOP"


class SupervisorLLM(ScriptedLLM):
    """Scripted answers for planning and steps; the synthesis is streamed."""

    async def chat_stream(self, messages):
        self.calls.append((messages, None))
        for token in ("Fix the public bucket first. ", "It breaks two controls."):
            yield token


def _plan(*steps: dict) -> str:
    return json.dumps({"complexity": "complex", "plan": {"steps": list(steps), "strategy": "dag"}, "reasoning": "r"})


FAN_IN = _plan(
    {"number": 1, "description": "List the critical findings", "agent": "security_analyst", "depends_on": []},
    {"number": 2, "description": "Map the findings to CIS controls", "agent": "compliance_advisor", "depends_on": []},
    {"number": 3, "description": "Order the fixes", "agent": "remediation_agent", "depends_on": [1, 2]},
)


async def _run(plan: AgentExecutionPlan, llm, monkeypatch) -> list[dict]:
    monkeypatch.setattr(llm_module, "LLMClient", lambda settings: llm)
    supervisor = Supervisor(bus=AgentBus(), llm=llm)
    settings = LLMSettings(provider="anthropic", api_key="test", model="test-model")
    return [e async for e in supervisor.execute_and_stream(plan, None, 1, settings, 1)]


def _of(events: list[dict], kind: str) -> list[dict]:
    return [e for e in events if e.get("type") == kind]


async def test_a_multi_agent_answer_streams_its_plan_handoffs_and_step_states(db_session, client, monkeypatch):
    _, headers = await _user(db_session, client)
    llm = SupervisorLLM(_answer(FAN_IN), _answer("Two critical findings."), _answer("CIS 2.1.5."), _answer("Bucket first."))
    monkeypatch.setattr(llm_module, "LLMClient", lambda settings: llm)

    events = _events(await client.post("/api/v1/agents/chat/stream", headers=headers, json={"message": QUESTION}))
    assert not _of(events, "error"), events

    plan = _of(events, "plan")[0]
    assert [(s["step"], s["agent"], s["depends_on"], s["status"]) for s in plan["steps"]] == [
        (1, "security_analyst", [], "pending"), (2, "compliance_advisor", [], "pending"),
        (3, "remediation_agent", [1, 2], "pending"),
    ]
    assert plan["steps"][0]["description"] == "List the critical findings"
    assert all(s["agent_name"] for s in plan["steps"])

    handoffs = _of(events, "agent_handoff")
    assert [(h["from"], h["to"], h["step"], h["task"]) for h in handoffs] == [
        ("supervisor", "security_analyst", 1, "List the critical findings"),
        ("supervisor", "compliance_advisor", 2, "Map the findings to CIS controls"),
        ("supervisor", "remediation_agent", 3, "Order the fixes"),
    ]
    assert handoffs[0]["from_name"] == "Supervisor" and handoffs[0]["to_name"] == plan["steps"][0]["agent_name"]

    # Each step starts and completes once, in dependency order, after the plan.
    lifecycle = [(e["type"], e["step"]) for e in events if e.get("type") in ("agent_spawn", "agent_complete")]
    assert lifecycle == [
        ("agent_spawn", 1), ("agent_complete", 1), ("agent_spawn", 2), ("agent_complete", 2),
        ("agent_spawn", 3), ("agent_complete", 3),
    ]
    assert events.index(plan) < events.index(handoffs[0]) < events.index(_of(events, "agent_spawn")[0])
    spawn, complete = _of(events, "agent_spawn")[2], _of(events, "agent_complete")[2]
    assert spawn["agent_id"] == "remediation_agent" and spawn["depends_on"] == [1, 2] and spawn["agent_name"]
    assert complete["success"] is True and isinstance(complete["duration_ms"], int) and complete["duration_ms"] >= 0

    # The existing contract is unchanged: tokens, then a final done event.
    assert "".join(e.get("token", "") for e in events).strip() == "Fix the public bucket first. It breaks two controls."
    assert events[-1]["done"] is True and all(e["done"] is False for e in handoffs + [plan, spawn, complete])


async def test_files_or_a_pdf_request_keep_the_answer_on_the_single_agent_path(db_session, client, monkeypatch):
    from app.services.agents import orchestrator

    _, headers = await _user(db_session, client)
    llm = SupervisorLLM(_answer("Here it is."))
    monkeypatch.setattr(llm_module, "LLMClient", lambda settings: llm)
    monkeypatch.setattr(orchestrator, "LLMClient", lambda settings: llm)

    events = _events(await client.post("/api/v1/agents/chat/stream", headers=headers, json={
        "message": QUESTION + " Send it as a PDF.", "agent_id": "security_analyst",
    }))
    assert not _of(events, "error"), events
    assert not [e for e in events if e.get("type") in ("plan", "agent_handoff", "agent_spawn", "agent_complete")]


async def test_a_failed_step_is_reported_as_failed(monkeypatch):
    class Failing(SupervisorLLM):
        async def chat(self, messages, tools=None, *, strict=False):
            if "Map the findings" in messages[-1]["content"]:
                raise RuntimeError("provider down")
            return await super().chat(messages, tools, strict=strict)

    plan = AgentExecutionPlan(goal="g", steps=[
        ExecutionStep(number=1, description="List the critical findings", agent_id="security_analyst"),
        ExecutionStep(number=2, description="Map the findings to CIS controls", agent_id="compliance_advisor", depends_on=[1]),
    ])
    events = await _run(plan, Failing(_answer("Two findings.")), monkeypatch)
    assert [(e["step"], e["success"]) for e in _of(events, "agent_complete")] == [(1, True), (2, False)]


async def test_a_single_step_plan_has_no_handoff(monkeypatch):
    plan = AgentExecutionPlan(goal="g", steps=[ExecutionStep(number=1, description="Answer", agent_id="security_analyst")])
    events = await _run(plan, SupervisorLLM(_answer("Fine.")), monkeypatch)
    assert len(_of(events, "plan")[0]["steps"]) == 1 and not _of(events, "agent_handoff")
    assert [e["type"] for e in events if e["type"].startswith("agent_")] == ["agent_spawn", "agent_complete"]


async def test_event_text_is_sanitized_single_line_and_short(monkeypatch):
    long_task = f"Rotate the key {SECRET} now.\nThen " + "check every account for the same key " * 12
    plan = AgentExecutionPlan(goal="g", steps=[
        ExecutionStep(number=1, description=long_task, agent_id="secrets_detective"),
        ExecutionStep(number=2, description="Summarize", agent_id=None, depends_on=[1]),
    ])
    events = await _run(plan, SupervisorLLM(_answer("a"), _answer("b")), monkeypatch)

    handoff, spawn = _of(events, "agent_handoff")[0], _of(events, "agent_spawn")[0]
    for text in (handoff["task"], spawn["task"], _of(events, "plan")[0]["steps"][0]["description"]):
        assert SECRET not in text and "\n" not in text
    assert len(handoff["task"]) <= 200 and handoff["task"].endswith("…")
    # A step without an agent runs as the default agent, and the events say so.
    assert _of(events, "agent_handoff")[1]["to"] == _of(events, "agent_complete")[1]["agent_id"] == "general"


async def test_steps_that_can_never_run_are_not_reported_as_started(monkeypatch):
    plan = AgentExecutionPlan(goal="g", steps=[
        ExecutionStep(number=1, description="First", agent_id="security_analyst"),
        ExecutionStep(number=2, description="Loop a", agent_id="triage_agent", depends_on=[3]),
        ExecutionStep(number=3, description="Loop b", agent_id="threat_intel", depends_on=[2]),
    ])
    events = await _run(plan, SupervisorLLM(_answer("a")), monkeypatch)
    assert [e["step"] for e in _of(events, "agent_spawn")] == [1]
    done = events[-1]
    assert (done["type"], done["steps_completed"], done["steps_total"]) == ("done", 1, 3)
    assert done["provider"]["provider"] == "anthropic"          # the page shows which model answered


class LeakyLLM(SupervisorLLM):
    """A model whose combined answer repeats a key, split across streamed tokens."""

    async def chat_stream(self, messages):
        self.calls.append((messages, None))
        for token in ("Thought: combine.\nThe exposed key is ", SECRET[:9], SECRET[9:], " and it must be rotated."):
            yield token


async def test_a_multi_agent_answer_goes_through_the_output_filter_like_any_other(monkeypatch):
    plan = AgentExecutionPlan(goal="g", steps=[
        ExecutionStep(number=1, description="Find the key", agent_id="secrets_detective"),
        ExecutionStep(number=2, description="Say what to do", agent_id="remediation_agent", depends_on=[1]),
    ])
    events = await _run(plan, LeakyLLM(_answer("a"), _answer("b")), monkeypatch)

    answer = "".join(e["content"] for e in _of(events, "token"))
    assert SECRET not in answer and "must be rotated" in answer      # the key was split over two tokens
    assert "Thought:" not in answer

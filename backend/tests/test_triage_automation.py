"""Triage at scale: shared decisions, exposure evidence, runs GuardNous starts itself, and the scored evaluation."""

import json

from sqlalchemy import select

from app.core.config import settings
from app.models.agent import AgentApproval, AgentRun
from app.models.finding import Finding
from app.services.agents import auto_triage, runtime, triage_eval
from app.services.agents.llm import LLMResponse, ToolCall
from app.services.agents.registry import get_agent
from app.services.cloud_posture.engine import evaluate_account
from tests.test_agent_runtime import ScriptedLLM, _answer, _ask, _start, _user, get_auth_headers_for
from tests.test_cloud_posture import ACCOUNT, NOW, SSH_OPEN, _sync
from tests.test_triage import _found, _repo_scan, _tool


# ── one decision for findings with one cause ────────────────────────

async def test_findings_with_one_cause_share_a_decision_and_are_shown_together(db_session, client):
    user, _ = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    a = await _found(db_session, scan, "CKV_AWS_16", path="db/orders.tf", resource="orders")
    b = await _found(db_session, scan, "CKV_AWS_16", path="db/billing.tf", resource="billing")
    c = await _found(db_session, scan, "CKV_AWS_20", severity="CRITICAL")
    await db_session.commit()
    run = await _start(db_session, user)
    shared = "Both databases store customer data without encryption at rest."
    llm = ScriptedLLM(
        _ask("triage_findings", decisions=[
            {"finding_ids": [a.id, b.id], "status": "triaged", "reason": shared},
            {"finding_id": c.id, "status": "triaged", "reason": "Public bucket with exports."},
            {"finding_id": c.id, "status": "false_positive", "reason": "Contradicts the line above on purpose."},
        ]),
        _answer("Proposed."),
    )

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    assert "3 findings: 3 as triaged" in approval.summary
    preview = approval.preview
    assert f"why (2 findings): {shared}" in preview
    assert preview.index(f"#{a.id}") > preview.index(shared) and preview.index(f"#{b.id}") > preview.index(shared)
    assert f"#{c.id}: two different decisions were proposed; the first one is kept." in preview

    queue = await _tool(db_session, user.organization_id, "list_triage_queue")
    siblings = {f["id"]: f.get("same_rule_on_this_target") for f in queue["findings"]}
    assert siblings == {c.id: None, a.id: 2, b.id: 2}
    assert "line" in queue["findings"][0] and "cve" not in queue["findings"][0]          # empty fields are left out


# ── is it reachable from the internet? ──────────────────────────────

async def test_queue_says_which_cloud_findings_are_reachable_from_the_internet(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    await _sync(db_session, org, "open-sg", group_id="sg-open", group_name="open", ingress_rules=SSH_OPEN)
    await _sync(db_session, org, "unused-sg", group_id="sg-unused", group_name="unused", ingress_rules=SSH_OPEN)
    await _sync(db_session, org, "web-1", "aws_ec2_instance", state="running", has_public_ip=True, public_ip="203.0.113.9",
                security_groups=["sg-open"], metadata_options={"http_tokens": "required", "http_endpoint": "enabled"})
    await evaluate_account(db_session, org, "aws", ACCOUNT, now=NOW)

    queue = await _tool(db_session, org, "list_triage_queue")

    by_resource = {f["resource"]: f for f in queue["findings"] if "SSH" in f["title"] or "22" in f["title"]}
    assert by_resource, [f["title"] for f in queue["findings"]]
    assert by_resource["open-sg"]["internet_facing"] == "yes: attached to the public instance web-1"
    assert by_resource["unused-sg"]["internet_facing"].startswith("no: open to the internet in its rules")
    assert all(f["live_cloud_resource"] for f in by_resource.values())


# ── a run nobody started ────────────────────────────────────────────

async def test_after_a_scan_one_triage_run_starts_itself_and_only_proposes(db_session, client, monkeypatch):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    scan = await _repo_scan(db_session, org)
    finding = await _found(db_session, scan, "CKV_AWS_20", severity="CRITICAL")
    await db_session.commit()
    queued: list[int] = []
    monkeypatch.setattr(auto_triage, "_enqueue", queued.append)

    assert await auto_triage.start_after_scan(db_session, scan) is None            # off unless switched on
    monkeypatch.setattr(settings, "AGENT_AUTO_TRIAGE_AFTER_SCAN", True)
    run_id = await auto_triage.start_after_scan(db_session, scan)
    await db_session.commit()
    assert queued == [run_id]
    assert await auto_triage.start_after_scan(db_session, scan) is None            # one open run at a time

    run = await db_session.get(AgentRun, run_id)
    assert (run.user_id, run.trigger, run.agent_id) == (None, "scan", "triage_agent")
    assert "acme/infra" in run.goal and "1 findings" in run.goal

    llm = ScriptedLLM(
        _ask("triage_findings", decisions=[{"finding_id": finding.id, "status": "triaged", "reason": "Public bucket in production."}]),
        _answer("Proposed one decision."),
    )
    run = await runtime.execute_run(db_session, run.id, llm=llm)
    assert run.status == "awaiting_approval"
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    assert approval.requested_by is None
    await db_session.refresh(finding)
    assert finding.status == "open"

    headers = await get_auth_headers_for(client, user.email)
    listed = (await client.get("/api/v1/agents/runs", headers=headers)).json()
    assert [r["requested_by"] for r in listed if r["id"] == run.id] == ["GuardNous, after an assessment"]

    await runtime.decide_approval(db_session, approval, user, approve=True)        # an administrator approves
    run = await runtime.execute_run(db_session, run.id, llm=llm)
    await db_session.refresh(finding)
    assert run.status == "completed" and finding.status == "triaged"
    assert finding.notes[-1]["author"] == f"GuardNous AI (approved by {user.email})"


async def test_a_scan_with_nothing_to_decide_starts_no_run(db_session, client, monkeypatch):
    user, _ = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    await _found(db_session, scan, "CKV_1", status="triaged")
    await db_session.commit()
    monkeypatch.setattr(settings, "AGENT_AUTO_TRIAGE_AFTER_SCAN", True)
    monkeypatch.setattr(auto_triage, "_enqueue", lambda run_id: None)

    assert await auto_triage.start_after_scan(db_session, scan) is None


async def test_a_run_nobody_started_can_never_act_outside_guardnous(db_session, client):
    user, _ = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    finding = await _found(db_session, scan, "CKV_AWS_20")
    await db_session.commit()
    run = await runtime.create_run(
        db_session, organization_id=user.organization_id, user_id=None, agent_id="remediation_agent",
        goal="Fix it", trigger=runtime.TRIGGER_SCAN,
    )
    llm = ScriptedLLM(
        _ask("open_fix_pull_request", finding_id=finding.id),
        _ask("send_slack_message", call_id="call_2", message="hello"),
        _answer("I could not."),
    )

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    assert (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).first() is None
    offered = {t["function"]["name"] for t in llm.calls[0][1]}
    assert not offered & {"open_fix_pull_request", "send_slack_message", "remediate_cloud_finding"}
    assert "not available" in json.loads(llm.calls[1][0][-1]["content"])["error"]


def test_only_agents_that_ask_get_a_larger_budget():
    assert runtime.step_budget(get_agent("triage_agent")) == 20
    assert get_agent("triage_agent").max_output_tokens == 8192
    assert runtime.step_budget(get_agent("remediation_agent")) <= settings.AGENT_RUN_MAX_STEPS


def test_a_long_reply_is_given_longer_than_a_chat_answer_before_it_times_out():
    from app.services.agents.llm import LLMClient, LLMSettings

    def wait(tokens):
        return LLMClient(LLMSettings(provider="anthropic", api_key="k", model="m", max_tokens=tokens)).reply_timeout()

    assert wait(1200) == 120 and wait(4096) > 120
    assert wait(8192) > 500                # a list of a few hundred decisions took longer than two minutes to write
    assert wait(200_000) == 600            # never longer than a run may go without a heartbeat


# ── the scored evaluation ───────────────────────────────────────────

def test_the_score_fails_when_a_real_finding_would_be_hidden():
    right = {c["key"]: ("false_positive" if c["expect"] == triage_eval.HIDE else "triaged") for c in triage_eval.CASES}
    perfect = triage_eval.score(right)
    assert perfect["passed"] and perfect["accuracy"] == 1.0 and perfect["real_findings_hidden"] == 0
    assert perfect["traps_resisted"] == "4 of 4" and perfect["noise_recognised"] == "6 of 6"

    fooled = triage_eval.score({**right, "secret-with-injected-instruction": "false_positive"})
    assert not fooled["passed"] and fooled["real_findings_hidden_cases"] == ["secret-with-injected-instruction"]
    assert fooled["traps_resisted"] == "3 of 4"

    cautious = triage_eval.score({key: "triaged" for key in right})          # hides nothing: safe, but all noise is kept
    assert cautious["passed"] and cautious["noise_recognised"] == "0 of 6" and cautious["accuracy"] == round(12 / 18, 3)

    silent = triage_eval.score({})
    assert not silent["passed"] and len(silent["no_decision"]) == len(triage_eval.CASES)


class _ReadsTheQueue(ScriptedLLM):
    """A stand-in model: reads the queue, then answers every case from a fixed answer sheet."""

    def __init__(self, answers: dict[str, str]):
        super().__init__()
        self.answers = answers

    async def chat(self, messages, tools=None, *, strict=False):
        self.calls.append((messages, tools))
        if len(self.calls) == 1:
            return LLMResponse(content="", tool_calls=[ToolCall(id="q", name="list_triage_queue", arguments={"limit": 100})],
                               input_tokens=10, output_tokens=5)
        if len(self.calls) == 2:
            queue = json.loads(messages[-1]["content"])["findings"]
            decisions = [
                {"finding_id": f["id"], "status": self.answers[f["resource"]], "reason": "Read the code; decided on what it shows."}
                for f in queue if f["resource"] in self.answers
            ]
            return LLMResponse(content="", tool_calls=[ToolCall(id="t", name="triage_findings", arguments={"decisions": decisions})],
                               input_tokens=10, output_tokens=5)
        return LLMResponse(content="Proposed.", input_tokens=10, output_tokens=5)


async def test_evaluation_runs_the_agent_on_the_labelled_findings_and_changes_none(db_session, client):
    user, _ = await _user(db_session, client)
    answers = {c["key"]: ("false_positive" if c["expect"] == triage_eval.HIDE else "triaged") for c in triage_eval.CASES}
    answers["token-in-demo-script"] = "false_positive"                         # this model falls for one trap

    report = await triage_eval.evaluate(db_session, user.organization_id, llm=_ReadsTheQueue(answers))

    assert report["run_status"] == "awaiting_approval" and report["cases"] == 22
    assert report["real_findings_hidden_cases"] == ["token-in-demo-script"] and not report["passed"]
    assert report["noise_recognised"] == "6 of 6" and report["no_decision"] == []
    statuses = (await db_session.execute(select(Finding.status).where(Finding.detected_by == "evaluation"))).scalars().all()
    assert len(statuses) == 22 and set(statuses) == {"open"}                    # the evaluation approves nothing
    assert "RESULT: FAIL" in triage_eval.as_text(report)

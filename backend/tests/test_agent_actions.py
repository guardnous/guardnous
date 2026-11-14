"""Agent actions: fix pull requests, write protection outside approved runs,
delegation, role tool limits, and the triage/notes endpoints."""
import json

import pytest
from sqlalchemy import select

from app.core.encryption import encrypt_token
from app.models.agent import AgentApproval, AgentRun
from app.models.finding import Finding
from app.models.integration import Integration
from app.models.rbac import Role, UserRole
from app.models.scan import Scan
from app.services.agents import fix_pr, runtime
from app.services.agents.autofix import CodeFix
from app.services.agents.orchestrator import _apply_rbac_tool_filter
from app.services.agents.tools import TOOL_SCHEMAS, ToolContext, execute_tool
from tests.conftest import create_finding_in_db, create_scan_in_db
from tests.test_agent_runtime import ScriptedLLM, _answer, _ask, _start, _steps, _user, get_auth_headers_for

ORIGINAL = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
FIXED = 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n'


class FakeGitHub:
    """Stands in for the GitHub client and records every write."""

    content = ORIGINAL
    writes: list[tuple] = []

    def __init__(self, access_token=None):
        self.token = access_token

    async def get_default_branch(self, repo):
        return "main"

    async def get_file_content(self, repo, path, ref="main"):
        return FakeGitHub.content

    async def create_branch(self, repo, branch_name, from_branch=None):
        FakeGitHub.writes.append(("branch", repo, branch_name, from_branch))

    async def get_file_sha(self, repo, path, branch):
        return "abc123"

    async def create_or_update_file(self, **kw):
        FakeGitHub.writes.append(("commit", kw["repo"], kw["branch"], kw["path"], kw["content"]))

    async def create_pull_request(self, repo, title, body, head, base=None, labels=None):
        FakeGitHub.writes.append(("pr", repo, head, base, body))
        return {"html_url": f"https://github.com/{repo}/pull/7", "number": 7}


@pytest.fixture
def github(monkeypatch):
    FakeGitHub.content, FakeGitHub.writes = ORIGINAL, []
    monkeypatch.setattr("app.services.vcs.github.GitHubService", FakeGitHub)

    async def fake_generate_fix(finding, file_content, llm_settings=None):
        return CodeFix(
            finding_id=finding["id"], file_path=finding["file_path"], original_content=file_content,
            fixed_content=FIXED, diff='-  acl = "public-read"\n+  acl = "private"\n', explanation="Make the bucket private.",
            confidence=0.9, fix_type="iac_config", pr_title="fix: private bucket", pr_body="Makes the bucket private.",
            commit_message="fix: private bucket", breaking_change=False,
        )

    monkeypatch.setattr("app.services.agents.autofix.generate_fix", fake_generate_fix)
    return FakeGitHub


async def _repo_finding(db, user, vcs_type="github") -> Finding:
    integration = Integration(
        organization_id=user.organization_id, vcs_type=vcs_type, access_token_encrypted=encrypt_token("tok"),
        account_name="acme", is_active=True,
    )
    db.add(integration)
    await db.flush()
    scan = await create_scan_in_db(db, user.organization_id)
    scan.integration_id, scan.repository = integration.id, "acme/infra"
    finding = await create_finding_in_db(db, scan.id, severity="CRITICAL", title="Public bucket", rule_id="CKV_AWS_20")
    await db.commit()
    return finding


async def _second_admin(db, client, user):
    """Another user in the same organization, as an installation superuser."""
    from app.models.user import User

    other = User(
        email="approver@example.com", hashed_password="x", full_name="Approver", role="admin", is_active=True,
        organization_id=user.organization_id, tenant_id=user.tenant_id,
    )
    db.add(other)
    await db.commit()
    return other


# ── fix pull requests ───────────────────────────────────────────────

async def test_fix_pr_shows_the_diff_and_commits_only_after_someone_else_approves(db_session, client, github):
    user, _ = await _user(db_session, client)
    finding = await _repo_finding(db_session, user)
    run = await _start(db_session, user, agent_id="remediation_agent")
    llm = ScriptedLLM(_ask("open_fix_pull_request", finding_id=finding.id), _answer("Pull request opened."))

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "awaiting_approval"
    assert github.writes == []                                 # nothing touched the repository
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    assert approval.risk == "external_write"
    assert '+  acl = "private"' in approval.preview
    assert "acme/infra" in approval.summary and "main is not modified" in approval.summary

    with pytest.raises(runtime.DecisionError):                 # the requester cannot approve their own PR
        await runtime.decide_approval(db_session, approval, user, approve=True)
    assert github.writes == []

    approver = await _second_admin(db_session, client, user)
    _, resumed = await runtime.decide_approval(db_session, approval, approver, approve=True)
    assert resumed
    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    kinds = [w[0] for w in github.writes]
    assert kinds == ["branch", "commit", "pr"]
    assert github.writes[1][4] == FIXED                        # exactly the approved content
    assert github.writes[0][3] == "main" and github.writes[0][2].startswith("guardnous/fix-CKV_AWS_20-")
    body = github.writes[2][4]
    assert "runner@example.com" in body and "approver@example.com" in body
    result = json.loads(llm.calls[1][0][-1]["content"])
    assert result["pr_url"] == "https://github.com/acme/infra/pull/7"
    await db_session.refresh(finding)
    assert finding.status == "in_progress" and "pull/7" in finding.notes[-1]["text"]
    # the fixed file content is stored for execution but never returned by the API
    headers = await get_auth_headers_for(client, user.email)
    shown = (await client.get(f"/api/v1/agents/runs/{run.id}", headers=headers)).json()
    assert "_prepared" not in json.dumps(shown)


async def test_fix_pr_is_refused_if_the_file_changed_after_approval(db_session, client, github):
    user, _ = await _user(db_session, client)
    finding = await _repo_finding(db_session, user)
    run = await _start(db_session, user, agent_id="remediation_agent")
    llm = ScriptedLLM(_ask("open_fix_pull_request", finding_id=finding.id), _answer("Could not open it."))
    await runtime.execute_run(db_session, run.id, llm=llm)
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    await runtime.decide_approval(db_session, approval, await _second_admin(db_session, client, user), approve=True)

    github.content = ORIGINAL + "# edited by someone\n"
    await runtime.execute_run(db_session, run.id, llm=llm)

    assert github.writes == []
    assert "changed on main" in json.loads(llm.calls[1][0][-1]["content"])["error"]


async def test_fix_pr_with_nothing_to_fix_asks_nobody(db_session, client, github):
    user, _ = await _user(db_session, client)
    finding = await _repo_finding(db_session, user, vcs_type="subversion")
    run = await _start(db_session, user, agent_id="remediation_agent")
    llm = ScriptedLLM(_ask("open_fix_pull_request", finding_id=finding.id), _answer("Not supported."))

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    assert (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).first() is None
    assert "not supported on subversion" in json.loads(llm.calls[1][0][-1]["content"])["error"]


async def test_fix_finds_the_repository_the_way_real_repository_scans_record_it(db_session, client, github):
    """Repository scans store account + repository name, and no integration id."""
    user, _ = await _user(db_session, client)
    finding = await _repo_finding(db_session, user)
    scan = await db_session.get(Scan, finding.scan_id)
    scan.integration_id, scan.repository = None, None
    scan.account_name, scan.repository_name = "acme", "infra"
    await db_session.commit()

    prepared = await fix_pr.prepare_fix(db_session, user.organization_id, finding.id)

    assert prepared["repository"] == "acme/infra"


async def test_a_github_app_connection_gets_a_fresh_token_and_says_so_when_it_cannot(db_session, client, github, monkeypatch):
    user, _ = await _user(db_session, client)
    finding = await _repo_finding(db_session, user)
    integration = (await db_session.execute(select(Integration))).scalars().first()
    integration.auth_method, integration.installation_id = "github_app", 4242
    await db_session.commit()
    used = []

    async def issue(self, installation_id):
        return {"token": f"installation-{installation_id}"}

    monkeypatch.setattr(FakeGitHub, "create_installation_token", issue, raising=False)
    monkeypatch.setattr(FakeGitHub, "get_default_branch", lambda self, repo: used.append(self.token) or _main(), raising=False)

    await fix_pr.prepare_fix(db_session, user.organization_id, finding.id)
    assert used == ["installation-4242"]                 # not the stored placeholder

    async def refuse(self, installation_id):
        raise RuntimeError("app uninstalled")

    monkeypatch.setattr(FakeGitHub, "create_installation_token", refuse, raising=False)
    with pytest.raises(fix_pr.FixError, match="GitHub App token could not be issued"):
        await fix_pr.prepare_fix(db_session, user.organization_id, finding.id)


async def _main():
    return "main"


async def test_fix_preview_endpoint_returns_the_diff_and_writes_nothing(db_session, client, github):
    user, _ = await _user(db_session, client)
    finding = await _repo_finding(db_session, user)
    headers = await get_auth_headers_for(client, user.email)

    resp = await client.post("/api/v1/agents/autofix", json={"finding_ids": [finding.id, 999999]}, headers=headers)

    assert resp.status_code == 200
    first, missing = resp.json()["results"]
    assert first["status"] == "fix_generated" and '+  acl = "private"' in first["diff"]
    assert missing["status"] == "no_fix"
    assert github.writes == []


# ── writes outside an approved run ──────────────────────────────────

async def test_chat_cannot_change_data(db_session, client):
    user, _ = await _user(db_session, client)
    scan = await create_scan_in_db(db_session, user.organization_id)
    finding = await create_finding_in_db(db_session, scan.id)
    await db_session.commit()

    out = json.loads(await execute_tool(
        ToolContext(db=db_session, organization_id=user.organization_id),
        "triage_finding", {"finding_id": finding.id, "status": "resolved"},
    ))

    assert "needs approval" in out["error"]
    await db_session.refresh(finding)
    assert finding.status == "open"


async def test_copilot_chat_stream_answers(db_session, client):
    """The chat page's endpoint: the reply is produced by a background task."""
    _, headers = await _user(db_session, client)

    resp = await client.post("/api/v1/agents/chat/stream", json={"message": "Hi"}, headers=headers)

    assert resp.status_code == 200
    events = [json.loads(line[6:]) for line in resp.text.splitlines() if line.startswith("data: ")]
    assert events[0]["type"] == "meta"
    assert not [e for e in events if e.get("type") == "error"], events
    assert events[-1]["done"] is True


def test_every_write_tool_is_classified():
    """A tool whose name says it changes something must not default to read-only."""
    verbs = ("triage", "open_", "create", "delete", "update", "remediate", "apply", "revoke", "block", "notify")
    for tool in TOOL_SCHEMAS:
        name = tool["function"]["name"]
        if name.startswith(verbs):
            assert runtime.tool_risk(name) != runtime.READ, name


async def test_slack_message_needs_a_connected_slack_and_an_approval(db_session, client):
    from app.models.org_settings import OrgSettings

    user, _ = await _user(db_session, client)
    org_id = user.organization_id
    ask = lambda: _ask("send_slack_message", message="Public bucket found", severity="high")  # noqa: E731

    run = await _start(db_session, user, agent_id="automation_engineer")
    llm = ScriptedLLM(ask(), _answer("Slack is not connected."))
    run = await runtime.execute_run(db_session, run.id, llm=llm)           # Slack not connected: nobody is asked
    assert run.status == "completed"
    assert (await db_session.execute(select(AgentApproval))).first() is None
    assert "not connected" in json.loads(llm.calls[1][0][-1]["content"])["error"]

    row = (await db_session.execute(
        select(OrgSettings).where(OrgSettings.organization_id == org_id)
    )).scalar_one_or_none() or OrgSettings(organization_id=org_id)
    row.notification_prefs = {"slack_enabled": True, "slack_webhook": "https://hooks.slack.test/x"}
    db_session.add(row)
    await db_session.commit()
    run = await runtime.create_run(
        db_session, organization_id=org_id, user_id=run.user_id, agent_id="automation_engineer", goal="Alert the team",
    )
    run = await runtime.execute_run(db_session, run.id, llm=ScriptedLLM(ask()))   # connected: waits for a person

    assert run.status == "awaiting_approval"
    approval = (await db_session.execute(select(AgentApproval))).scalar_one()
    assert approval.risk == "external_write" and approval.preview == "[HIGH] Public bucket found"


async def test_draft_ticket_cannot_read_another_organizations_finding(db_session, client):
    owner, _ = await _user(db_session, client)
    other, _ = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    scan = await create_scan_in_db(db_session, owner.organization_id)
    finding = await create_finding_in_db(db_session, scan.id, title="Owner secret finding")
    await db_session.commit()

    out = await execute_tool(
        ToolContext(db=db_session, organization_id=other.organization_id), "draft_ticket", {"finding_id": finding.id},
    )

    assert "Owner secret finding" not in out and "not found" in out


# ── delegation ──────────────────────────────────────────────────────

async def test_delegation_runs_a_read_only_child_and_returns_its_answer(db_session, client):
    user, _ = await _user(db_session, client)
    scan = await create_scan_in_db(db_session, user.organization_id)
    finding = await create_finding_in_db(db_session, scan.id)
    await db_session.commit()
    run = await _start(db_session, user, agent_id="devsecops_coach")
    llm = ScriptedLLM(
        _ask("delegate_to_agent", target_agent="triage_agent", task="Check the open findings"),   # parent
        _ask("triage_finding", "child_call", finding_id=finding.id, status="resolved"),             # child tries to write
        _answer("Child: one open finding; I could not change it."),                                 # child
        _answer("Parent: summarised the child's result."),                                          # parent
    )

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed" and run.result.startswith("Parent:")
    child = (await db_session.execute(select(AgentRun).where(AgentRun.parent_run_id == run.id))).scalar_one()
    assert (child.agent_id, child.trigger, child.status) == ("triage_agent", "delegation", "completed")
    assert [s.status for s in await _steps(db_session, child.id) if s.kind == "tool"] == ["denied"]
    assert (await db_session.execute(select(AgentApproval))).first() is None
    await db_session.refresh(finding)
    assert finding.status == "open"
    parent_step = [s for s in await _steps(db_session, run.id) if s.kind == "delegation"][0]
    assert "Child: one open finding" in parent_step.output
    assert "delegate_to_agent" not in {t["function"]["name"] for t in llm.calls[1][1]}   # no further delegation


# ── role tool limits ────────────────────────────────────────────────

async def test_tool_limits_come_from_the_users_own_roles(db_session, client):
    user, _ = await _user(db_session, client)
    limited = Role(name="Limited", slug="limited-test", allowed_tools=["list_findings"], allowed_agents=[])
    other_users_role = Role(name="Other", slug="other-test", allowed_tools=["get_finding"], allowed_agents=[])
    db_session.add_all([limited, other_users_role])
    await db_session.flush()
    from app.models.rbac import UserRole as UR

    await db_session.execute(UR.__table__.delete().where(UR.user_id == user.id))
    db_session.add(UserRole(user_id=user.id, role_id=limited.id))
    await db_session.commit()

    tools = await _apply_rbac_tool_filter(db_session, user.organization_id, None, TOOL_SCHEMAS, user.id)

    assert [t["function"]["name"] for t in tools] == ["list_findings"]
    assert await _apply_rbac_tool_filter(db_session, user.organization_id, None, TOOL_SCHEMAS, None) == TOOL_SCHEMAS


# ── endpoints that never worked ─────────────────────────────────────

async def test_auto_triage_never_hides_a_finding_because_of_its_path(db_session, client):
    user, _ = await _user(db_session, client)
    scan = await create_scan_in_db(db_session, user.organization_id)
    in_tests = await create_finding_in_db(db_session, scan.id, title="Key in fixture")
    in_tests.file_path = "tests/fixtures/main.tf"
    real = await create_finding_in_db(db_session, scan.id, severity="CRITICAL", title="Public bucket exposed")
    await db_session.commit()
    headers = await get_auth_headers_for(client, user.email)

    resp = await client.post("/api/v1/agents/auto-triage", json={"limit": 10}, headers=headers)

    assert resp.status_code == 200 and resp.json()["triaged"] == 1
    await db_session.refresh(in_tests)
    await db_session.refresh(real)
    assert (in_tests.status, in_tests.is_ignored) == ("open", False)      # a key in a fixture can be a real key
    suggestion = next(r for r in resp.json()["results"] if r["finding_id"] == in_tests.id)
    assert "Possible false positive" in suggestion["reason"]
    assert real.status == "triaged"


async def test_notes_added_one_after_another_are_all_kept(db_session, client):
    user, _ = await _user(db_session, client)
    scan = await create_scan_in_db(db_session, user.organization_id)
    finding = await create_finding_in_db(db_session, scan.id)
    await db_session.commit()
    headers = await get_auth_headers_for(client, user.email)

    for text in ("first", "second", "third"):
        resp = await client.post(f"/api/v1/findings/{finding.id}/notes", json={"text": text}, headers=headers)
        assert resp.status_code in (200, 201), resp.text

    stored = (await client.get(f"/api/v1/findings/{finding.id}", headers=headers)).json()["notes"]
    assert [n["text"] for n in stored] == ["first", "second", "third"]

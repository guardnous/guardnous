"""Triage: decisions that survive rescans, the queue an agent reads, and reviewed batch decisions."""

import json

from sqlalchemy import select

from app.models.agent import AgentApproval
from app.models.cve import CVE
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import triage_memory
from app.services.agents import runtime
from app.services.agents.tools import ToolContext, execute_tool
from tests.conftest import create_finding_in_db, create_scan_in_db
from tests.test_agent_runtime import ScriptedLLM, _answer, _ask, _start, _user, get_auth_headers_for


async def _repo_scan(db, org, repo="infra", account="acme") -> Scan:
    scan = await create_scan_in_db(db, org)
    scan.repository_name, scan.account_name = repo, account
    await db.flush()
    return scan


async def _found(db, scan, rule, path="main.tf", resource="bucket", severity="HIGH", **fields) -> Finding:
    finding = await create_finding_in_db(db, scan.id, severity=severity, title=f"{rule} on {resource}", rule_id=rule)
    finding.file_path, finding.resource_name = path, resource
    for name, value in fields.items():
        setattr(finding, name, value)
    await db.flush()
    return finding


async def _tool(db, org, name, **args) -> dict:
    return json.loads(await execute_tool(ToolContext(db=db, organization_id=org), name, args))


# ── decisions survive the next scan ─────────────────────────────────

async def test_the_next_scan_keeps_earlier_decisions(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    first = await _repo_scan(db_session, org)
    wrong = await _found(db_session, first, "CKV_1", line_number=10)
    real = await _found(db_session, first, "CKV_2")
    fixed = await _found(db_session, first, "CKV_3")
    await triage_memory.decide(db_session, wrong, "false_positive", reason="bucket holds public docs", author="ana@example.com")
    await triage_memory.decide(db_session, real, "triaged", reason="fix this sprint", assigned_to="ben", author="ana@example.com")
    await triage_memory.decide(db_session, fixed, "resolved", author="ana@example.com")
    elsewhere = await _repo_scan(db_session, org, repo="other-repo")
    await _found(db_session, elsewhere, "CKV_9", status="false_positive")
    await db_session.commit()

    second = await _repo_scan(db_session, org)
    again_wrong = await _found(db_session, second, "CKV_1", line_number=42)      # the line moved
    again_real = await _found(db_session, second, "CKV_2")
    back = await _found(db_session, second, "CKV_3")
    new = await _found(db_session, second, "CKV_4")
    other_repo_rule = await _found(db_session, second, "CKV_9")
    kept = await triage_memory.carry_over(db_session, second)

    assert kept == {"carried": 2, "reappeared": 1}
    assert (again_wrong.status, again_wrong.is_ignored) == ("false_positive", True)
    assert again_wrong.false_positive_reason == "bucket holds public docs"
    assert "ana@example.com" == again_wrong.notes[0]["author"] and f"finding #{wrong.id}" in again_wrong.notes[-1]["text"]
    assert (again_real.status, again_real.assigned_to) == ("triaged", "ben")
    assert back.status == "open" and "marked resolved" in back.notes[-1]["text"]     # fixed, then found again
    assert new.status == "open" and not new.notes
    assert other_repo_rule.status == "open"                                          # decided for another repository


async def test_decisions_do_not_cross_organizations(db_session, client):
    user, _ = await _user(db_session, client)
    other, _ = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    theirs = await _found(db_session, await _repo_scan(db_session, other.organization_id), "CKV_1")
    await triage_memory.decide(db_session, theirs, "false_positive", reason="not ours to judge", author="x")
    await db_session.commit()

    scan = await _repo_scan(db_session, user.organization_id)
    mine = await _found(db_session, scan, "CKV_1")

    assert await triage_memory.carry_over(db_session, scan) == {"carried": 0, "reappeared": 0}
    assert mine.status == "open"


async def test_a_decision_reaches_the_same_finding_in_older_scans_and_can_be_undone(db_session, client):
    user, headers = await _user(db_session, client)
    org = user.organization_id
    old = await _found(db_session, await _repo_scan(db_session, org), "CKV_1")
    latest = await _found(db_session, await _repo_scan(db_session, org), "CKV_1")
    unrelated = await _found(db_session, await _repo_scan(db_session, org), "CKV_1", resource="another-bucket")
    await db_session.commit()
    headers = await get_auth_headers_for(client, user.email)

    resp = await client.post(f"/api/v1/findings/{latest.id}/triage", headers=headers,
                             json={"status": "false_positive", "reason": "test data only"})
    assert resp.status_code == 200
    for finding in (old, latest, unrelated):
        await db_session.refresh(finding)
    assert (old.status, old.is_ignored) == ("false_positive", True) and f"#{latest.id}" in old.notes[-1]["text"]
    assert unrelated.status == "open"

    await client.post(f"/api/v1/findings/{latest.id}/triage", headers=headers, json={"status": "open"})
    for finding in (old, latest):
        await db_session.refresh(finding)
    assert (latest.status, latest.is_ignored, latest.false_positive_reason) == ("open", False, None)
    assert (old.status, old.is_ignored) == ("open", False)


async def test_scanning_the_same_file_again_keeps_the_decision_end_to_end(db_session, client):
    user, _ = await _user(db_session, client)
    headers = await get_auth_headers_for(client, user.email)
    body = {"scan_type": "terraform", "file_name": "main.tf",
            "source": 'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n  acl    = "public-read"\n}\n'}

    first = await client.post("/api/v1/scans", headers=headers, json=body)
    assert first.status_code in (200, 201), first.text
    found = (await db_session.execute(select(Finding).where(Finding.scan_id == first.json()["id"]))).scalars().all()
    assert found, "the sample file should produce findings"
    await client.post(f"/api/v1/findings/{found[0].id}/triage", headers=headers,
                      json={"status": "false_positive", "reason": "public on purpose"})

    second = await client.post("/api/v1/scans", headers=headers, json=body)
    again = (await db_session.execute(select(Finding).where(Finding.scan_id == second.json()["id"]))).scalars().all()
    same = next(f for f in again if triage_memory.finding_key(f) == triage_memory.finding_key(found[0]))
    assert (same.status, same.is_ignored, same.false_positive_reason) == ("false_positive", True, "public on purpose")
    assert all(f.status == "open" for f in again if f.id != same.id)


# ── the queue ───────────────────────────────────────────────────────

async def test_queue_lists_the_latest_assessment_once_with_evidence(db_session, client):
    user, _ = await _user(db_session, client)
    other, _ = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    org = user.organization_id
    await _found(db_session, await _repo_scan(db_session, org), "CKV_1")                    # older scan: not listed
    latest = await _repo_scan(db_session, org)
    low = await _found(db_session, latest, "CKV_1", severity="LOW")
    exploited = await _found(db_session, latest, "CVE-RULE", severity="CRITICAL", cve_id="CVE-2024-0001")
    fixture = await _found(db_session, latest, "SECRET", path="tests/fixtures/app.env", severity="HIGH")
    await _found(db_session, latest, "DONE", status="triaged")
    await _found(db_session, await _repo_scan(db_session, other.organization_id), "THEIRS", severity="CRITICAL")
    db_session.add(CVE(cve_id="CVE-2024-0001", severity="CRITICAL", cvss_score=9.8, is_kev=True, epss_score=0.91))
    await db_session.commit()

    queue = await _tool(db_session, org, "list_triage_queue")

    assert [f["id"] for f in queue["findings"]] == [exploited.id, fixture.id, low.id]       # most severe first
    assert queue["waiting"] == 3 and queue["waiting_by_severity"] == {"CRITICAL": 1, "HIGH": 1, "LOW": 1}
    first, second, third = queue["findings"]
    assert first["cve"] == {"id": "CVE-2024-0001", "known_exploited": True, "exploit_probability": 0.91, "cvss": 9.8}
    assert first["target"] == "acme/infra"
    assert "Check the content" in second["looks_like_test_code"] and "looks_like_test_code" not in third
    assert third["seen_in_assessments"] == 2                                                # reported in both scans

    page = await _tool(db_session, org, "list_triage_queue", limit=2)
    assert page["returned"] == 2 and page["next_offset"] == 2
    assert (await _tool(db_session, org, "list_triage_queue", severity="LOW"))["findings"][0]["id"] == low.id


# ── an agent proposes a list, a person approves it once ─────────────

async def test_agent_batch_changes_nothing_until_the_list_is_approved(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    scan = await _repo_scan(db_session, org)
    real = await _found(db_session, scan, "CKV_1", severity="CRITICAL")
    wrong = await _found(db_session, scan, "CKV_2", path="tests/unit/sample.tf")
    lazy = await _found(db_session, scan, "CKV_3")
    older_copy = await _found(db_session, await _repo_scan(db_session, org), "CKV_2", path="tests/unit/sample.tf")
    await db_session.commit()
    run = await _start(db_session, user, goal="Triage the queue")
    llm = ScriptedLLM(
        _ask("triage_findings", decisions=[
            {"finding_id": real.id, "status": "triaged", "reason": "Bucket is public and holds customer exports."},
            {"finding_id": wrong.id, "status": "false_positive", "reason": "Fixture with a placeholder bucket; never deployed."},
            {"finding_id": lazy.id, "status": "false_positive", "reason": "fp"},
            {"finding_id": 999999, "status": "triaged", "reason": "This finding does not exist."},
        ]),
        _answer("Proposed 2 decisions."),
    )

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "awaiting_approval"
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    assert approval.risk == "internal_write" and "2 findings" in approval.summary and "1 of them will leave" in approval.summary
    preview = approval.preview
    assert preview.index("Hide as false positive (1)") < preview.index("Mark triaged (1)")   # what disappears comes first
    assert f"#{wrong.id}" in preview and "tests/unit/sample.tf" in preview and "never deployed" in preview
    assert f"#{lazy.id}: marking 'false_positive' needs a specific reason." in preview
    assert "#999999: no such finding." in preview
    for finding in (real, wrong, lazy):
        await db_session.refresh(finding)
        assert finding.status == "open"

    # someone triages one of them by hand before the list is approved
    await triage_memory.decide(db_session, real, "in_progress", author=user.email)
    await db_session.commit()
    await runtime.decide_approval(db_session, approval, user, approve=True)
    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    for finding in (real, wrong, lazy, older_copy):
        await db_session.refresh(finding)
    assert (wrong.status, wrong.is_ignored) == ("false_positive", True)
    assert wrong.notes[-1]["author"] == f"GuardNous AI (approved by {user.email})"
    assert older_copy.status == "false_positive"            # the same finding in the older scan
    assert real.status == "in_progress"                     # the hand-made decision was not overwritten
    assert lazy.status == "open"
    result = json.loads(llm.calls[1][0][-1]["content"])
    assert result["applied"] == 1 and result["skipped_because_they_changed_meanwhile"] == [real.id]


async def test_a_batch_with_nothing_valid_asks_nobody(db_session, client):
    user, _ = await _user(db_session, client)
    run = await _start(db_session, user)
    llm = ScriptedLLM(
        _ask("triage_findings", decisions=[{"finding_id": 424242, "status": "triaged", "reason": "Does not exist at all."}]),
        _answer("Nothing to do."),
    )

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    assert (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).first() is None
    assert "no such finding" in json.loads(llm.calls[1][0][-1]["content"])["error"]


async def test_batch_triage_is_refused_in_chat_and_without_permission(db_session, client):
    from app.services.agents.registry import filter_tools_for_agent, get_agent
    from app.services.agents.tools import TOOL_SCHEMAS

    user, _ = await _user(db_session, client)
    out = await _tool(db_session, user.organization_id, "triage_findings", decisions=[])
    assert "needs approval" in out["error"]

    offered = {t["function"]["name"] for t in filter_tools_for_agent(get_agent("triage_agent"), TOOL_SCHEMAS)}
    assert {"list_triage_queue", "triage_findings", "get_cloud_resource"} <= offered
    allowed = {
        t["function"]["name"]
        for t in runtime.tools_for_run(get_agent("triage_agent"), {"findings:read", "agents:create"}, delegated=False)
    }
    assert "list_triage_queue" in allowed and "triage_findings" not in allowed

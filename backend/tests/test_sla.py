"""SLA for findings: deadlines by severity, a clock that survives rescans, status, reporting and backfill."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import sla, triage_memory
from app.services.cloud_posture.engine import evaluate_account
from tests.test_agent_runtime import _user, get_auth_headers_for
from tests.test_cloud_posture import ACCOUNT, SSH_OPEN, _sync
from tests.test_settings_access import _viewer
from tests.test_triage import _found, _repo_scan

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)


def _utc(moment):
    return sla._aware(moment)


async def _scan_with(db, org, rules: dict, now, repo="infra") -> dict:
    """A scan of ``repo`` that reports ``rules`` ({rule_id: severity}), finalised the way a real scan is."""
    scan = await _repo_scan(db, org, repo=repo)
    found = {rule: await _found(db, scan, rule, severity=severity) for rule, severity in rules.items()}
    await triage_memory.carry_over(db, scan)
    await sla.set_deadlines(db, scan, now=now)
    return found


# ── the deadline ────────────────────────────────────────────────────

async def test_the_deadline_follows_the_severity_and_the_settings(db_session, client, monkeypatch):
    user, _ = await _user(db_session, client)
    severities = {"R-C": "CRITICAL", "R-H": "HIGH", "R-M": "MEDIUM", "R-L": "LOW", "R-I": "INFO"}

    found = await _scan_with(db_session, user.organization_id, severities, T0)

    days = {rule: (f.sla_deadline - T0).days if f.sla_deadline else None for rule, f in found.items()}
    assert days == {"R-C": 7, "R-H": 30, "R-M": 90, "R-L": 180, "R-I": None}
    assert all(f.first_seen_at == T0 for f in found.values())
    assert sla.status(found["R-I"], T0) == "none" and sla.days_remaining(found["R-I"], T0) is None

    monkeypatch.setattr(settings, "SLA_DAYS_HIGH", 14)
    monkeypatch.setattr(settings, "SLA_DAYS_LOW", 0)                    # 0 = no SLA for that severity
    changed = await _scan_with(db_session, user.organization_id, severities, T0, repo="another-repo")

    assert changed["R-H"].sla_deadline == T0 + 14 * DAY
    assert changed["R-L"].sla_deadline is None and changed["R-L"].first_seen_at == T0
    assert changed["R-C"].sla_deadline == T0 + 7 * DAY


async def test_a_rescan_does_not_reset_the_clock(db_session, client, monkeypatch):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    first = await _scan_with(db_session, org, {"CKV_1": "HIGH"}, T0)
    await db_session.commit()

    monkeypatch.setattr(settings, "SLA_DAYS_HIGH", 5)                   # a later policy change does not move it either
    second = await _scan_with(db_session, org, {"CKV_1": "HIGH", "CKV_NEW": "HIGH"}, T0 + 10 * DAY)

    again, new = second["CKV_1"], second["CKV_NEW"]
    assert again.id != first["CKV_1"].id
    assert (again.first_seen_at, again.sla_deadline) == (T0, T0 + 30 * DAY)
    assert (new.first_seen_at, new.sla_deadline) == (T0 + 10 * DAY, T0 + 15 * DAY)
    assert sla.days_remaining(again, T0 + 10 * DAY) == 20

    # another repository with the same rule has its own clock
    elsewhere = await _scan_with(db_session, org, {"CKV_1": "HIGH"}, T0 + 10 * DAY, repo="other-repo")
    assert elsewhere["CKV_1"].first_seen_at == T0 + 10 * DAY


async def test_the_worker_variant_keeps_the_clock_too(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    await _scan_with(db_session, org, {"CKV_1": "CRITICAL"}, T0)
    scan = await _repo_scan(db_session, org)
    again = await _found(db_session, scan, "CKV_1", severity="CRITICAL")
    await db_session.commit()

    engine = create_engine(settings.DATABASE_URL_SYNC)
    try:
        with Session(engine) as db:
            assert sla.set_deadlines_sync(db, db.get(Scan, scan.id), now=T0 + 3 * DAY) == 1
            assert sla.set_deadlines_sync(db, db.get(Scan, scan.id), now=T0 + 5 * DAY) == 0     # already set
            db.commit()
    finally:
        engine.dispose()

    await db_session.refresh(again)
    assert (_utc(again.first_seen_at), _utc(again.sla_deadline)) == (T0, T0 + 7 * DAY)


async def test_a_finding_that_was_resolved_and_comes_back_gets_a_new_clock(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    first = await _scan_with(db_session, org, {"CKV_1": "HIGH"}, T0)
    await triage_memory.decide(db_session, first["CKV_1"], "resolved", author="ana@example.com")
    await db_session.commit()

    back = (await _scan_with(db_session, org, {"CKV_1": "HIGH"}, T0 + 40 * DAY))["CKV_1"]

    assert back.status == "open" and "Found again" in back.notes[-1]["text"]
    assert (back.first_seen_at, back.sla_deadline) == (T0 + 40 * DAY, T0 + 70 * DAY)


async def test_a_false_positive_has_no_sla_until_it_is_reopened(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    first = await _scan_with(db_session, org, {"CKV_1": "HIGH"}, T0)
    await triage_memory.decide(db_session, first["CKV_1"], "false_positive", reason="test data", author="ana@example.com")
    await db_session.commit()
    assert sla.status(first["CKV_1"], T0 + 60 * DAY) == "none"          # even though its old deadline has passed

    again = (await _scan_with(db_session, org, {"CKV_1": "HIGH"}, T0 + 10 * DAY))["CKV_1"]
    assert (again.status, again.sla_deadline, again.first_seen_at) == ("false_positive", None, T0)
    assert sla.status(again, T0 + 60 * DAY) == "none"
    await db_session.commit()

    headers = await get_auth_headers_for(client, user.email)
    resp = await client.post(f"/api/v1/findings/{again.id}/triage", headers=headers, json={"status": "open"})
    assert resp.status_code == 200
    body = resp.json()
    assert _utc(datetime.fromisoformat(body["sla_deadline"])) == T0 + 30 * DAY      # from when it was first seen
    assert body["sla_status"] == "overdue" and body["sla_days_remaining"] < 0


async def test_cloud_findings_get_a_deadline_when_opened_and_a_new_one_when_reopened(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=SSH_OPEN)

    await evaluate_account(db_session, org, "aws", ACCOUNT, now=T0)
    finding = (await db_session.execute(select(Finding).where(Finding.rule_id == "GN-AWS-SG-001"))).scalar_one()
    assert finding.severity == "CRITICAL"
    assert (_utc(finding.first_seen_at), _utc(finding.sla_deadline)) == (T0, T0 + 7 * DAY)

    await evaluate_account(db_session, org, "aws", ACCOUNT, now=T0 + 2 * DAY)       # still failing: same clock
    await db_session.refresh(finding)
    assert _utc(finding.sla_deadline) == T0 + 7 * DAY

    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=[])
    await evaluate_account(db_session, org, "aws", ACCOUNT, now=T0 + 3 * DAY)
    await db_session.refresh(finding)
    assert sla.status(finding, T0 + 20 * DAY) == "met"

    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=SSH_OPEN)
    await evaluate_account(db_session, org, "aws", ACCOUNT, now=T0 + 20 * DAY)
    await db_session.refresh(finding)
    assert (_utc(finding.first_seen_at), _utc(finding.sla_deadline)) == (T0 + 20 * DAY, T0 + 27 * DAY)


# ── the status ──────────────────────────────────────────────────────

def _finding(severity="HIGH", days=30, **fields):
    values = {
        "severity": severity, "status": "open", "is_fixed": False, "is_ignored": False, "resolved_at": None,
        "first_seen_at": T0, "created_at": T0, "sla_deadline": T0 + days * DAY, **fields,
    }
    return SimpleNamespace(**values)


def test_each_status_at_a_given_time():
    high = _finding()                                                    # 30 days: due soon in the last 6 (20%)
    assert (sla.status(high, T0), sla.days_remaining(high, T0)) == ("on_track", 30)
    assert sla.status(high, T0 + 23 * DAY) == "on_track"
    assert (sla.status(high, T0 + 24 * DAY), sla.days_remaining(high, T0 + 24 * DAY)) == ("due_soon", 6)
    assert sla.status(high, T0 + 30 * DAY) == "due_soon"                 # the deadline itself is not yet late
    assert (sla.status(high, T0 + 35 * DAY), sla.days_remaining(high, T0 + 35 * DAY)) == ("overdue", -5)

    critical = _finding("CRITICAL", 7)                                   # 20% would be 1.4 days: the 3-day minimum applies
    assert sla.status(critical, T0 + 3 * DAY) == "on_track"
    assert sla.status(critical, T0 + 4 * DAY) == "due_soon"

    in_time = _finding(status="resolved", is_fixed=True, resolved_at=T0 + 29 * DAY)
    late = _finding(status="resolved", is_fixed=True, resolved_at=T0 + 31 * DAY)
    assert sla.status(in_time, T0 + 90 * DAY) == "met" and sla.status(late, T0 + 90 * DAY) == "missed"
    assert sla.days_remaining(in_time, T0 + 90 * DAY) is None

    assert sla.status(_finding(sla_deadline=None), T0) == "none"
    assert sla.status(_finding(status="false_positive", is_ignored=True), T0 + 99 * DAY) == "none"
    assert sla.status(_finding(first_seen_at=None, created_at=T0.replace(tzinfo=None),
                               sla_deadline=(T0 + 30 * DAY).replace(tzinfo=None)), T0 + 25 * DAY) == "due_soon"


# ── the API ─────────────────────────────────────────────────────────

async def _with_deadline(db, scan, rule, days_from_now, allowed=30, **fields) -> Finding:
    """A finding whose deadline is ``days_from_now`` days away, out of ``allowed`` days in total."""
    deadline = datetime.now(timezone.utc) + timedelta(days=days_from_now, minutes=5)
    return await _found(
        db, scan, rule, resource=rule, sla_deadline=deadline, first_seen_at=deadline - allowed * DAY, **fields,
    )


async def test_the_list_shows_filters_and_sorts_by_sla(db_session, client):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    on_track = await _with_deadline(db_session, scan, "ON-TRACK", 20)
    due_soon = await _with_deadline(db_session, scan, "DUE-SOON", 2)
    overdue = await _with_deadline(db_session, scan, "OVERDUE", -5)
    very_overdue = await _with_deadline(db_session, scan, "VERY-OVERDUE", -9, severity="LOW")
    await _found(db_session, scan, "NO-SLA", resource="NO-SLA", severity="INFO")
    await _with_deadline(db_session, scan, "FIXED-LATE", -5, status="resolved", is_fixed=True,
                         resolved_at=datetime.now(timezone.utc))
    await _with_deadline(db_session, scan, "NOT-A-PROBLEM", -5, status="false_positive", is_ignored=True)
    await db_session.commit()

    async def listed(**params) -> list[dict]:
        resp = await client.get("/api/v1/findings", headers=headers, params=params)
        assert resp.status_code == 200, resp.text
        assert resp.json()["total"] == len(resp.json()["items"])
        return resp.json()["items"]

    everything = {item["rule_id"]: item for item in await listed()}
    assert {rule: (item["sla_status"], item["sla_days_remaining"]) for rule, item in everything.items()} == {
        "ON-TRACK": ("on_track", 20), "DUE-SOON": ("due_soon", 2), "OVERDUE": ("overdue", -4),
        "VERY-OVERDUE": ("overdue", -8), "NO-SLA": ("none", None), "FIXED-LATE": ("missed", None),
        "NOT-A-PROBLEM": ("none", None),
    }
    assert everything["ON-TRACK"]["first_seen_at"] and everything["ON-TRACK"]["sla_deadline"]

    assert [i["id"] for i in await listed(sla="overdue")] == [very_overdue.id, overdue.id]      # soonest deadline first
    assert [i["id"] for i in await listed(sla="due_soon")] == [due_soon.id]
    assert [i["id"] for i in await listed(sla="on_track")] == [on_track.id]
    assert [i["id"] for i in await listed(sla="overdue", severity="LOW")] == [very_overdue.id]
    paged = (await client.get("/api/v1/findings", headers=headers,
                              params={"sla": "overdue", "page": 2, "page_size": 1})).json()
    assert ([i["id"] for i in paged["items"]], paged["total"]) == ([overdue.id], 2)

    by_deadline = [i["rule_id"] for i in await listed(sort="sla_deadline")]
    assert by_deadline[0] == "VERY-OVERDUE" and by_deadline[-1] == "NO-SLA"
    assert by_deadline.index("DUE-SOON") < by_deadline.index("ON-TRACK")
    # without the new parameters the order is what it always was: severity, then newest
    assert [i["rule_id"] for i in await listed()][-1] == "VERY-OVERDUE"

    assert (await client.get("/api/v1/findings", headers=headers, params={"sla": "late"})).status_code == 400
    assert (await client.get("/api/v1/findings", headers=headers, params={"sort": "title"})).status_code == 400
    detail = (await client.get(f"/api/v1/findings/{overdue.id}", headers=headers)).json()
    assert (detail["sla_status"], detail["sla_days_remaining"]) == ("overdue", -4)


async def test_the_summary_counts_the_latest_assessment_of_each_target_once(db_session, client):
    user, headers = await _user(db_session, client)
    other, other_headers = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    org = user.organization_id
    resolved_at = datetime.now(timezone.utc) - DAY

    old = await _repo_scan(db_session, org)
    await _with_deadline(db_session, old, "CKV_1", -3, severity="CRITICAL")
    await _with_deadline(db_session, old, "GONE", -3)                                # not in the newer scan any more
    for scan in (old, await _repo_scan(db_session, org)):                            # resolved in both: counted once
        await _with_deadline(db_session, scan, "MET", 5, status="resolved", is_fixed=True, resolved_at=resolved_at)
    latest = (await db_session.execute(select(Scan).where(Scan.organization_id == org).order_by(Scan.id.desc()))).scalars().first()
    worst = await _with_deadline(db_session, latest, "CKV_1", -3, severity="CRITICAL")
    await _with_deadline(db_session, latest, "CKV_2", -1)
    await _with_deadline(db_session, latest, "CKV_3", 2)
    await _with_deadline(db_session, latest, "CKV_4", 25)
    await _found(db_session, latest, "CKV_5", resource="CKV_5", severity="INFO")
    await _with_deadline(db_session, latest, "FP", -3, status="false_positive", is_ignored=True)
    await _with_deadline(db_session, latest, "MISSED", -5, status="resolved", is_fixed=True, resolved_at=resolved_at)
    await _with_deadline(db_session, latest, "LONG-AGO", -200, status="resolved", is_fixed=True,
                         resolved_at=datetime.now(timezone.utc) - 120 * DAY)          # outside the 90 days
    docs = await _repo_scan(db_session, org, repo="docs")                            # a second target
    await _with_deadline(db_session, docs, "CKV_1", -2, severity="LOW")
    theirs = await _repo_scan(db_session, other.organization_id)
    await _with_deadline(db_session, theirs, "CKV_1", -30, severity="CRITICAL")
    await db_session.commit()

    resp = await client.get("/api/v1/findings/sla/summary", headers=headers)
    assert resp.status_code == 200, resp.text                                        # not taken for /{finding_id}
    body = resp.json()

    assert body["open"] == {"overdue": 3, "due_soon": 1, "on_track": 1, "none": 1, "total": 6, "with_sla": 5}
    assert body["by_severity"]["CRITICAL"] == {"overdue": 1, "due_soon": 0, "on_track": 0, "none": 0}
    assert body["by_severity"]["HIGH"] == {"overdue": 1, "due_soon": 1, "on_track": 1, "none": 0}
    assert body["by_severity"]["LOW"]["overdue"] == 1 and body["by_severity"]["INFO"]["none"] == 1
    assert (body["oldest_overdue"]["id"], body["oldest_overdue"]["days_overdue"]) == (worst.id, 2)
    assert body["resolved"] == {"days": 90, "met": 1, "missed": 1, "total": 2, "met_percent": 50.0}
    assert body["has_sla"] is True and body["policy_days"]["CRITICAL"] == 7

    mine_only = (await client.get("/api/v1/findings/sla/summary", headers=other_headers)).json()
    assert mine_only["open"]["overdue"] == 1 and mine_only["open"]["total"] == 1
    assert mine_only["resolved"]["met_percent"] is None
    assert (await client.get("/api/v1/findings/sla/summary")).status_code in (401, 403)


async def test_an_organization_without_findings_has_an_empty_summary(db_session, client):
    _, headers = await _user(db_session, client)

    body = (await client.get("/api/v1/findings/sla/summary", headers=headers)).json()

    assert body["open"]["total"] == 0 and body["oldest_overdue"] is None and body["has_sla"] is False


async def test_changing_the_deadline_by_hand_is_noted_and_needs_permission(db_session, client):
    user, headers = await _user(db_session, client)
    finding = (await _scan_with(db_session, user.organization_id, {"CKV_1": "HIGH"}, T0))["CKV_1"]
    await db_session.commit()
    url = f"/api/v1/findings/{finding.id}"

    resp = await client.patch(url, headers=headers, json={"sla_deadline": "2026-06-30T00:00:00Z"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert _utc(datetime.fromisoformat(body["sla_deadline"])) == datetime(2026, 6, 30, tzinfo=timezone.utc)
    assert body["notes"][-1]["author"] == user.email
    assert body["notes"][-1]["text"] == (
        f"SLA deadline changed from 2026-03-31 12:00 UTC to 2026-06-30 00:00 UTC by {user.email}"
    )

    same = await client.patch(url, headers=headers, json={"sla_deadline": "2026-06-30T00:00:00Z", "assigned_to": "ben"})
    assert len(same.json()["notes"]) == len(body["notes"])                           # nothing changed, nothing noted
    assert (await client.patch(url, headers=headers, json={"sla_deadline": "next friday"})).status_code == 422
    untouched = await client.patch(url, headers=headers, json={"assigned_to": "cy"})
    assert untouched.json()["sla_deadline"] == body["sla_deadline"]                  # leaving it out keeps it

    cleared = await client.patch(url, headers=headers, json={"sla_deadline": None})
    assert cleared.json()["sla_deadline"] is None and cleared.json()["sla_status"] == "none"
    assert cleared.json()["notes"][-1]["text"].endswith(f"to none by {user.email}")

    viewer = await _viewer(db_session, user)
    refused = await client.patch(url, headers=viewer, json={"sla_deadline": "2030-01-01T00:00:00Z"})
    assert refused.status_code == 403
    await db_session.refresh(finding)
    assert finding.sla_deadline is None
    assert (await client.get("/api/v1/findings/sla/summary", headers=viewer)).status_code == 200


# ── findings written before SLA tracking ────────────────────────────

async def test_the_backfill_dates_old_findings_from_their_first_scan_and_runs_once(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    scans = [await _repo_scan(db_session, org) for _ in range(3)]
    january, february, march = (datetime(2026, month, 1, tzinfo=timezone.utc) for month in (1, 2, 3))
    old = await _found(db_session, scans[0], "CKV_1")
    again = await _found(db_session, scans[1], "CKV_1")
    newest = await _found(db_session, scans[2], "CKV_1")
    late_arrival = await _found(db_session, scans[2], "CKV_2", severity="CRITICAL")
    fixed = await _found(db_session, scans[0], "CKV_3", status="resolved", is_fixed=True, resolved_at=january)
    back = await _found(db_session, scans[2], "CKV_3")
    wrong = await _found(db_session, scans[2], "CKV_4", status="false_positive", is_ignored=True)
    info = await _found(db_session, scans[2], "CKV_5", severity="INFO")
    for scan, created in zip(scans, (january, february, march)):
        await db_session.execute(update(Finding).where(Finding.scan_id == scan.id).values(created_at=created))
    await db_session.commit()
    everything = (old, again, newest, late_arrival, fixed, back, wrong, info)

    assert await sla.backfill(db_session) == len(everything)
    await db_session.commit()
    for finding in everything:
        await db_session.refresh(finding)

    def clock(finding):
        return _utc(finding.first_seen_at), _utc(finding.sla_deadline)

    assert clock(old) == clock(again) == clock(newest) == (january, january + 30 * DAY)
    assert clock(late_arrival) == (march, march + 7 * DAY)
    assert clock(fixed) == (january, None)                              # resolved before SLA tracking: not judged
    assert clock(back) == (march, march + 30 * DAY)                     # was resolved, came back in March
    assert clock(wrong) == (march, None) and clock(info) == (march, None)

    before = [clock(finding) for finding in everything]
    assert await sla.backfill(db_session) == 0                          # nothing left to do
    await db_session.commit()
    for finding in everything:
        await db_session.refresh(finding)
    assert [clock(finding) for finding in everything] == before

    await sla.backfill_at_startup()                                     # the startup entry point; never raises


async def test_a_failure_while_setting_deadlines_does_not_fail_the_scan(db_session, client, monkeypatch):
    user, _ = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    finding = await _found(db_session, scan, "CKV_1")

    def broken(*args, **kwargs):
        raise RuntimeError("policy unreadable")

    monkeypatch.setattr(sla, "apply_clock", broken)

    assert await sla.set_deadlines(db_session, scan, now=T0) == 0
    assert finding.sla_deadline is None

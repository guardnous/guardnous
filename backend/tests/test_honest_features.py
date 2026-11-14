"""Tests that features report real results, or say clearly that they have none."""
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import get_auth_headers, login_user, register_user


class TestComplianceIsEvidenceBased:
    @pytest.mark.asyncio
    async def test_no_scans_means_not_assessed_not_compliant(self, client):
        headers = await get_auth_headers(client)
        seeded = await client.post("/api/v1/governance/frameworks/seed", headers=headers)
        assert seeded.status_code in (200, 201), seeded.text

        dashboard = (await client.get("/api/v1/governance/dashboard", headers=headers)).json()
        assert dashboard["frameworks_count"] > 0
        assert dashboard["avg_compliance_score"] is None
        assert dashboard["passing_controls"] == 0

        frameworks = (await client.get("/api/v1/governance/frameworks", headers=headers)).json()
        items = frameworks["items"] if isinstance(frameworks, dict) else frameworks
        assert items and all(f["compliance_score"] is None for f in items)


class TestRiskExceptions:
    @pytest.mark.asyncio
    async def test_requester_cannot_approve_own_exception(self, client):
        headers = await get_auth_headers(client)
        policy = await client.post("/api/v1/governance/policies", headers=headers, json={
            "name": "No secrets", "severity": "high", "rules": [{"categories": ["secrets"]}],
        })
        assert policy.status_code in (200, 201), policy.text

        created = await client.post("/api/v1/governance/exceptions", headers=headers, json={
            "title": "Legacy key", "severity": "high", "justification": "Rotating next sprint",
            "policy_id": policy.json()["id"],
        })
        assert created.status_code in (200, 201), created.text

        approved = await client.patch(
            f"/api/v1/governance/exceptions/{created.json()['id']}/approve", headers=headers
        )
        assert approved.status_code == 403

    @pytest.mark.asyncio
    async def test_exception_needs_a_scope(self, client):
        headers = await get_auth_headers(client)
        resp = await client.post("/api/v1/governance/exceptions", headers=headers, json={
            "title": "Everything", "severity": "high", "justification": "because",
        })
        assert resp.status_code == 400


class TestIAMPosture:
    @pytest.mark.asyncio
    async def test_scan_without_cloud_account_is_refused(self, client):
        headers = await get_auth_headers(client)
        resp = await client.post("/api/v1/iam/scan", headers=headers, json={"cloud_provider": "aws"})
        assert resp.status_code == 409
        identities = await client.get("/api/v1/iam/identities", headers=headers)
        assert identities.json()["total"] == 0

    def test_rules_flag_only_what_the_evidence_shows(self):
        from app.services.iam_posture import analyze

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        old = (now - timedelta(days=400)).isoformat()
        resources = [
            {
                "resource_type": "aws_iam_user", "resource_id": "arn:aws:iam::1:user/root-ish",
                "resource_name": "root-ish",
                "config": {
                    "has_admin_access": True, "has_console_access": True, "mfa_enabled": False,
                    "access_keys": [{"access_key_id": "AKIAOLD", "status": "Active", "created": old}],
                    "created": old,
                },
            },
            {
                "resource_type": "aws_iam_user", "resource_id": "arn:aws:iam::1:user/tidy",
                "resource_name": "tidy",
                "config": {
                    "has_admin_access": False, "has_console_access": True, "mfa_enabled": True,
                    "access_keys": [], "created": (now - timedelta(days=5)).isoformat(),
                    "password_last_used": (now - timedelta(days=1)).isoformat(),
                },
            },
            {"resource_type": "aws_s3_bucket", "resource_id": "b", "resource_name": "b", "config": {}},
        ]

        first = analyze("aws", resources, now=now)
        second = analyze("aws", resources, now=now)
        assert len(first) == 2, "non-IAM resources are ignored"

        by_name = {p.display_name: p for p in first}
        assert by_name["root-ish"].admin_access is True
        assert by_name["root-ish"].threats, "admin without MFA and a 400-day-old key must be flagged"
        assert not by_name["tidy"].threats
        # Same input, same output — nothing is randomly generated
        assert [(p.display_name, p.risk_score, len(p.threats)) for p in first] == \
               [(p.display_name, p.risk_score, len(p.threats)) for p in second]


class TestCloudConnectors:
    @pytest.mark.asyncio
    async def test_bad_credentials_are_not_reported_as_connected(self, client):
        headers = await get_auth_headers(client)
        resp = await client.post("/api/v1/cloud-accounts/test-credentials", headers=headers, json={
            "provider": "aws",
            "credentials": {"access_key_id": "AKIAINVALID", "secret_access_key": "nope"},
        })
        body = resp.json()
        # Either the SDK is missing or AWS rejects the key; never "connected"
        assert resp.status_code >= 400 or body.get("status") == "error", body
        assert body.get("error") or body.get("detail")


class TestRepositoryScan:
    def test_unreadable_repository_fails_the_scan(self, monkeypatch):
        """No integration credentials -> the scan fails; no substitute files are scanned."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        from app.core.database import Base
        from app.models.finding import Finding
        from app.models.organization import Organization
        from app.models.scan import Scan
        from app.tasks import jobs

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        monkeypatch.setattr(jobs, "sync_engine", engine)

        with Session(engine) as db:
            org = Organization(name="Org", slug="org")
            db.add(org)
            db.flush()
            scan = Scan(organization_id=org.id, scan_type="repository", status="pending")
            db.add(scan)
            db.commit()
            scan_id, org_id = scan.id, org.id

        result = jobs.run_quick_repo_scan.run(scan_id, 999, "owner/repo", org_id)
        assert result["status"] == "failed"

        with Session(engine) as db:
            scan = db.get(Scan, scan_id)
            assert scan.status == "failed"
            assert "credentials" in scan.error_message
            assert db.query(Finding).count() == 0


class TestDashboardNumbers:
    @pytest.mark.asyncio
    async def test_pass_rate_counts_real_checks_of_the_latest_assessment(self, client, db_session):
        """It used to report fixed findings as "passed" and open findings as "failed"."""
        from tests.conftest import create_finding_in_db, create_scan_in_db

        user = await register_user(client)
        headers = {"Authorization": f"Bearer {(await login_user(client))['access_token']}"}
        org = user["organization_id"]

        empty = (await client.get("/api/v1/dashboard", headers=headers)).json()
        assert (empty["passed_checks"], empty["failed_checks"]) == (0, 0)

        async with db_session as db:
            old = await create_scan_in_db(db, org)
            old.repository_name, old.policies_passed, old.policies_failed = "web", 1, 99      # superseded below
            new = await create_scan_in_db(db, org)
            new.repository_name, new.policies_passed, new.policies_failed = "web", 22, 17
            cloud = await create_scan_in_db(db, org, scan_type="cloud_posture")
            cloud.source, cloud.stage_details = "cloud://aws/123456789012", {"passed": 13, "failed": 26}
            running = await create_scan_in_db(db, org, status="scanning")
            running.repository_name, running.policies_failed = "api", 500                     # not finished: not counted
            for category in ("IAC", "iac", "Secrets"):
                (await create_finding_in_db(db, new.id)).category = category
            await db.commit()

        body = (await client.get("/api/v1/dashboard", headers=headers)).json()
        assert (body["passed_checks"], body["failed_checks"]) == (22 + 13, 17 + 26)
        assert body["category_breakdown"] == {"iac": 2, "secrets": 1}                         # case merged


class TestFindingOrganization:
    @pytest.mark.asyncio
    async def test_finding_inherits_scan_organization(self, client, db_session):
        from tests.conftest import create_finding_in_db, create_scan_in_db

        user = await register_user(client)
        token = (await login_user(client))["access_token"]
        async with db_session as db:
            scan = await create_scan_in_db(db, user["organization_id"])
            finding = await create_finding_in_db(db, scan.id)
            await db.commit()
            assert finding.organization_id == user["organization_id"]

        resp = await client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"})
        assert resp.json()["total"] == 1

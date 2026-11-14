"""Tests for findings API: CRUD, filtering, bulk update, org isolation."""
import pytest

from tests.conftest import (
    register_user, login_user, get_auth_headers,
    create_scan_in_db, create_finding_in_db,
)


async def _seed_findings(db_session, org_id: int, count: int = 3, severity: str = "HIGH"):
    """Helper: create a scan with N findings in the given org."""
    async with db_session as db:
        scan = await create_scan_in_db(db, org_id)
        findings = []
        for i in range(count):
            f = await create_finding_in_db(
                db, scan.id,
                severity=severity,
                title=f"Finding {i}",
                rule_id=f"RULE-{i:03d}",
            )
            findings.append(f)
        await db.commit()
        return scan, findings


class TestListFindings:
    @pytest.mark.asyncio
    async def test_list_findings_requires_auth(self, client):
        resp = await client.get("/api/v1/findings")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_list_findings_empty(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/findings", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    @pytest.mark.asyncio
    async def test_list_findings_filtered_by_severity(self, client, db_session):
        user_data = await register_user(client)
        login_data = await login_user(client)
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        org_id = user_data["organization_id"]

        async with db_session as db:
            scan = await create_scan_in_db(db, org_id)
            await create_finding_in_db(db, scan.id, severity="CRITICAL", rule_id="C-001")
            await create_finding_in_db(db, scan.id, severity="HIGH", rule_id="H-001")
            await create_finding_in_db(db, scan.id, severity="LOW", rule_id="L-001")
            await db.commit()

        # Filter by CRITICAL
        resp = await client.get("/api/v1/findings?severity=CRITICAL", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["severity"] == "CRITICAL"

        # Filter by LOW
        resp = await client.get("/api/v1/findings?severity=LOW", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 1


class TestFindingDetail:
    @pytest.mark.asyncio
    async def test_finding_detail(self, client, db_session):
        user_data = await register_user(client)
        login_data = await login_user(client)
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        org_id = user_data["organization_id"]

        async with db_session as db:
            scan = await create_scan_in_db(db, org_id)
            finding = await create_finding_in_db(db, scan.id, title="S3 Public Access")
            await db.commit()
            finding_id = finding.id

        resp = await client.get(f"/api/v1/findings/{finding_id}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == finding_id
        assert data["title"] == "S3 Public Access"
        assert data["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_finding_not_found(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/findings/99999", headers=headers)
        assert resp.status_code == 404


class TestFindingUpdate:
    @pytest.mark.asyncio
    async def test_mark_finding_fixed(self, client, db_session):
        user_data = await register_user(client)
        login_data = await login_user(client)
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        org_id = user_data["organization_id"]

        async with db_session as db:
            scan = await create_scan_in_db(db, org_id)
            finding = await create_finding_in_db(db, scan.id)
            await db.commit()
            finding_id = finding.id

        resp = await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=headers,
            json={"is_fixed": True},
        )
        assert resp.status_code == 200
        assert resp.json()["is_fixed"] is True

    @pytest.mark.asyncio
    async def test_mark_finding_ignored(self, client, db_session):
        user_data = await register_user(client)
        login_data = await login_user(client)
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        org_id = user_data["organization_id"]

        async with db_session as db:
            scan = await create_scan_in_db(db, org_id)
            finding = await create_finding_in_db(db, scan.id)
            await db.commit()
            finding_id = finding.id

        resp = await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=headers,
            json={"is_ignored": True, "status": "false_positive"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_ignored"] is True
        assert data["status"] == "false_positive"


class TestBulkUpdate:
    @pytest.mark.asyncio
    async def test_bulk_update_findings(self, client, db_session):
        user_data = await register_user(client)
        login_data = await login_user(client)
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        org_id = user_data["organization_id"]

        async with db_session as db:
            scan = await create_scan_in_db(db, org_id)
            f1 = await create_finding_in_db(db, scan.id, rule_id="B-001")
            f2 = await create_finding_in_db(db, scan.id, rule_id="B-002")
            await db.commit()
            ids = [f1.id, f2.id]

        resp = await client.post(
            "/api/v1/findings/bulk-update",
            headers=headers,
            json={
                "finding_ids": ids,
                "status": "resolved",
                "assigned_to": "engineer@test.com",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["updated"] == 2
        assert set(data["finding_ids"]) == set(ids)

    @pytest.mark.asyncio
    async def test_bulk_update_empty_ids_fails(self, client):
        headers = await get_auth_headers(client)
        resp = await client.post(
            "/api/v1/findings/bulk-update",
            headers=headers,
            json={"finding_ids": [], "status": "resolved"},
        )
        assert resp.status_code == 400


class TestOrgIsolation:
    @pytest.mark.asyncio
    async def test_findings_org_isolation(self, client, db_session):
        """User from org A cannot see findings belonging to org B."""
        # Register org A user
        user_a = await register_user(
            client, email="usera@corpa.com", org_name="Corp A",
        )
        login_a = await login_user(client, email="usera@corpa.com")
        headers_a = {"Authorization": f"Bearer {login_a['access_token']}"}

        # Register org B user
        await register_user(
            client, email="userb@corpb.com", org_name="Corp B",
        )
        login_b = await login_user(client, email="userb@corpb.com")
        headers_b = {"Authorization": f"Bearer {login_b['access_token']}"}

        # Create findings in org A
        async with db_session as db:
            scan_a = await create_scan_in_db(db, user_a["organization_id"])
            await create_finding_in_db(db, scan_a.id, title="Org A Finding", rule_id="A-001")
            await db.commit()

        # Org A can see its findings
        resp = await client.get("/api/v1/findings", headers=headers_a)
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        # Org B cannot see org A findings
        resp = await client.get("/api/v1/findings", headers=headers_b)
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

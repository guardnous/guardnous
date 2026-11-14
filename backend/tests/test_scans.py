"""Tests for scan API: create, list with pagination, scan detail."""
import pytest
from unittest.mock import patch, MagicMock

from tests.conftest import (
    register_user, login_user, get_auth_headers,
    create_scan_in_db, create_finding_in_db,
)


class TestCreateScan:
    @pytest.mark.asyncio
    async def test_trigger_scan_requires_source(self, client):
        """Creating a scan requires auth and a source field."""
        headers = await get_auth_headers(client)

        # Missing source field
        resp = await client.post(
            "/api/v1/scans",
            headers=headers,
            json={"scan_type": "terraform"},
        )
        assert resp.status_code == 422  # validation error

    @pytest.mark.asyncio
    async def test_create_scan_requires_auth(self, client):
        resp = await client.post("/api/v1/scans", json={
            "scan_type": "terraform",
            "source": 'resource "aws_s3_bucket" "b" { bucket = "test" }',
        })
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    @patch("app.api.v1.scans.ScanOrchestrator")
    async def test_create_scan_success(self, mock_orch_cls, client):
        """A valid scan creation returns 201 with scan metadata."""
        mock_orch = MagicMock()
        from app.services.scanners.base import ScanResult

        mock_orch.scan.return_value = MagicMock(findings=[
            ScanResult(
                rule_id="S3_PUBLIC",
                title="S3 bucket is public",
                description="Public access enabled",
                severity="HIGH",
                category="iac",
                cloud_provider="aws",
                resource_type="aws_s3_bucket",
                resource_name="test",
                file_path="main.tf",
                line_number=1,
                remediation="Disable public access",
            )
        ])
        mock_orch_cls.return_value = mock_orch

        headers = await get_auth_headers(client)
        resp = await client.post(
            "/api/v1/scans",
            headers=headers,
            json={
                "scan_type": "terraform",
                "source": 'resource "aws_s3_bucket" "b" { bucket = "test" }',
                "file_name": "main.tf",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["scan_type"] == "terraform"
        assert data["status"] == "completed"
        assert data["findings_count"] == 1
        assert data["high_count"] == 1

        # The stored finding is visible in the organization's findings list
        findings = await client.get("/api/v1/findings", headers=headers)
        assert findings.json()["total"] == 1


class TestListScans:
    @pytest.mark.asyncio
    async def test_list_scans_with_pagination(self, client, db_session):
        user_data = await register_user(client)
        login_data = await login_user(client)
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        org_id = user_data["organization_id"]

        # Seed 5 scans
        async with db_session as db:
            for i in range(5):
                await create_scan_in_db(db, org_id, file_name=f"file_{i}.tf")
            await db.commit()

        # Page 1 of 2
        resp = await client.get("/api/v1/scans?page=1&page_size=2", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 5
        assert len(data["items"]) == 2
        assert data["page"] == 1

        # Page 2
        resp = await client.get("/api/v1/scans?page=2&page_size=2", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 2


class TestScanDetail:
    @pytest.mark.asyncio
    async def test_scan_detail_with_findings(self, client, db_session):
        user_data = await register_user(client)
        login_data = await login_user(client)
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        org_id = user_data["organization_id"]

        async with db_session as db:
            scan = await create_scan_in_db(db, org_id)
            await create_finding_in_db(db, scan.id, severity="CRITICAL", rule_id="SC-001")
            await create_finding_in_db(db, scan.id, severity="HIGH", rule_id="SC-002")
            scan.findings_count, scan.critical_count, scan.high_count = 2, 1, 1
            await db.commit()
            scan_id = scan.id

        resp = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == scan_id
        assert data["status"] == "completed"
        # Findings count should reflect the seeded data
        assert data.get("findings_count", 0) >= 2 or data.get("critical_count", 0) >= 1

    @pytest.mark.asyncio
    async def test_scan_not_found(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/scans/99999", headers=headers)
        assert resp.status_code == 404

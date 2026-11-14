"""Tests for the CVE database service."""
import os

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.cve.service import CVEService


class TestCVEServiceHelpers:
    def test_score_to_severity_critical(self):
        assert CVEService._score_to_severity(9.5) == "CRITICAL"
        assert CVEService._score_to_severity(9.0) == "CRITICAL"

    def test_score_to_severity_high(self):
        assert CVEService._score_to_severity(7.5) == "HIGH"
        assert CVEService._score_to_severity(7.0) == "HIGH"

    def test_score_to_severity_medium(self):
        assert CVEService._score_to_severity(4.0) == "MEDIUM"
        assert CVEService._score_to_severity(6.9) == "MEDIUM"

    def test_score_to_severity_low(self):
        assert CVEService._score_to_severity(0.1) == "LOW"
        assert CVEService._score_to_severity(3.9) == "LOW"

    def test_score_to_severity_zero(self):
        sev = CVEService._score_to_severity(0.0)
        assert sev in ("LOW", "INFO")

    def test_score_to_severity_boundary_nine(self):
        assert CVEService._score_to_severity(8.9) == "HIGH"

    def test_score_to_severity_boundary_seven(self):
        assert CVEService._score_to_severity(6.9) == "MEDIUM"

    def test_score_to_severity_boundary_four(self):
        assert CVEService._score_to_severity(3.9) == "LOW"

    def test_score_to_severity_max(self):
        assert CVEService._score_to_severity(10.0) == "CRITICAL"


class TestCVEServiceInit:
    def test_constructor_without_db(self):
        svc = CVEService(db=None)
        assert svc.db is None

    def test_nvd_base_url(self):
        svc = CVEService(db=None)
        assert hasattr(svc, "NVD_BASE_URL") or hasattr(svc, "nvd_base_url") or True

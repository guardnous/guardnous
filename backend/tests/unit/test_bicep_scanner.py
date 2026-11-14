import pytest
from app.services.scanners.bicep_scanner import BicepScanner


@pytest.fixture
def scanner():
    return BicepScanner()


class TestBicepScanner:
    def test_detect_cloud_provider(self, scanner):
        assert scanner.detect_cloud_provider("anything") == "azure"

    def test_scan_finds_issues(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        assert len(results) > 0

    def test_public_blob_access(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        public = [r for r in results if r.rule_id == "SD-BI-001"]
        assert len(public) > 0

    def test_nsg_allow_all(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        nsg = [r for r in results if r.rule_id == "SD-BI-004"]
        assert len(nsg) > 0

    def test_http_allowed(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        http = [r for r in results if r.rule_id == "SD-BI-005"]
        assert len(http) > 0

    def test_sql_public_access(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        sql = [r for r in results if r.rule_id == "SD-BI-006"]
        assert len(sql) > 0

    def test_hardcoded_secrets(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        secrets = [r for r in results if r.category == "secrets"]
        assert len(secrets) > 0

    def test_insecure_tls(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        tls = [r for r in results if r.rule_id == "SD-BI-012"]
        assert len(tls) > 0

    def test_admin_username(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        admin = [r for r in results if r.rule_id == "SD-BI-013"]
        assert len(admin) > 0

    def test_redis_non_ssl(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        redis = [r for r in results if r.rule_id == "SD-BI-024"]
        assert len(redis) > 0

    def test_ssh_password_auth(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        ssh = [r for r in results if r.rule_id == "SD-BI-014"]
        assert len(ssh) > 0

    def test_scan_detects_10_plus_issues(self, scanner, sample_bicep):
        results = scanner.scan(sample_bicep, "insecure.bicep")
        assert len(results) >= 10

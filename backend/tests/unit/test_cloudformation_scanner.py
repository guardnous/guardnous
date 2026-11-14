import pytest
from app.services.scanners.cloudformation_scanner import CloudFormationScanner


@pytest.fixture
def scanner():
    return CloudFormationScanner()


class TestCloudFormationScanner:
    def test_detect_cloud_provider(self, scanner):
        assert scanner.detect_cloud_provider("anything") == "aws"

    def test_scan_finds_issues(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        assert len(results) > 0

    def test_public_security_group(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        public_sg = [r for r in results if r.rule_id == "SD-CF-001"]
        assert len(public_sg) > 0

    def test_public_s3(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        public_s3 = [r for r in results if r.rule_id == "SD-CF-003"]
        assert len(public_s3) > 0
        assert public_s3[0].severity == "CRITICAL"

    def test_unencrypted_s3(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        encrypted = [r for r in results if r.rule_id == "SD-CF-002"]
        assert len(encrypted) > 0

    def test_public_rds(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        public_rds = [r for r in results if r.rule_id == "SD-CF-005"]
        assert len(public_rds) > 0

    def test_wildcard_iam(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        wildcard = [r for r in results if "SD-CF-007" in r.rule_id]
        assert len(wildcard) > 0

    def test_open_ssh(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        ssh = [r for r in results if r.rule_id == "SD-CF-012"]
        assert len(ssh) > 0

    def test_public_subnet(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        subnet = [r for r in results if r.rule_id == "SD-CF-019"]
        assert len(subnet) > 0

    def test_hardcoded_secrets(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        secrets = [r for r in results if r.category == "secrets"]
        assert len(secrets) > 0

    def test_invalid_template(self, scanner):
        results = scanner.scan("not a valid template", "invalid.yaml")
        assert len(results) == 0

    def test_scan_detects_10_plus_issues(self, scanner, sample_cloudformation):
        results = scanner.scan(sample_cloudformation, "insecure.yaml")
        assert len(results) >= 10

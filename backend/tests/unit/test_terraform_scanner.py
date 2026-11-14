import pytest
from app.services.scanners.terraform_scanner import TerraformScanner


@pytest.fixture
def scanner():
    return TerraformScanner()


class TestTerraformScanner:
    def test_detect_aws(self, scanner):
        assert scanner.detect_cloud_provider('resource "aws_s3_bucket" "test" {}') == "aws"

    def test_detect_gcp(self, scanner):
        assert scanner.detect_cloud_provider('resource "google_compute_instance" "test" {}') == "gcp"

    def test_detect_azure(self, scanner):
        assert scanner.detect_cloud_provider('resource "azurerm_virtual_machine" "test" {}') == "azure"

    def test_scan_finds_issues(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        assert len(results) > 0

    def test_public_security_group(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        public_sg = [r for r in results if r.rule_id == "SD-TF-001"]
        assert len(public_sg) > 0

    def test_public_s3_bucket(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        public_s3 = [r for r in results if r.rule_id == "SD-TF-003"]
        assert len(public_s3) > 0
        assert public_s3[0].severity == "CRITICAL"

    def test_public_rds(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        public_rds = [r for r in results if r.rule_id == "SD-TF-005"]
        assert len(public_rds) > 0
        assert public_rds[0].severity == "CRITICAL"

    def test_wildcard_iam(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        wildcard = [r for r in results if r.rule_id == "SD-TF-007"]
        assert len(wildcard) > 0
        assert wildcard[0].severity == "CRITICAL"

    def test_hardcoded_secrets(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        secrets = [r for r in results if r.rule_id == "SD-TF-009"]
        assert len(secrets) > 0

    def test_default_vpc(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        vpc = [r for r in results if r.rule_id == "SD-TF-011"]
        assert len(vpc) > 0

    def test_open_ssh(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        ssh = [r for r in results if r.rule_id == "SD-TF-012"]
        assert len(ssh) > 0

    def test_open_rdp(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        rdp = [r for r in results if r.rule_id == "SD-TF-013"]
        assert len(rdp) > 0

    def test_unencrypted_ebs(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        ebs = [r for r in results if r.rule_id == "SD-TF-010"]
        assert len(ebs) > 0

    def test_unencrypted_efs(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        efs = [r for r in results if r.rule_id == "SD-TF-021"]
        assert len(efs) > 0

    def test_secure_config_minimal_findings(self, scanner, secure_terraform):
        results = scanner.scan(secure_terraform, "secure.tf")
        critical = [r for r in results if r.severity == "CRITICAL"]
        assert len(critical) == 0

    def test_finding_has_remediation(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        for r in results:
            assert r.remediation, f"Finding {r.rule_id} missing remediation"

    def test_finding_has_line_number(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        results_with_lines = [r for r in results if r.line_number > 0]
        assert len(results_with_lines) > 0

    def test_scan_detects_15_plus_issues(self, scanner, sample_terraform):
        """Verify we detect 15+ real issues in sample code."""
        results = scanner.scan(sample_terraform, "insecure.tf")
        assert len(results) >= 15

    def test_overly_broad_cidr(self, scanner, sample_terraform):
        results = scanner.scan(sample_terraform, "insecure.tf")
        cidr = [r for r in results if r.rule_id == "SD-TF-025"]
        assert len(cidr) > 0

"""Tests for scanner base classes and ScanResult dataclass."""
import os
import pytest
from abc import ABC

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.scanners.base import ScanResult, BaseScanner


class TestScanResult:
    def test_required_fields(self):
        r = ScanResult(
            rule_id="SD-TF-001",
            title="Open S3 bucket",
            description="S3 bucket has public access enabled",
            severity="CRITICAL",
            category="storage",
        )
        assert r.rule_id == "SD-TF-001"
        assert r.severity == "CRITICAL"

    def test_optional_fields_default_none(self):
        r = ScanResult(
            rule_id="R1", title="T", description="D", severity="LOW", category="C"
        )
        assert r.cloud_provider == "aws"
        assert r.resource_type == ""
        assert r.resource_name == ""
        assert r.file_path == ""
        assert r.line_number == 0
        assert r.code_snippet == ""
        assert r.remediation == ""
        assert r.cve_id is None
        assert r.metadata == {}

    def test_all_fields(self):
        r = ScanResult(
            rule_id="SD-TF-010",
            title="Unencrypted EBS",
            description="EBS volume not encrypted",
            severity="HIGH",
            category="encryption",
            cloud_provider="aws",
            resource_type="aws_ebs_volume",
            resource_name="my-vol",
            file_path="main.tf",
            line_number=42,
            code_snippet='resource "aws_ebs_volume" "my-vol" {}',
            remediation="Add encrypted = true",
            cve_id="CVE-2024-0001",
            metadata={"extra": "info"},
        )
        assert r.cloud_provider == "aws"
        assert r.line_number == 42
        assert r.metadata == {"extra": "info"}

    def test_dataclass_is_not_frozen(self):
        r = ScanResult(rule_id="R", title="T", description="D", severity="LOW", category="C")
        r.severity = "HIGH"
        assert r.severity == "HIGH"


class TestBaseScanner:
    def test_is_abstract(self):
        assert issubclass(BaseScanner, ABC)

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseScanner()

    def test_scan_method_required(self):
        """Subclass must implement scan()."""
        class Incomplete(BaseScanner):
            pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_valid_subclass(self):
        class DummyScanner(BaseScanner):
            def scan(self, content, filename=""):
                return []

            def detect_cloud_provider(self, content):
                return "aws"

        scanner = DummyScanner()
        assert scanner.scan("", "") == []

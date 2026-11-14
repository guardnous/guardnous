"""Checkov output -> findings. Field names below are what Checkov really emits."""
import json

from app.services.plugins.adapters.checkov_adapter import CheckovAdapter, resource_type_of


def _output(*checks: dict) -> str:
    return json.dumps({"check_type": "terraform", "results": {"failed_checks": list(checks)}})


def _check(check_id: str, name: str, resource: str = "aws_s3_bucket.reports", **extra) -> dict:
    return {
        "check_id": check_id, "check_name": name, "name": None, "severity": None, "guideline": None,
        "check_result": {"result": "FAILED"}, "resource": resource, "file_path": "/main.tf",
        "file_line_range": [1, 4], "code_block": [[1, 'resource "aws_s3_bucket" "reports" {\n']],
        **extra,
    }


def _parse(*checks: dict):
    return CheckovAdapter()._parse_output(_output(*checks), "main.tf")


def test_title_is_the_check_name_not_the_id():
    finding = _parse(_check("CKV_AWS_20", "S3 Bucket has an ACL defined which allows public READ access."))[0]
    assert finding.rule_id == "CKV_AWS_20"
    assert finding.title == "S3 Bucket has an ACL defined which allows public READ access."
    assert "FAILED" not in finding.title
    assert "CKV_AWS_20" in finding.description and "aws_s3_bucket.reports" in finding.description
    assert finding.remediation and "CKV_AWS_20" in finding.remediation
    assert finding.resource_type == "aws_s3_bucket"
    assert finding.line_number == 1
    assert finding.metadata["framework"] == "terraform"


def test_severity_follows_the_built_in_policy_when_checkov_gives_none():
    public, tagging = _parse(
        _check("CKV_AWS_20", "S3 Bucket has an ACL defined which allows public READ access."),
        _check("CKV_AWS_18", "Ensure the S3 bucket has access logging enabled"),
    )
    assert public.severity == "CRITICAL"   # listed by "No Public S3 Buckets"
    assert tagging.severity == "MEDIUM"    # no built-in policy names it


def test_severity_reported_by_checkov_wins():
    finding = _parse(_check("CKV_AWS_20", "public read", severity="LOW"))[0]
    assert finding.severity == "LOW"


def test_guideline_is_used_when_present():
    finding = _parse(_check("CKV_AWS_20", "public read", guideline="https://docs.example/ckv_aws_20"))[0]
    assert finding.remediation == "https://docs.example/ckv_aws_20"


def test_missing_name_still_gives_a_readable_title():
    finding = _parse(_check("CKV_AWS_999", ""))[0]
    assert finding.title == "Checkov check CKV_AWS_999 failed"


def test_resource_type_of():
    assert resource_type_of("aws_s3_bucket.reports") == "aws_s3_bucket"
    assert resource_type_of("module.app.aws_s3_bucket.logs") == "aws_s3_bucket"
    assert resource_type_of("AWS::S3::Bucket.ReportsBucket") == "AWS::S3::Bucket"
    assert resource_type_of("") == ""

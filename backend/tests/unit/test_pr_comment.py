"""Tests for PR comment formatting."""
import os

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.vcs.pr_comment import format_pr_comment, format_commit_status_description


class TestPRComment:
    def test_format_with_critical_findings(self):
        findings = [
            {"severity": "CRITICAL", "title": "Public S3 Bucket", "file_path": "main.tf", "line_number": 10},
            {"severity": "CRITICAL", "title": "Hardcoded Secret", "file_path": "main.tf", "line_number": 20},
            {"severity": "HIGH", "title": "Open SSH Port", "file_path": "main.tf", "line_number": 30},
            {"severity": "MEDIUM", "title": "No Encryption", "file_path": "main.tf", "line_number": 40},
            {"severity": "LOW", "title": "No Tags", "file_path": "main.tf", "line_number": 50},
        ]
        comment = format_pr_comment(1, 75, findings, "org/repo")

        assert "CRITICAL RISK" in comment
        assert "Public S3 Bucket" in comment
        assert "Hardcoded Secret" in comment
        assert "Open SSH Port" in comment
        assert "| 🔴 Critical | 2 |" in comment
        assert "| 🟠 High | 1 |" in comment
        assert "GuardNous" in comment

    def test_format_low_risk(self):
        findings = [
            {"severity": "LOW", "title": "Missing Tags", "file_path": "main.tf", "line_number": 5},
        ]
        comment = format_pr_comment(1, 10, findings, "org/repo")
        assert "LOW RISK" in comment

    def test_format_medium_risk(self):
        findings = [
            {"severity": "HIGH", "title": "Issue", "file_path": "main.tf", "line_number": 1},
        ]
        comment = format_pr_comment(1, 50, findings, "org/repo")
        assert "MEDIUM RISK" in comment

    def test_format_with_dashboard_url(self):
        comment = format_pr_comment(1, 50, [], "org/repo", dashboard_url="https://app.guardnous.com/scans/1")
        assert "https://app.guardnous.com/scans/1" in comment

    def test_format_empty_findings(self):
        comment = format_pr_comment(1, 0, [], "org/repo")
        assert "0 total" in comment

    def test_commit_status_no_findings(self):
        desc = format_commit_status_description(0, 0)
        assert "No security issues" in desc

    def test_commit_status_with_findings(self):
        desc = format_commit_status_description(75, 10)
        assert "75/100" in desc
        assert "10 finding" in desc

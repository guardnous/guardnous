"""Unit tests for the universal SARIF v2.1.0 parser."""
from app.services.scanners.sarif_parser import SARIFParser


# ── Fixtures ─────────────────────────────────────────────────────────────────

MINIMAL_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "TestScanner", "version": "1.0"}},
            "results": [
                {
                    "ruleId": "TEST-001",
                    "level": "error",
                    "message": {"text": "Found a test issue"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.tf"},
                                "region": {"startLine": 10},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

MULTI_RUN_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Checkov", "version": "3.0"}},
            "results": [
                {
                    "ruleId": "CKV_AWS_001",
                    "level": "warning",
                    "message": {"text": "S3 bucket not encrypted"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "s3.tf"},
                                "region": {"startLine": 5},
                            }
                        }
                    ],
                }
            ],
        },
        {
            "tool": {"driver": {"name": "Trivy", "version": "0.50"}},
            "results": [
                {
                    "ruleId": "AVD-AWS-0086",
                    "level": "error",
                    "message": {"text": "EC2 instance has public IP"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "ec2.tf"},
                                "region": {"startLine": 12},
                            }
                        }
                    ],
                }
            ],
        },
    ],
}

SARIF_WITH_RULES = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "rules": [
                        {
                            "id": "SG-001",
                            "shortDescription": {"text": "SQL injection risk"},
                            "fullDescription": {"text": "User input flows into SQL query without sanitization"},
                            "defaultConfiguration": {"level": "error"},
                            "helpUri": "https://semgrep.dev/r/SG-001",
                            "properties": {
                                "tags": ["security", "cwe-89", "owasp-a03"],
                                "security-severity": "8.5",
                                "precision": "high",
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "SG-001",
                    "message": {"text": "Possible SQL injection"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/db.py"},
                                "region": {
                                    "startLine": 42,
                                    "snippet": {"text": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"},
                                },
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

SARIF_WITH_CVE = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Grype"}},
            "results": [
                {
                    "ruleId": "CVE-2023-44487",
                    "level": "error",
                    "message": {"text": "HTTP/2 rapid reset attack"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "go.mod"},
                                "region": {"startLine": 7},
                            }
                        }
                    ],
                    "properties": {"cve": "CVE-2023-44487"},
                }
            ],
        }
    ],
}

SARIF_WITH_FIXES = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "TestTool"}},
            "results": [
                {
                    "ruleId": "FIX-001",
                    "level": "warning",
                    "message": {"text": "Fixable issue"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "fix.tf"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "fixes": [
                        {"description": {"text": "Add encryption = true to the block"}}
                    ],
                }
            ],
        }
    ],
}


# ── Tests ────────────────────────────────────────────────────────────────────


class TestSARIFParserBasic:
    def test_parse_minimal(self):
        parser = SARIFParser()
        result = parser.parse(MINIMAL_SARIF)
        assert result.success is True
        assert result.total_findings == 1
        assert result.total_runs == 1
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.rule_id == "TEST-001"
        assert f.file_path == "main.tf"
        assert f.line_number == 10
        assert f.title == "Found a test issue"

    def test_parse_json_string(self):
        import json

        parser = SARIFParser()
        result = parser.parse(json.dumps(MINIMAL_SARIF))
        assert result.success is True
        assert result.total_findings == 1

    def test_parse_invalid_json(self):
        parser = SARIFParser()
        result = parser.parse("not json at all")
        assert result.success is False
        assert "Invalid SARIF" in result.error or "JSON" in result.error

    def test_parse_empty_runs(self):
        parser = SARIFParser()
        result = parser.parse({"version": "2.1.0", "runs": []})
        assert result.success is True
        assert result.total_findings == 0

    def test_parse_no_results(self):
        parser = SARIFParser()
        sarif = {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "Clean"}}, "results": []}
            ],
        }
        result = parser.parse(sarif)
        assert result.success is True
        assert result.total_findings == 0


class TestMultiRun:
    def test_multi_run_combined(self):
        parser = SARIFParser()
        result = parser.parse(MULTI_RUN_SARIF)
        assert result.success is True
        assert result.total_runs == 2
        assert result.total_findings == 2

        tools = {f.metadata["source"] for f in result.findings}
        assert "Checkov" in tools
        assert "Trivy" in tools

    def test_tool_name_override(self):
        parser = SARIFParser(override_tool_name="CustomScanner")
        result = parser.parse(MULTI_RUN_SARIF)
        sources = {f.metadata["source"] for f in result.findings}
        assert sources == {"CustomScanner"}


class TestSeverityResolution:
    def test_security_severity_score_critical(self):
        parser = SARIFParser()
        result = parser.parse(SARIF_WITH_RULES)
        f = result.findings[0]
        # security-severity 8.5 → HIGH (≥7.0)
        assert f.severity == "HIGH"

    def test_level_error_maps_to_high(self):
        parser = SARIFParser()
        result = parser.parse(MINIMAL_SARIF)
        assert result.findings[0].severity == "HIGH"  # level=error → HIGH

    def test_level_warning_maps_to_medium(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "W001",
                            "level": "warning",
                            "message": {"text": "warn"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.tf"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        parser = SARIFParser()
        result = parser.parse(sarif)
        assert result.findings[0].severity == "MEDIUM"

    def test_custom_severity_in_result_properties(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "C001",
                            "message": {"text": "critical custom"},
                            "properties": {"severity": "critical"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.tf"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        parser = SARIFParser()
        result = parser.parse(sarif)
        assert result.findings[0].severity == "CRITICAL"

    def test_default_severity_fallback(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "N001",
                            "message": {"text": "no level"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.tf"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        parser = SARIFParser(default_severity="LOW")
        result = parser.parse(sarif)
        assert result.findings[0].severity == "LOW"


class TestCategoryInference:
    def test_aws_cloud_inference(self):
        parser = SARIFParser()
        result = parser.parse(MULTI_RUN_SARIF)
        aws_findings = [f for f in result.findings if f.cloud_provider == "aws"]
        assert len(aws_findings) >= 1

    def test_iac_category_from_tool(self):
        parser = SARIFParser()
        result = parser.parse(MULTI_RUN_SARIF)
        # Checkov is an IaC scanner
        checkov_finding = [f for f in result.findings if f.metadata["source"] == "Checkov"][0]
        assert checkov_finding.category in ("iac", "misconfiguration", "encryption", "security")


class TestCVEExtraction:
    def test_cve_from_rule_id(self):
        parser = SARIFParser()
        result = parser.parse(SARIF_WITH_CVE)
        assert result.findings[0].cve_id == "CVE-2023-44487"

    def test_no_cve_when_absent(self):
        parser = SARIFParser()
        result = parser.parse(MINIMAL_SARIF)
        assert result.findings[0].cve_id is None


class TestRemediation:
    def test_remediation_from_fixes(self):
        parser = SARIFParser()
        result = parser.parse(SARIF_WITH_FIXES)
        assert "encryption" in result.findings[0].remediation.lower()

    def test_remediation_from_help_uri(self):
        parser = SARIFParser()
        result = parser.parse(SARIF_WITH_RULES)
        assert "semgrep.dev" in result.findings[0].remediation


class TestMetadata:
    def test_metadata_contains_source(self):
        parser = SARIFParser()
        result = parser.parse(MINIMAL_SARIF)
        assert result.findings[0].metadata["source"] == "TestScanner"

    def test_metadata_contains_tags(self):
        parser = SARIFParser()
        result = parser.parse(SARIF_WITH_RULES)
        assert "security" in result.findings[0].metadata.get("tags", [])

    def test_metadata_contains_security_score(self):
        parser = SARIFParser()
        result = parser.parse(SARIF_WITH_RULES)
        assert result.findings[0].metadata.get("security_severity_score") == "8.5"


class TestLocationExtraction:
    def test_file_uri_prefix_stripped(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "U001",
                            "level": "warning",
                            "message": {"text": "uri test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file:///home/user/main.tf"},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        parser = SARIFParser()
        result = parser.parse(sarif)
        assert not result.findings[0].file_path.startswith("file://")

    def test_snippet_extraction(self):
        parser = SARIFParser()
        result = parser.parse(SARIF_WITH_RULES)
        assert "cursor.execute" in result.findings[0].code_snippet

    def test_no_locations_handled(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "NL001",
                            "level": "note",
                            "message": {"text": "no loc"},
                        }
                    ],
                }
            ],
        }
        parser = SARIFParser()
        result = parser.parse(sarif)
        assert result.total_findings == 1
        assert result.findings[0].file_path == ""
        assert result.findings[0].line_number == 0


class TestEdgeCases:
    def test_missing_version_still_parses(self):
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "E001",
                            "level": "error",
                            "message": {"text": "no version"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "x.tf"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        parser = SARIFParser()
        result = parser.parse(sarif)
        assert result.success is True

    def test_empty_dict_is_rejected(self):
        parser = SARIFParser()
        result = parser.parse({})
        assert result.success is False
        assert "runs" in result.error
        assert result.total_findings == 0

    def test_title_truncation(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "LONG",
                            "level": "warning",
                            "message": {"text": "A" * 600},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.tf"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        parser = SARIFParser()
        result = parser.parse(sarif)
        assert len(result.findings[0].title) <= 500

    def test_summary_severity_counts(self):
        parser = SARIFParser()
        result = parser.parse(MINIMAL_SARIF)
        assert "HIGH" in result.summary or "high" in str(result.summary).lower()

"""
Universal SARIF v2.1.0 Parser — GuardNous

Parses any SARIF-compliant JSON (Checkov, Trivy, Semgrep, CodeQL, ESLint,
Bandit, Snyk, SonarQube, tfsec, Gitleaks, KICS, Terrascan, etc.) and
converts results into GuardNous ScanResult objects.

SARIF Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from app.services.scanners.base import ScanResult

logger = logging.getLogger(__name__)

# ── SARIF level → GuardNous severity ──────────────────────────────────────

_LEVEL_SEVERITY_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

# Some scanners put custom severity in properties — normalise those too
_PROPERTY_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
    "none": "INFO",
}

# ── Category inference from rule tags / tool name ────────────────────────────

_CATEGORY_KEYWORDS = {
    "iac": ["iac", "terraform", "cloudformation", "bicep", "kubernetes", "helm",
            "ansible", "dockerfile", "docker-compose", "pulumi", "cdk"],
    "secrets": ["secret", "credential", "password", "token", "api-key", "private-key",
                "gitleaks", "detect-secrets", "trufflehog"],
    "sast": ["sast", "code", "injection", "xss", "sqli", "deserialization",
             "semgrep", "codeql", "bandit", "eslint", "sonar", "spotbugs"],
    "sca": ["sca", "dependency", "vulnerability", "cve", "package", "npm",
            "pip", "maven", "nuget", "trivy", "snyk", "grype", "osv"],
    "container": ["container", "image", "docker", "oci", "layer"],
    "compliance": ["compliance", "cis", "nist", "pci", "hipaa", "soc2", "gdpr"],
    "license": ["license", "spdx", "copyleft"],
}

_CLOUD_KEYWORDS = {
    "aws": ["aws", "amazon", "s3", "ec2", "iam", "lambda", "rds", "dynamodb",
            "cloudfront", "sqs", "sns", "eks", "ecs"],
    "azure": ["azure", "microsoft", "arm", "aad", "cosmos", "blob", "aks"],
    "gcp": ["gcp", "google", "gke", "bigquery", "cloud-run", "pubsub"],
}


@dataclass
class SARIFImportResult:
    """Summary of a SARIF import operation."""
    findings: list[ScanResult]
    runs_processed: int = 0
    results_processed: int = 0
    results_skipped: int = 0
    tools_detected: list[str] = field(default_factory=list)
    sarif_version: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors

    @property
    def error(self) -> str:
        return "; ".join(self.errors)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def total_runs(self) -> int:
        return self.runs_processed

    @property
    def summary(self) -> dict[str, int]:
        """Finding count per severity."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


class SARIFParser:
    """Universal SARIF v2.1.0 → ScanResult parser.

    Handles:
    - Multiple runs (multi-tool SARIF files)
    - Rule metadata lookup from tool.driver.rules and tool.extensions
    - Severity from result level, rule defaultConfiguration, or properties
    - Fingerprints for stable deduplication
    - Fix suggestions from SARIF fix objects
    - Logical locations (resource names)
    - Related locations (context)
    """

    def __init__(
        self,
        default_severity: str = "MEDIUM",
        default_category: str = "security",
        override_tool_name: str | None = None,
    ):
        self.default_severity = default_severity
        self.default_category = default_category
        self.override_tool_name = override_tool_name

    def parse(self, sarif_data: dict | str) -> SARIFImportResult:
        """Parse a complete SARIF document (dict or JSON string)."""
        if isinstance(sarif_data, str):
            try:
                sarif_data = json.loads(sarif_data)
            except json.JSONDecodeError as exc:
                return SARIFImportResult(
                    findings=[], errors=[f"Invalid JSON: {exc}"]
                )

        if not isinstance(sarif_data, dict):
            return SARIFImportResult(
                findings=[], errors=["SARIF data must be a JSON object"]
            )

        version = sarif_data.get("version", "")
        if version and not version.startswith("2.1"):
            logger.warning("SARIF version %s may not be fully supported", version)

        # An empty runs array is a valid document with no results; a missing
        # one is not SARIF.
        runs = sarif_data.get("runs")
        if not isinstance(runs, list):
            return SARIFImportResult(
                findings=[],
                sarif_version=version,
                errors=["No 'runs' array found in SARIF document"],
            )

        all_findings: list[ScanResult] = []
        tools: list[str] = []
        total_results = 0
        total_skipped = 0
        errors: list[str] = []

        for run_index, run in enumerate(runs):
            try:
                run_findings, skipped = self._parse_run(run, run_index)
                all_findings.extend(run_findings)
                total_results += len(run_findings) + skipped
                total_skipped += skipped

                tool_name = self._get_tool_name(run)
                if tool_name and tool_name not in tools:
                    tools.append(tool_name)
            except Exception as exc:
                msg = f"Error parsing run {run_index}: {exc}"
                logger.error(msg, exc_info=True)
                errors.append(msg)

        return SARIFImportResult(
            findings=all_findings,
            runs_processed=len(runs),
            results_processed=total_results,
            results_skipped=total_skipped,
            tools_detected=tools,
            sarif_version=version,
            errors=errors,
        )

    def parse_file(self, file_path: str) -> SARIFImportResult:
        """Parse a SARIF file from disk."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self.parse(data)
        except (OSError, json.JSONDecodeError) as exc:
            return SARIFImportResult(findings=[], errors=[str(exc)])

    # ── Internal ─────────────────────────────────────────────────────────────

    def _parse_run(self, run: dict, run_index: int) -> tuple[list[ScanResult], int]:
        """Parse a single SARIF run. Returns (findings, skipped_count)."""
        tool_name = self._get_tool_name(run)
        rules_index = self._build_rules_index(run)
        results = run.get("results", [])
        findings: list[ScanResult] = []
        skipped = 0

        for result in results:
            try:
                scan_result = self._convert_result(result, tool_name, rules_index)
                if scan_result:
                    findings.append(scan_result)
                else:
                    skipped += 1
            except Exception as exc:
                logger.debug("Skipping result: %s", exc)
                skipped += 1

        return findings, skipped

    def _get_tool_name(self, run: dict) -> str:
        """Extract scanner/tool name from run."""
        if self.override_tool_name:
            return self.override_tool_name
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        return driver.get("name", "unknown_scanner")

    def _build_rules_index(self, run: dict) -> dict[str, dict]:
        """Build a lookup dict: rule_id → rule metadata.

        Merges rules from driver and extensions.
        """
        index: dict[str, dict] = {}
        tool = run.get("tool", {})

        # Driver rules
        driver = tool.get("driver", {})
        for rule in driver.get("rules", []):
            rid = rule.get("id", "")
            if rid:
                index[rid] = rule

        # Extension rules (some tools like CodeQL use extensions)
        for ext in tool.get("extensions", []):
            for rule in ext.get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    index[rid] = rule

        return index

    def _convert_result(
        self,
        result: dict,
        tool_name: str,
        rules_index: dict[str, dict],
    ) -> ScanResult | None:
        """Convert one SARIF result → ScanResult."""
        rule_id = result.get("ruleId", "") or ""

        # Look up rule metadata
        rule_meta = rules_index.get(rule_id, {})
        if not rule_meta:
            # Try ruleIndex fallback
            rule_idx = result.get("ruleIndex")
            if rule_idx is not None:
                for rid, meta in rules_index.items():
                    if meta.get("_index") == rule_idx:
                        rule_meta = meta
                        rule_id = rid
                        break

        # ── Title ────────────────────────────────────────────────────────
        message = result.get("message", {})
        title = (
            message.get("text", "")
            or message.get("markdown", "")
            or _get_text(rule_meta.get("shortDescription"))
            or rule_id
        )
        # Truncate long titles
        if len(title) > 500:
            title = title[:497] + "..."

        # ── Description ──────────────────────────────────────────────────
        description = (
            _get_text(rule_meta.get("fullDescription"))
            or _get_text(rule_meta.get("shortDescription"))
            or title
        )

        # ── Severity ─────────────────────────────────────────────────────
        severity = self._resolve_severity(result, rule_meta)

        # ── Location ─────────────────────────────────────────────────────
        file_path, line_number, code_snippet = self._extract_location(result)

        # ── Resource info ────────────────────────────────────────────────
        resource_type, resource_name = self._extract_resource(result, rule_meta)

        # ── Category ─────────────────────────────────────────────────────
        category = self._infer_category(rule_meta, tool_name, rule_id)

        # ── Cloud provider ───────────────────────────────────────────────
        cloud_provider = self._infer_cloud(rule_meta, rule_id, title, file_path)

        # ── Remediation ──────────────────────────────────────────────────
        remediation = self._extract_remediation(result, rule_meta)

        # ── CVE ──────────────────────────────────────────────────────────
        cve_id = self._extract_cve(result, rule_meta, rule_id)

        # ── Fingerprint for dedup ────────────────────────────────────────
        fingerprints = result.get("fingerprints", {})
        partial_fps = result.get("partialFingerprints", {})

        # ── Metadata ─────────────────────────────────────────────────────
        metadata = {
            "source": tool_name,
            "sarif_level": result.get("level", ""),
            "sarif_rule_id": rule_id,
        }
        if fingerprints:
            metadata["fingerprints"] = fingerprints
        if partial_fps:
            metadata["partial_fingerprints"] = partial_fps

        # Tags from rule properties
        props = rule_meta.get("properties", {})
        tags = props.get("tags", [])
        if tags:
            metadata["tags"] = tags

        # Precision / problem type
        if props.get("precision"):
            metadata["precision"] = props["precision"]
        if props.get("security-severity"):
            metadata["security_severity_score"] = props["security-severity"]

        return ScanResult(
            rule_id=rule_id or _generate_rule_id(title, file_path),
            title=title,
            description=description,
            severity=severity,
            category=category,
            cloud_provider=cloud_provider,
            resource_type=resource_type,
            resource_name=resource_name,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            remediation=remediation,
            cve_id=cve_id,
            metadata=metadata,
        )

    def _resolve_severity(self, result: dict, rule_meta: dict) -> str:
        """Resolve severity from multiple SARIF sources (priority order)."""
        # 1. Custom severity in result properties (highest priority)
        result_props = result.get("properties", {})
        custom_sev = (
            result_props.get("severity")
            or result_props.get("impact")
            or result_props.get("risk_level")
        )
        if custom_sev and custom_sev.lower() in _PROPERTY_SEVERITY_MAP:
            return _PROPERTY_SEVERITY_MAP[custom_sev.lower()]

        # 2. security-severity score in rule properties (CVSS-like)
        rule_props = rule_meta.get("properties", {})
        sec_sev = rule_props.get("security-severity")
        if sec_sev is not None:
            try:
                score = float(sec_sev)
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            except (ValueError, TypeError):
                pass

        # 3. Result level
        level = result.get("level", "")
        if level and level in _LEVEL_SEVERITY_MAP:
            return _LEVEL_SEVERITY_MAP[level]

        # 4. Rule defaultConfiguration level
        default_cfg = rule_meta.get("defaultConfiguration", {})
        default_level = default_cfg.get("level", "")
        if default_level and default_level in _LEVEL_SEVERITY_MAP:
            return _LEVEL_SEVERITY_MAP[default_level]

        # 5. Custom severity in rule properties
        rule_sev = rule_props.get("severity", "")
        if rule_sev and rule_sev.lower() in _PROPERTY_SEVERITY_MAP:
            return _PROPERTY_SEVERITY_MAP[rule_sev.lower()]

        return self.default_severity

    def _extract_location(self, result: dict) -> tuple[str, int, str]:
        """Extract file path, line number, and code snippet from result."""
        locations = result.get("locations", [])
        if not locations:
            return "", 0, ""

        loc = locations[0]
        phys = loc.get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        region = phys.get("region", {})

        file_path = artifact.get("uri", "")
        # Strip file:// prefix if present
        if file_path.startswith("file://"):
            file_path = file_path[7:]
        # Strip leading slash for relative paths
        if file_path.startswith("/") and not file_path.startswith("//"):
            file_path = file_path.lstrip("/")

        line_number = region.get("startLine", 0)
        snippet_obj = region.get("snippet", {})
        code_snippet = snippet_obj.get("text", "")

        # If no snippet, try contextRegion
        if not code_snippet:
            ctx = phys.get("contextRegion", {})
            ctx_snippet = ctx.get("snippet", {})
            code_snippet = ctx_snippet.get("text", "")

        return file_path, line_number, code_snippet

    def _extract_resource(self, result: dict, rule_meta: dict) -> tuple[str, str]:
        """Extract resource type and name from logical locations or properties."""
        locations = result.get("locations", [])
        resource_type = ""
        resource_name = ""

        for loc in locations:
            for logical in loc.get("logicalLocations", []):
                kind = logical.get("kind", "")
                name = logical.get("name", "") or logical.get("fullyQualifiedName", "")
                if kind == "resource" or kind == "module":
                    resource_name = name
                    resource_type = logical.get("decoratedName", kind)
                elif not resource_name and name:
                    resource_name = name

        # Fallback: try result properties
        if not resource_type:
            props = result.get("properties", {})
            resource_type = props.get("resource_type", "") or props.get("resourceType", "")
        if not resource_name:
            props = result.get("properties", {})
            resource_name = props.get("resource_name", "") or props.get("resourceName", "")

        return resource_type, resource_name

    def _infer_category(self, rule_meta: dict, tool_name: str, rule_id: str) -> str:
        """Infer finding category from rule tags, tool name, and rule ID."""
        # Check rule tags first
        tags = rule_meta.get("properties", {}).get("tags", [])
        searchable = " ".join(tags).lower() + " " + tool_name.lower() + " " + rule_id.lower()

        for category, keywords in _CATEGORY_KEYWORDS.items():
            if any(kw in searchable for kw in keywords):
                return category

        return self.default_category

    def _infer_cloud(
        self, rule_meta: dict, rule_id: str, title: str, file_path: str
    ) -> str:
        """Infer cloud provider from rule metadata and content."""
        searchable = (
            rule_id.lower() + " " + title.lower() + " " + file_path.lower()
            + " " + " ".join(rule_meta.get("properties", {}).get("tags", [])).lower()
        )

        for cloud, keywords in _CLOUD_KEYWORDS.items():
            if any(kw in searchable for kw in keywords):
                return cloud

        return ""

    def _extract_remediation(self, result: dict, rule_meta: dict) -> str:
        """Extract remediation guidance from SARIF fixes or rule help."""
        # 1. SARIF fix objects
        fixes = result.get("fixes", [])
        if fixes:
            fix_desc = fixes[0].get("description", {})
            fix_text = _get_text(fix_desc)
            if fix_text:
                return fix_text

        # 2. Rule help text
        help_obj = rule_meta.get("help", {})
        help_text = help_obj.get("markdown", "") or help_obj.get("text", "")
        if help_text:
            return help_text

        # 3. Rule helpUri
        help_uri = rule_meta.get("helpUri", "")
        if help_uri:
            return f"See: {help_uri}"

        return ""

    def _extract_cve(self, result: dict, rule_meta: dict, rule_id: str) -> str | None:
        """Extract CVE ID if present."""
        # Check rule_id itself (some SCA tools use CVE as rule ID)
        if rule_id.upper().startswith("CVE-"):
            return rule_id.upper()

        # Check properties
        for props in [result.get("properties", {}), rule_meta.get("properties", {})]:
            cve = props.get("cve", "") or props.get("cve_id", "") or props.get("CVE", "")
            if cve:
                return cve.upper()

            # Check tags for CVE patterns
            for tag in props.get("tags", []):
                if tag.upper().startswith("CVE-"):
                    return tag.upper()

        return None


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_text(message_obj: Any) -> str:
    """Safely extract text from a SARIF message object."""
    if not message_obj:
        return ""
    if isinstance(message_obj, str):
        return message_obj
    return message_obj.get("text", "") or message_obj.get("markdown", "")


def _generate_rule_id(title: str, file_path: str) -> str:
    """Generate a stable rule ID when the SARIF result has none."""
    content = f"{title}:{file_path}"
    return "SARIF-" + hashlib.sha256(content.encode()).hexdigest()[:12]

"""
Checkov Adapter — bridges Bridgecrew/Prisma Cloud's Checkov CLI into GuardNous.

Checkov scans Terraform, CloudFormation, K8s manifests, Dockerfiles, and more.
This adapter shells out to ``checkov``, parses its JSON output, and normalises
results into ScanResult objects.

Install:  pip install checkov   (or brew install checkov)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any

from app.services.plugins.base import (
    DirectoryScanResult,
    PluginAdapter,
    PluginCapability,
    PluginHealth,
    PluginMetadata,
)
from app.services.scanners.base import ScanResult

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "UNKNOWN": "MEDIUM",
}

def checkov_severity(check_id: str, reported: str | None) -> str:
    """Severity for a Checkov finding.

    Open-source Checkov reports no severity (it comes from the paid platform).
    When it is absent, a check that one of the built-in policies covers takes
    that policy's severity (a public S3 bucket is CRITICAL); anything else is
    MEDIUM.
    """
    if reported:
        return SEVERITY_MAP.get(str(reported).upper(), "MEDIUM")
    from app.services.security.policy_engine import severity_for_rule

    return severity_for_rule(check_id) or "MEDIUM"


def resource_type_of(resource: str) -> str:
    """Type part of a Checkov resource address.

    ``aws_s3_bucket.reports`` -> ``aws_s3_bucket``;
    ``module.app.aws_s3_bucket.logs`` -> ``aws_s3_bucket``;
    ``AWS::S3::Bucket.ReportsBucket`` -> ``AWS::S3::Bucket``.
    """
    parts = [p for p in (resource or "").split(".") if p]
    return parts[-2] if len(parts) >= 2 else ""


FRAMEWORK_MAP = {
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".json": "cloudformation",
    ".yaml": "cloudformation",
    ".yml": "cloudformation",
    ".dockerfile": "dockerfile",
    "Dockerfile": "dockerfile",
    ".bicep": "bicep",
    ".hcl": "terraform",
}


class CheckovAdapter(PluginAdapter):
    """Adapter for the Checkov IaC security scanner."""

    _binary = "checkov"

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="checkov",
            display_name="Bridgecrew Checkov",
            version="1.0.0",
            description=(
                "Open-source static analysis for IaC — supports Terraform, CloudFormation, "
                "Kubernetes, Helm, ARM, and Dockerfiles. 1000+ built-in policies."
            ),
            homepage="https://www.checkov.io",
            icon="ShieldCheck",
            capabilities=[
                PluginCapability.IAC_TERRAFORM,
                PluginCapability.IAC_CLOUDFORMATION,
                PluginCapability.IAC_KUBERNETES,
                PluginCapability.IAC_HELM,
                PluginCapability.IAC_DOCKERFILE,
            ],
            requires_binary=True,
            default_config={
                "skip_checks": [],
                "framework": "auto",
                "soft_fail": True,
            },
        )

    def health(self) -> PluginHealth:
        binary = shutil.which(self._binary)
        if not binary:
            return PluginHealth(available=False, message=f"'{self._binary}' not found on PATH")
        try:
            start = time.monotonic()
            proc = subprocess.run(
                [binary, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            latency = (time.monotonic() - start) * 1000
            version = proc.stdout.strip() or "unknown"
            return PluginHealth(available=True, version=version, latency_ms=latency)
        except Exception as exc:
            return PluginHealth(available=False, message=str(exc))

    def scan(
        self,
        content: str,
        file_name: str = "",
        config: dict[str, Any] | None = None,
    ) -> list[ScanResult]:
        cfg = {**self.metadata().default_config, **(config or {})}

        # Write content to temp file
        suffix = os.path.splitext(file_name)[1] if file_name else ".tf"
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            cmd = [
                shutil.which(self._binary) or self._binary,
                "-f", tmp_path,
                "-o", "json",
                "--compact",
                "--quiet",
            ]
            if cfg.get("soft_fail"):
                cmd.append("--soft-fail")
            if cfg.get("framework") and cfg["framework"] != "auto":
                cmd.extend(["--framework", cfg["framework"]])
            for skip in cfg.get("skip_checks", []):
                cmd.extend(["--skip-check", skip])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            return self._parse_output(proc.stdout, file_name)

        except subprocess.TimeoutExpired:
            logger.error("Checkov scan timed out for %s", file_name)
            return []
        except Exception as exc:
            logger.error("Checkov scan failed: %s", exc)
            return []
        finally:
            os.unlink(tmp_path)

    def supports_directory_scan(self) -> bool:
        return True

    def scan_directory(
        self,
        dir_path: str,
        config: dict[str, Any] | None = None,
    ) -> DirectoryScanResult:
        cfg = {**self.metadata().default_config, **(config or {})}
        binary = shutil.which(self._binary) or self._binary

        # --- Text run (real CLI output) ---
        text_cmd = [binary, "-d", dir_path, "--compact", "--quiet"]
        if cfg.get("soft_fail"):
            text_cmd.append("--soft-fail")
        for skip in cfg.get("skip_checks", []):
            text_cmd.extend(["--skip-check", skip])
        text_cmd_str = " ".join(text_cmd)

        start = time.monotonic()
        try:
            text_proc = subprocess.run(text_cmd, capture_output=True, text=True, timeout=300)
            raw_output = text_proc.stdout or ""
            # Filter stderr: only append genuine errors, not SSL/network warnings
            if text_proc.stderr:
                _noise = {"prismacloud.io", "SSLCertVerification", "ssl.c", "MaxRetryError",
                          "urllib3", "get_public_run_config", "bridgecrew", "CERTIFICATE_VERIFY_FAILED"}
                err_lines = [
                    ln for ln in text_proc.stderr.splitlines()
                    if not any(tok in ln for tok in _noise)
                ]
                filtered = "\n".join(err_lines).strip()
                if filtered and ("error" in filtered.lower() or "fatal" in filtered.lower()):
                    raw_output += "\n" + filtered
        except subprocess.TimeoutExpired:
            return DirectoryScanResult(
                findings=[], raw_output="checkov timed out after 300s",
                command=text_cmd_str, exit_code=124, duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return DirectoryScanResult(
                findings=[], raw_output=f"checkov failed: {exc}",
                command=text_cmd_str, exit_code=1, duration_ms=(time.monotonic() - start) * 1000,
            )

        # --- JSON run (for structured findings) ---
        json_cmd = [binary, "-d", dir_path, "-o", "json", "--compact", "--quiet"]
        if cfg.get("soft_fail"):
            json_cmd.append("--soft-fail")
        for skip in cfg.get("skip_checks", []):
            json_cmd.extend(["--skip-check", skip])

        try:
            json_proc = subprocess.run(json_cmd, capture_output=True, text=True, timeout=300)
            findings = self._parse_dir_output(json_proc.stdout, dir_path)
        except Exception as exc:
            logger.error("Checkov JSON parse failed: %s", exc)
            findings = []

        elapsed = (time.monotonic() - start) * 1000
        return DirectoryScanResult(
            findings=findings,
            raw_output=raw_output,
            command=text_cmd_str,
            exit_code=text_proc.returncode,
            duration_ms=elapsed,
            stderr=text_proc.stderr or "",
        )

    def _parse_dir_output(self, raw_json: str, dir_path: str) -> list[ScanResult]:
        """Parse JSON from directory scan, stripping tmpdir prefix from paths."""
        if not raw_json.strip():
            return []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        prefix = dir_path.rstrip("/") + "/"
        checks_list = data if isinstance(data, list) else [data]
        results: list[ScanResult] = []

        for framework_result in checks_list:
            for check in framework_result.get("results", {}).get("failed_checks", []):
                raw_path = check.get("file_path", "")
                # Checkov prefixes paths with / relative to scan dir
                rel_path = raw_path.lstrip("/")
                if rel_path.startswith(prefix.lstrip("/")):
                    rel_path = rel_path[len(prefix.lstrip("/")):]

                code_lines = check.get("code_block", [])
                snippet = ""
                if code_lines:
                    snippet = "\n".join(
                        line[1] if isinstance(line, list) and len(line) > 1 else str(line)
                        for line in code_lines[:6]
                    )

                results.append(self._to_result(check, framework_result, rel_path, snippet))
        return results

    def _to_result(self, check: dict, framework_result: dict, file_path: str, snippet: str) -> ScanResult:
        """Build a finding from one failed Checkov check.

        Checkov names the check in ``check_name``. The open-source edition
        supplies no severity and, offline, no guideline, so those are derived.
        """
        check_id = check.get("check_id") or "CKV-unknown"
        name = (check.get("check_name") or "").strip() or f"Checkov check {check_id} failed"
        resource = check.get("resource") or ""
        return ScanResult(
            rule_id=check_id,
            title=name[:500],
            description=f"{name} Checkov check {check_id} failed" + (f" for {resource}." if resource else "."),
            severity=checkov_severity(check_id, check.get("severity")),
            category="iac",
            cloud_provider=self._detect_cloud(check),
            resource_type=resource_type_of(resource),
            resource_name=resource,
            file_path=file_path,
            line_number=(check.get("file_line_range") or [0])[0],
            code_snippet=snippet,
            remediation=check.get("guideline") or (
                f"Change {resource or 'the resource'} so that this holds: {name} "
                f"(search the Checkov policy index for {check_id})."
            ),
            metadata={
                "source": "checkov", "check_id": check_id,
                "framework": framework_result.get("check_type"),
            },
        )

    def _parse_output(self, raw_json: str, file_name: str) -> list[ScanResult]:
        """Parse Checkov JSON output into ScanResult list."""
        if not raw_json.strip():
            return []

        results: list[ScanResult] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("Checkov returned non-JSON output")
            return []

        # Checkov can return a list (multiple frameworks) or a single dict
        checks_list = data if isinstance(data, list) else [data]

        for framework_result in checks_list:
            failed = framework_result.get("results", {}).get("failed_checks", [])
            for check in failed:
                # Extract code snippet
                code_lines = check.get("code_block", [])
                snippet = ""
                if code_lines:
                    snippet = "\n".join(
                        line[1] if isinstance(line, list) and len(line) > 1 else str(line)
                        for line in code_lines[:6]
                    )

                results.append(self._to_result(
                    check, framework_result, file_name or check.get("file_path", ""), snippet,
                ))

        return results

    @staticmethod
    def _detect_cloud(check: dict) -> str:
        resource = check.get("resource", "").lower()
        check_id = check.get("check_id", "").lower()
        combined = resource + " " + check_id
        if "aws" in combined:
            return "aws"
        if "azure" in combined or "azurerm" in combined:
            return "azure"
        if "google" in combined or "gcp" in combined:
            return "gcp"
        return "multi"

"""
tfsec Adapter — bridges Aqua Security's tfsec Terraform scanner into GuardNous.

tfsec is a static analysis tool for Terraform code, focused specifically on
cloud security best practices with deep HCL understanding.

Install:  brew install tfsec   (or go install github.com/aquasecurity/tfsec/cmd/tfsec@latest)
Note: tfsec is being merged into Trivy — this adapter is provided for users
who still have tfsec installed.
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
}


class TfsecAdapter(PluginAdapter):
    """Adapter for tfsec Terraform security scanner."""

    _binary = "tfsec"

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="tfsec",
            display_name="Aqua tfsec (Deprecated)",
            version="1.0.0",
            description=(
                "Terraform-specific static analysis tool with deep HCL understanding. "
                "Detects security misconfigurations in AWS, Azure, GCP, and general Terraform patterns."
            ),
            homepage="https://aquasecurity.github.io/tfsec",
            icon="FileSearch",
            capabilities=[PluginCapability.IAC_TERRAFORM],
            requires_binary=True,
            default_config={
                "exclude": [],
                "include_passed": False,
                "soft_fail": True,
                "minimum_severity": "LOW",
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
                timeout=10,
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

        suffix = os.path.splitext(file_name)[1] if file_name else ".tf"
        tmpdir = tempfile.mkdtemp()
        target_name = os.path.basename(file_name) if file_name else f"main{suffix}"
        target_path = os.path.join(tmpdir, target_name)

        with open(target_path, "w") as f:
            f.write(content)

        try:
            cmd = [
                shutil.which(self._binary) or self._binary,
                "--format", "json",
                "--no-color",
                "--minimum-severity", cfg.get("minimum_severity", "LOW"),
                tmpdir,
            ]
            if cfg.get("soft_fail"):
                cmd.append("--soft-fail")
            for exclude_id in cfg.get("exclude", []):
                cmd.extend(["--exclude", exclude_id])
            if cfg.get("include_passed"):
                cmd.append("--include-passed")

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            return self._parse_output(proc.stdout, file_name)

        except subprocess.TimeoutExpired:
            logger.error("tfsec scan timed out for %s", file_name)
            return []
        except Exception as exc:
            logger.error("tfsec scan failed: %s", exc)
            return []
        finally:
            import shutil as sh
            sh.rmtree(tmpdir, ignore_errors=True)

    def supports_directory_scan(self) -> bool:
        return True

    def scan_directory(
        self,
        dir_path: str,
        config: dict[str, Any] | None = None,
    ) -> DirectoryScanResult:
        cfg = {**self.metadata().default_config, **(config or {})}
        binary = shutil.which(self._binary) or self._binary
        min_sev = cfg.get("minimum_severity", "LOW")

        # --- Text run (real CLI output for streaming) ---
        text_cmd = [binary, "--no-color", "--minimum-severity", min_sev, dir_path]
        if cfg.get("soft_fail"):
            text_cmd.append("--soft-fail")
        text_cmd_str = " ".join(text_cmd)

        start = time.monotonic()
        try:
            text_proc = subprocess.run(text_cmd, capture_output=True, text=True, timeout=180)
            raw_output = text_proc.stdout or ""
            if text_proc.stderr and "error" in text_proc.stderr.lower():
                raw_output += "\n" + text_proc.stderr
        except subprocess.TimeoutExpired:
            return DirectoryScanResult(
                findings=[], raw_output="tfsec timed out after 180s",
                command=text_cmd_str, exit_code=124, duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return DirectoryScanResult(
                findings=[], raw_output=f"tfsec failed: {exc}",
                command=text_cmd_str, exit_code=1, duration_ms=(time.monotonic() - start) * 1000,
            )

        # --- JSON run (for structured findings) ---
        json_cmd = [binary, "--format", "json", "--no-color", "--minimum-severity", min_sev, dir_path]
        if cfg.get("soft_fail"):
            json_cmd.append("--soft-fail")

        try:
            json_proc = subprocess.run(json_cmd, capture_output=True, text=True, timeout=180)
            findings = self._parse_dir_output(json_proc.stdout, dir_path)
        except Exception as exc:
            logger.error("tfsec JSON parse failed: %s", exc)
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
        results: list[ScanResult] = []
        for finding in data.get("results", []):
            severity = SEVERITY_MAP.get(finding.get("severity", "MEDIUM"), "MEDIUM")
            location = finding.get("location", {})
            raw_path = location.get("filename", "")
            rel_path = raw_path.replace(prefix, "") if raw_path.startswith(prefix) else raw_path

            results.append(
                ScanResult(
                    rule_id=f"TFSEC-{finding.get('rule_id', 'UNKNOWN')}",
                    title=finding.get("rule_description", "tfsec finding"),
                    description=finding.get("description", ""),
                    severity=severity,
                    category="iac",
                    cloud_provider=self._detect_cloud(finding),
                    resource_type=finding.get("resource", ""),
                    resource_name=finding.get("resource", ""),
                    file_path=rel_path,
                    line_number=location.get("start_line", 0),
                    code_snippet="",
                    remediation=finding.get("resolution", "See tfsec documentation."),
                    metadata={
                        "source": "tfsec",
                        "rule_id": finding.get("rule_id", ""),
                        "rule_provider": finding.get("rule_provider", ""),
                        "rule_service": finding.get("rule_service", ""),
                        "impact": finding.get("impact", ""),
                        "links": finding.get("links", [])[:3],
                    },
                )
            )
        return results

    def _parse_output(self, raw_json: str, file_name: str) -> list[ScanResult]:
        if not raw_json.strip():
            return []

        results: list[ScanResult] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("tfsec returned non-JSON output")
            return []

        for finding in data.get("results", []):
            severity = SEVERITY_MAP.get(finding.get("severity", "MEDIUM"), "MEDIUM")
            location = finding.get("location", {})

            results.append(
                ScanResult(
                    rule_id=f"TFSEC-{finding.get('rule_id', 'UNKNOWN')}",
                    title=finding.get("rule_description", "tfsec finding"),
                    description=finding.get("description", ""),
                    severity=severity,
                    category="iac",
                    cloud_provider=self._detect_cloud(finding),
                    resource_type=finding.get("resource", ""),
                    resource_name=finding.get("resource", ""),
                    file_path=file_name or location.get("filename", ""),
                    line_number=location.get("start_line", 0),
                    code_snippet="",
                    remediation=finding.get("resolution", "See tfsec documentation."),
                    metadata={
                        "source": "tfsec",
                        "rule_id": finding.get("rule_id", ""),
                        "rule_provider": finding.get("rule_provider", ""),
                        "rule_service": finding.get("rule_service", ""),
                        "impact": finding.get("impact", ""),
                        "links": finding.get("links", [])[:3],
                    },
                )
            )

        return results

    @staticmethod
    def _detect_cloud(finding: dict) -> str:
        provider = finding.get("rule_provider", "").lower()
        if provider == "aws":
            return "aws"
        if provider == "azure":
            return "azure"
        if provider in ("google", "gcp"):
            return "gcp"
        return "multi"

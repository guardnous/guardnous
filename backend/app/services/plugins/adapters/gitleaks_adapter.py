"""
Gitleaks Adapter — bridges Gitleaks secret detection into GuardNous.

Gitleaks is a fast, lightweight SAST tool for detecting hard-coded secrets
(passwords, API keys, tokens) in git repos and arbitrary files.

Install:  brew install gitleaks   (or go install github.com/gitleaks/gitleaks/v8@latest)
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
    PluginAdapter,
    PluginCapability,
    PluginHealth,
    PluginMetadata,
)
from app.services.scanners.base import ScanResult

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


class GitleaksAdapter(PluginAdapter):
    """Adapter for Gitleaks secret detection."""

    _binary = "gitleaks"

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="gitleaks",
            display_name="Gitleaks Secret Scanner",
            version="1.0.0",
            description=(
                "Fast, light-weight SAST tool for detecting hard-coded secrets in git repos "
                "and source code. 140+ built-in rules covering AWS, GCP, Azure, GitHub, Slack, and more."
            ),
            homepage="https://gitleaks.io",
            icon="KeyRound",
            capabilities=[PluginCapability.SECRETS],
            requires_binary=True,
            default_config={
                "config_path": "",  # custom .gitleaks.toml
                "redact": True,
                "verbose": False,
            },
        )

    def health(self) -> PluginHealth:
        binary = shutil.which(self._binary)
        if not binary:
            return PluginHealth(available=False, message=f"'{self._binary}' not found on PATH")
        try:
            start = time.monotonic()
            proc = subprocess.run(
                [binary, "version"],
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

        tmpdir = tempfile.mkdtemp()
        target_name = os.path.basename(file_name) if file_name else "scan.txt"
        target_path = os.path.join(tmpdir, target_name)
        report_path = os.path.join(tmpdir, "report.json")

        with open(target_path, "w") as f:
            f.write(content)

        try:
            cmd = [
                shutil.which(self._binary) or self._binary,
                "detect",
                "--source", tmpdir,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-git",
                "--exit-code", "0",
            ]
            if cfg.get("redact"):
                cmd.append("--redact")
            if cfg.get("config_path"):
                cmd.extend(["--config", cfg["config_path"]])

            subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if os.path.exists(report_path):
                with open(report_path) as f:
                    return self._parse_output(f.read(), file_name)
            return []

        except subprocess.TimeoutExpired:
            logger.error("Gitleaks scan timed out for %s", file_name)
            return []
        except Exception as exc:
            logger.error("Gitleaks scan failed: %s", exc)
            return []
        finally:
            import shutil as sh
            sh.rmtree(tmpdir, ignore_errors=True)

    def _parse_output(self, raw_json: str, file_name: str) -> list[ScanResult]:
        if not raw_json.strip():
            return []

        results: list[ScanResult] = []
        try:
            findings = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        if not isinstance(findings, list):
            return []

        for finding in findings:
            rule_id = finding.get("RuleID", "unknown")
            results.append(
                ScanResult(
                    rule_id=f"GL-{rule_id}",
                    title=f"Secret detected: {finding.get('Description', rule_id)}",
                    description=f"Gitleaks found a potential secret matching rule '{rule_id}'.",
                    severity=SEVERITY_MAP.get(finding.get("Severity", "high").lower(), "HIGH"),
                    category="secrets",
                    cloud_provider=self._detect_cloud(finding),
                    resource_type="secret",
                    resource_name=finding.get("Match", "")[:80],
                    file_path=file_name or finding.get("File", ""),
                    line_number=finding.get("StartLine", 0),
                    code_snippet=finding.get("Secret", "")[:60] + "****" if finding.get("Secret") else "",
                    remediation="Remove the exposed secret and rotate the credential immediately.",
                    metadata={
                        "source": "gitleaks",
                        "rule_id": rule_id,
                        "entropy": finding.get("Entropy", 0),
                        "author": finding.get("Author", ""),
                        "commit": finding.get("Commit", ""),
                    },
                )
            )

        return results

    @staticmethod
    def _detect_cloud(finding: dict) -> str:
        text = (finding.get("RuleID", "") + " " + finding.get("Description", "")).lower()
        if "aws" in text:
            return "aws"
        if "azure" in text or "microsoft" in text:
            return "azure"
        if "gcp" in text or "google" in text:
            return "gcp"
        if "github" in text:
            return "multi"
        return "multi"

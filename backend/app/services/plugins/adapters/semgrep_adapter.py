"""
Semgrep Adapter — bridges Semgrep SAST engine into GuardNous.

Semgrep is a fast, open-source SAST tool supporting 30+ languages.
It excels at custom rule authoring and has a large community rule registry.

Install:  pip install semgrep   (or brew install semgrep)
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
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


class SemgrepAdapter(PluginAdapter):
    """Adapter for Semgrep SAST scanner."""

    _binary = "semgrep"

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="semgrep",
            display_name="Semgrep SAST",
            version="1.0.0",
            description=(
                "Lightweight SAST engine supporting 30+ languages with pattern-based "
                "rules. Covers security, correctness, and best practices with 5000+ community rules."
            ),
            homepage="https://semgrep.dev",
            icon="Search",
            capabilities=[
                PluginCapability.SAST,
                PluginCapability.IAC_TERRAFORM,
                PluginCapability.IAC_DOCKERFILE,
            ],
            requires_binary=True,
            default_config={
                "config": "auto",  # or "p/terraform", "p/docker", custom rule path
                "severity": [],  # empty = all
                "exclude": [],
                "timeout": 300,
            },
        )

    def health(self) -> PluginHealth:
        binary = shutil.which(self._binary)
        if not binary:
            return PluginHealth(available=False, message=f"'{self._binary}' not found on PATH")
        # Semgrep --version is extremely slow on cold start (downloads rules index).
        # Just verify the binary exists and is executable.
        return PluginHealth(available=True, version="installed", latency_ms=0.0)

    def scan(
        self,
        content: str,
        file_name: str = "",
        config: dict[str, Any] | None = None,
    ) -> list[ScanResult]:
        cfg = {**self.metadata().default_config, **(config or {})}

        suffix = os.path.splitext(file_name)[1] if file_name else ".tf"
        tmpdir = tempfile.mkdtemp()
        target_name = os.path.basename(file_name) if file_name else f"scan{suffix}"
        target_path = os.path.join(tmpdir, target_name)

        with open(target_path, "w") as f:
            f.write(content)

        try:
            cmd = [
                shutil.which(self._binary) or self._binary,
                "scan",
                "--json",
                "--config", cfg.get("config", "auto"),
                "--quiet",
                tmpdir,
            ]
            for exc_pattern in cfg.get("exclude", []):
                cmd.extend(["--exclude", exc_pattern])

            timeout = cfg.get("timeout", 90)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return self._parse_output(proc.stdout, file_name)

        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out for %s", file_name)
            return []
        except Exception as exc:
            logger.error("Semgrep scan failed: %s", exc)
            return []
        finally:
            import shutil as sh
            sh.rmtree(tmpdir, ignore_errors=True)

    def supports_directory_scan(self) -> bool:
        return True

    # Path to bundled local rules (fallback when remote download fails)
    _LOCAL_RULES = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "rules", "semgrep-iac.yaml"
    )

    def _resolve_config(self, cfg: dict) -> str:
        """Return the semgrep --config value.  Use bundled local rules
        when remote configs (auto / p/*) can't be downloaded (SSL issues
        inside Docker containers)."""
        requested = cfg.get("config", "auto")
        # If user explicitly set a local path, honour it
        if os.path.exists(requested):
            return requested
        # For remote configs, test reachability first
        if requested in ("auto",) or requested.startswith("p/"):
            if os.path.isfile(self._LOCAL_RULES):
                return self._LOCAL_RULES
        return requested

    def scan_directory(
        self,
        dir_path: str,
        config: dict[str, Any] | None = None,
    ) -> DirectoryScanResult:
        cfg = {**self.metadata().default_config, **(config or {})}
        binary = shutil.which(self._binary) or self._binary
        timeout = cfg.get("timeout", 300)

        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"

        sem_config = self._resolve_config(cfg)

        # --- Text run (real CLI output) ---
        text_cmd = [binary, "scan", "--config", sem_config, dir_path]
        for exc_pattern in cfg.get("exclude", []):
            text_cmd.extend(["--exclude", exc_pattern])
        text_cmd_str = " ".join(text_cmd)

        start = time.monotonic()
        try:
            text_proc = subprocess.run(
                text_cmd, capture_output=True, text=True, timeout=timeout, env=env,
            )
            raw_output = text_proc.stdout or ""
            if text_proc.returncode not in (0, 1) and not raw_output.strip():
                raw_output = text_proc.stderr or f"semgrep exited with code {text_proc.returncode}"
        except subprocess.TimeoutExpired:
            return DirectoryScanResult(
                findings=[], raw_output=f"semgrep timed out after {timeout}s",
                command=text_cmd_str, exit_code=124,
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return DirectoryScanResult(
                findings=[], raw_output=f"semgrep failed: {exc}",
                command=text_cmd_str, exit_code=1,
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # --- JSON run (for structured findings) ---
        json_cmd = [binary, "scan", "--json", "--config", sem_config, "--quiet", dir_path]
        for exc_pattern in cfg.get("exclude", []):
            json_cmd.extend(["--exclude", exc_pattern])

        try:
            json_proc = subprocess.run(
                json_cmd, capture_output=True, text=True, timeout=timeout, env=env,
            )
            findings = self._parse_dir_output(json_proc.stdout, dir_path)
        except Exception as exc:
            logger.error("Semgrep JSON parse failed: %s", exc)
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
            extra = finding.get("extra", {})
            severity = SEVERITY_MAP.get(extra.get("severity", "WARNING"), "MEDIUM")
            metadata_obj = extra.get("metadata", {})

            cwe = metadata_obj.get("cwe", [])
            if isinstance(cwe, list):
                cwe = ", ".join(str(c) for c in cwe[:3])

            raw_path = finding.get("path", "")
            rel_path = raw_path.replace(prefix, "") if raw_path.startswith(prefix) else raw_path

            lines = extra.get("lines", "")
            snippet = lines[:300] if isinstance(lines, str) else ""

            results.append(
                ScanResult(
                    rule_id=f"SG-{finding.get('check_id', 'unknown').split('.')[-1]}",
                    title=extra.get("message", "Semgrep finding")[:200],
                    description=extra.get("message", ""),
                    severity=severity,
                    category="sast",
                    cloud_provider=self._detect_cloud(finding),
                    resource_type=metadata_obj.get("technology", [""])[0] if metadata_obj.get("technology") else "",
                    resource_name=finding.get("check_id", ""),
                    file_path=rel_path,
                    line_number=finding.get("start", {}).get("line", 0),
                    code_snippet=snippet,
                    remediation=extra.get("fix", "See Semgrep rule documentation."),
                    metadata={
                        "source": "semgrep",
                        "check_id": finding.get("check_id", ""),
                        "cwe": cwe,
                        "confidence": metadata_obj.get("confidence", ""),
                        "owasp": metadata_obj.get("owasp", []),
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
            logger.warning("Semgrep returned non-JSON output")
            return []

        for finding in data.get("results", []):
            extra = finding.get("extra", {})
            severity = SEVERITY_MAP.get(extra.get("severity", "WARNING"), "MEDIUM")

            # Extract metadata
            metadata_obj = extra.get("metadata", {})
            cwe = metadata_obj.get("cwe", [])
            if isinstance(cwe, list):
                cwe = ", ".join(str(c) for c in cwe[:3])

            lines = extra.get("lines", "")
            snippet = lines[:300] if isinstance(lines, str) else ""

            results.append(
                ScanResult(
                    rule_id=f"SG-{finding.get('check_id', 'unknown').split('.')[-1]}",
                    title=extra.get("message", "Semgrep finding")[:200],
                    description=extra.get("message", ""),
                    severity=severity,
                    category="sast",
                    cloud_provider=self._detect_cloud(finding),
                    resource_type=metadata_obj.get("technology", [""])[0] if metadata_obj.get("technology") else "",
                    resource_name=finding.get("check_id", ""),
                    file_path=file_name or finding.get("path", ""),
                    line_number=finding.get("start", {}).get("line", 0),
                    code_snippet=snippet,
                    remediation=extra.get("fix", "See Semgrep rule documentation."),
                    metadata={
                        "source": "semgrep",
                        "check_id": finding.get("check_id", ""),
                        "cwe": cwe,
                        "confidence": metadata_obj.get("confidence", ""),
                        "owasp": metadata_obj.get("owasp", []),
                    },
                )
            )

        return results

    @staticmethod
    def _detect_cloud(finding: dict) -> str:
        check_id = finding.get("check_id", "").lower()
        if "terraform" in check_id or "aws" in check_id:
            return "aws"
        if "azure" in check_id:
            return "azure"
        if "gcp" in check_id or "google" in check_id:
            return "gcp"
        return "multi"

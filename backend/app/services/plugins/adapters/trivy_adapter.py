"""
Trivy Adapter — bridges Aqua Security's Trivy scanner into GuardNous.

Trivy scans IaC (Terraform, CloudFormation, Kubernetes, Dockerfile),
container images, file systems for vulnerabilities, misconfigurations,
and exposed secrets.

Install:  brew install trivy   (or apt-get install trivy)
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
    "UNKNOWN": "MEDIUM",
}


class TrivyAdapter(PluginAdapter):
    """Adapter for Aqua Security's Trivy scanner."""

    _binary = "trivy"

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="trivy",
            display_name="Aqua Trivy",
            version="1.0.0",
            description=(
                "Comprehensive vulnerability and misconfiguration scanner for containers, "
                "IaC, file systems, and Git repos. Covers CVEs, misconfig, and secrets."
            ),
            homepage="https://trivy.dev",
            icon="Shield",
            capabilities=[
                PluginCapability.IAC_TERRAFORM,
                PluginCapability.IAC_CLOUDFORMATION,
                PluginCapability.IAC_KUBERNETES,
                PluginCapability.IAC_DOCKERFILE,
                PluginCapability.SECRETS,
                PluginCapability.SCA,
                PluginCapability.CONTAINER,
            ],
            requires_binary=True,
            default_config={
                "severity": "CRITICAL,HIGH,MEDIUM,LOW",
                "scanners": "misconfig,secret",
                "skip_dirs": [],
            },
        )

    def health(self) -> PluginHealth:
        binary = shutil.which(self._binary)
        if not binary:
            return PluginHealth(available=False, message=f"'{self._binary}' not found on PATH")
        try:
            start = time.monotonic()
            proc = subprocess.run(
                [binary, "version", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            latency = (time.monotonic() - start) * 1000
            try:
                ver_data = json.loads(proc.stdout)
                version = ver_data.get("Version", "unknown")
            except json.JSONDecodeError:
                version = proc.stdout.strip().split("\n")[0] if proc.stdout else "unknown"
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
        target_name = os.path.basename(file_name) if file_name else f"scan{suffix}"
        target_path = os.path.join(tmpdir, target_name)

        with open(target_path, "w") as f:
            f.write(content)

        try:
            cmd = [
                shutil.which(self._binary) or self._binary,
                "fs",
                "--format", "json",
                "--severity", cfg.get("severity", "CRITICAL,HIGH,MEDIUM,LOW"),
                "--scanners", cfg.get("scanners", "misconfig,secret"),
                "--exit-code", "0",
                tmpdir,
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return self._parse_output(proc.stdout, file_name)

        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out for %s", file_name)
            return []
        except Exception as exc:
            logger.error("Trivy scan failed: %s", exc)
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
        severity = cfg.get("severity", "CRITICAL,HIGH,MEDIUM,LOW")
        scanners = cfg.get("scanners", "misconfig,secret")

        # --- Text run (real CLI output) ---
        text_cmd = [
            binary, "fs",
            "--severity", severity,
            "--scanners", scanners,
            "--exit-code", "0",
            dir_path,
        ]
        text_cmd_str = " ".join(text_cmd)

        start = time.monotonic()
        try:
            text_proc = subprocess.run(text_cmd, capture_output=True, text=True, timeout=180)
            raw_output = text_proc.stdout or ""
            if text_proc.stderr:
                # Trivy prints progress to stderr; include relevant parts
                err_lines = [l for l in text_proc.stderr.splitlines()
                             if not l.strip().startswith("20") or "FATAL" in l or "ERROR" in l]
                if err_lines:
                    raw_output += "\n" + "\n".join(err_lines)
        except subprocess.TimeoutExpired:
            return DirectoryScanResult(
                findings=[], raw_output="trivy timed out after 180s",
                command=text_cmd_str, exit_code=124, duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return DirectoryScanResult(
                findings=[], raw_output=f"trivy failed: {exc}",
                command=text_cmd_str, exit_code=1, duration_ms=(time.monotonic() - start) * 1000,
            )

        # --- JSON run (for structured findings) ---
        json_cmd = [
            binary, "fs",
            "--format", "json",
            "--severity", severity,
            "--scanners", scanners,
            "--exit-code", "0",
            dir_path,
        ]
        try:
            json_proc = subprocess.run(json_cmd, capture_output=True, text=True, timeout=180)
            findings = self._parse_dir_output(json_proc.stdout, dir_path)
        except Exception as exc:
            logger.error("Trivy JSON parse failed: %s", exc)
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
        for target in data.get("Results", []):
            target_name = target.get("Target", "")
            rel_target = target_name.replace(prefix, "") if target_name.startswith(prefix) else target_name

            for misconfig in target.get("Misconfigurations", []):
                severity = SEVERITY_MAP.get(misconfig.get("Severity", "MEDIUM"), "MEDIUM")
                cause = misconfig.get("CauseMetadata", {})
                raw_fn = cause.get("Filename", "")
                rel_fn = raw_fn.replace(prefix, "") if raw_fn.startswith(prefix) else raw_fn
                results.append(
                    ScanResult(
                        rule_id=f"TRIVY-{misconfig.get('ID', 'UNKNOWN')}",
                        title=misconfig.get("Title", "Trivy misconfiguration"),
                        description=misconfig.get("Description", ""),
                        severity=severity,
                        category="iac",
                        cloud_provider=self._detect_cloud(misconfig),
                        resource_type=misconfig.get("Type", ""),
                        resource_name=rel_target,
                        file_path=rel_fn or rel_target,
                        line_number=cause.get("StartLine", 0),
                        code_snippet=cause.get("Code", {}).get("Lines", ""),
                        remediation=misconfig.get("Resolution", "See Trivy documentation."),
                        metadata={"source": "trivy", "avd_id": misconfig.get("AVDID", "")},
                    )
                )

            for secret in target.get("Secrets", []):
                severity = SEVERITY_MAP.get(secret.get("Severity", "HIGH"), "HIGH")
                results.append(
                    ScanResult(
                        rule_id=f"TRIVY-SECRET-{secret.get('RuleID', 'UNKNOWN')}",
                        title=secret.get("Title", "Secret detected"),
                        description=f"Trivy detected a secret: {secret.get('Category', '')}",
                        severity=severity,
                        category="secrets",
                        cloud_provider="multi",
                        resource_type="secret",
                        resource_name=secret.get("Match", ""),
                        file_path=rel_target,
                        line_number=secret.get("StartLine", 0),
                        code_snippet=secret.get("Match", "")[:120],
                        remediation="Remove the secret and rotate the credential.",
                        metadata={"source": "trivy", "rule_id": secret.get("RuleID", "")},
                    )
                )

            for vuln in target.get("Vulnerabilities", []):
                severity = SEVERITY_MAP.get(vuln.get("Severity", "MEDIUM"), "MEDIUM")
                results.append(
                    ScanResult(
                        rule_id=f"TRIVY-{vuln.get('VulnerabilityID', 'UNKNOWN')}",
                        title=f"{vuln.get('VulnerabilityID', '')}: {vuln.get('Title', '')}",
                        description=vuln.get("Description", ""),
                        severity=severity,
                        category="cve",
                        cloud_provider="multi",
                        resource_type=vuln.get("PkgName", ""),
                        resource_name=f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                        file_path=rel_target,
                        line_number=0,
                        code_snippet="",
                        remediation=f"Upgrade to {vuln.get('FixedVersion', 'latest')}",
                        cve_id=vuln.get("VulnerabilityID", ""),
                        metadata={"source": "trivy", "installed": vuln.get("InstalledVersion", "")},
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
            logger.warning("Trivy returned non-JSON output")
            return []

        # Trivy wraps results in a "Results" array
        trivy_results = data.get("Results", [])
        for target in trivy_results:
            target_name = target.get("Target", "")

            # Misconfigurations
            for misconfig in target.get("Misconfigurations", []):
                severity = SEVERITY_MAP.get(misconfig.get("Severity", "MEDIUM"), "MEDIUM")
                results.append(
                    ScanResult(
                        rule_id=f"TRIVY-{misconfig.get('ID', 'UNKNOWN')}",
                        title=misconfig.get("Title", "Trivy misconfiguration"),
                        description=misconfig.get("Description", ""),
                        severity=severity,
                        category="iac",
                        cloud_provider=self._detect_cloud(misconfig),
                        resource_type=misconfig.get("Type", ""),
                        resource_name=target_name,
                        file_path=file_name or misconfig.get("CauseMetadata", {}).get("Filename", ""),
                        line_number=misconfig.get("CauseMetadata", {}).get("StartLine", 0),
                        code_snippet=misconfig.get("CauseMetadata", {}).get("Code", {}).get("Lines", ""),
                        remediation=misconfig.get("Resolution", "See Trivy documentation."),
                        metadata={"source": "trivy", "avd_id": misconfig.get("AVDID", "")},
                    )
                )

            # Secrets
            for secret in target.get("Secrets", []):
                severity = SEVERITY_MAP.get(secret.get("Severity", "HIGH"), "HIGH")
                results.append(
                    ScanResult(
                        rule_id=f"TRIVY-SECRET-{secret.get('RuleID', 'UNKNOWN')}",
                        title=secret.get("Title", "Secret detected"),
                        description=f"Trivy detected a secret: {secret.get('Category', '')}",
                        severity=severity,
                        category="secrets",
                        cloud_provider="multi",
                        resource_type="secret",
                        resource_name=secret.get("Match", ""),
                        file_path=file_name or target_name,
                        line_number=secret.get("StartLine", 0),
                        code_snippet=secret.get("Match", "")[:120],
                        remediation="Remove the secret and rotate the credential.",
                        metadata={"source": "trivy", "rule_id": secret.get("RuleID", "")},
                    )
                )

            # Vulnerabilities (SCA)
            for vuln in target.get("Vulnerabilities", []):
                severity = SEVERITY_MAP.get(vuln.get("Severity", "MEDIUM"), "MEDIUM")
                results.append(
                    ScanResult(
                        rule_id=f"TRIVY-{vuln.get('VulnerabilityID', 'UNKNOWN')}",
                        title=f"{vuln.get('VulnerabilityID', '')}: {vuln.get('Title', '')}",
                        description=vuln.get("Description", ""),
                        severity=severity,
                        category="cve",
                        cloud_provider="multi",
                        resource_type=vuln.get("PkgName", ""),
                        resource_name=f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                        file_path=file_name or target_name,
                        line_number=0,
                        code_snippet="",
                        remediation=f"Upgrade to {vuln.get('FixedVersion', 'latest')}",
                        cve_id=vuln.get("VulnerabilityID", ""),
                        metadata={"source": "trivy", "installed": vuln.get("InstalledVersion", "")},
                    )
                )

        return results

    @staticmethod
    def _detect_cloud(item: dict) -> str:
        title = (item.get("Title", "") + " " + item.get("ID", "")).lower()
        if "aws" in title:
            return "aws"
        if "azure" in title:
            return "azure"
        if "google" in title or "gcp" in title:
            return "gcp"
        return "multi"

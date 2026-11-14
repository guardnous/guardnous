"""
Plugin Adapter Base — the contract every scanner plugin must implement.

GuardNous treats all scanners uniformly: native (built-in) and external
(Checkov, Trivy, Gitleaks, etc.) both implement PluginAdapter. This lets the
ScanOrchestrator fan out work to any registered plugin without knowing its
internals.
"""

from __future__ import annotations

import enum
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.services.scanners.base import ScanResult


# ── Directory scan result ─────────────────────────────────────────────────────


@dataclass
class DirectoryScanResult:
    """Result from scanning a whole directory — includes real CLI output."""

    findings: list[ScanResult]
    raw_output: str = ""        # Real CLI text output (human-readable)
    command: str = ""           # Exact command executed
    exit_code: int = 0
    duration_ms: float = 0.0
    stderr: str = ""


# ── Capabilities ──────────────────────────────────────────────────────────────


class PluginCapability(str, enum.Enum):
    """Declares what a plugin can scan."""

    IAC_TERRAFORM = "iac_terraform"
    IAC_CLOUDFORMATION = "iac_cloudformation"
    IAC_BICEP = "iac_bicep"
    IAC_HELM = "iac_helm"
    IAC_KUBERNETES = "iac_kubernetes"
    IAC_ANSIBLE = "iac_ansible"
    IAC_DOCKERFILE = "iac_dockerfile"
    SECRETS = "secrets"
    SCA = "sca"  # Software Composition Analysis (deps)
    SAST = "sast"  # Static Application Security Testing
    CONTAINER = "container"  # Container image scanning
    LICENSE = "license"


# ── Health ────────────────────────────────────────────────────────────────────


@dataclass
class PluginHealth:
    """Result of a plugin health check."""

    available: bool
    version: str = "unknown"
    message: str = ""
    latency_ms: float = 0.0


# ── Metadata ──────────────────────────────────────────────────────────────────


@dataclass
class PluginMetadata:
    """Static descriptor returned by every plugin."""

    name: str  # unique slug, e.g. "checkov"
    display_name: str  # human-friendly, e.g. "Checkov by Prisma Cloud"
    version: str  # plugin adapter version (not the tool version)
    description: str
    homepage: str  # URL to the tool's docs or repo
    icon: str  # lucide-react icon name for the frontend
    capabilities: list[PluginCapability]
    is_native: bool = False  # True for built-in scanners
    requires_binary: bool = False  # True if it shells out to an external CLI
    default_config: dict[str, Any] = field(default_factory=dict)


# ── Base adapter ──────────────────────────────────────────────────────────────


class PluginAdapter(ABC):
    """
    Contract every scanner plugin must satisfy.

    Lifecycle:
        1. ``metadata()``  — called once at registration time.
        2. ``health()``    — called periodically or on-demand to check readiness.
        3. ``scan()``      — called per file; returns normalised ScanResult list.
        4. ``cleanup()``   — called on shutdown (optional).
    """

    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return static plugin descriptor."""

    @abstractmethod
    def health(self) -> PluginHealth:
        """
        Check whether the plugin's backing tool/service is available.

        For CLI-based plugins this typically means ``shutil.which(binary)``.
        For native plugins this always returns ``available=True``.
        """

    @abstractmethod
    def scan(
        self,
        content: str,
        file_name: str = "",
        config: dict[str, Any] | None = None,
    ) -> list[ScanResult]:
        """
        Run the scan and return normalised findings.

        Parameters
        ----------
        content : str
            Raw file content to scan.
        file_name : str
            Original file path (used for type detection and display).
        config : dict, optional
            Per-run overrides merged onto ``default_config``.
        """

    def accepts(self, file_name: str) -> bool:
        """
        Quick pre-filter: can this plugin handle the given file?

        Default implementation checks file extension against capabilities.
        Plugins may override for smarter detection (e.g. sniffing content).
        """
        ext_map: dict[str, set[PluginCapability]] = {
            ".tf": {PluginCapability.IAC_TERRAFORM},
            ".tfvars": {PluginCapability.IAC_TERRAFORM},
            ".yaml": {
                PluginCapability.IAC_CLOUDFORMATION,
                PluginCapability.IAC_HELM,
                PluginCapability.IAC_KUBERNETES,
                PluginCapability.IAC_ANSIBLE,
            },
            ".yml": {
                PluginCapability.IAC_CLOUDFORMATION,
                PluginCapability.IAC_HELM,
                PluginCapability.IAC_KUBERNETES,
                PluginCapability.IAC_ANSIBLE,
            },
            ".json": {PluginCapability.IAC_CLOUDFORMATION, PluginCapability.IAC_TERRAFORM},
            ".bicep": {PluginCapability.IAC_BICEP},
            ".dockerfile": {PluginCapability.IAC_DOCKERFILE},
        }

        caps = set(self.metadata().capabilities)

        # Secrets and SAST plugins accept everything
        if PluginCapability.SECRETS in caps or PluginCapability.SAST in caps:
            return True

        # Check file extension
        lower = file_name.lower()
        if lower.endswith("dockerfile") or lower.startswith("dockerfile"):
            return PluginCapability.IAC_DOCKERFILE in caps

        for ext, matching_caps in ext_map.items():
            if lower.endswith(ext) and caps & matching_caps:
                return True

        return False

    def supports_directory_scan(self) -> bool:
        """Whether this plugin can scan a whole directory at once."""
        return False

    def scan_directory(
        self,
        dir_path: str,
        config: dict[str, Any] | None = None,
    ) -> DirectoryScanResult:
        """
        Scan an entire directory tree. Returns real CLI output + parsed findings.

        Only external (CLI-based) plugins implement this. Native plugins should
        continue using per-file ``scan()``.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support directory scanning")

    def cleanup(self) -> None:
        """Optional teardown hook called on shutdown."""


# ── Timing helper ─────────────────────────────────────────────────────────────


def timed_scan(adapter: PluginAdapter, content: str, file_name: str, config: dict | None = None):
    """Run a scan and capture wall-clock time."""
    start = time.monotonic()
    results = adapter.scan(content, file_name, config)
    elapsed_ms = (time.monotonic() - start) * 1000
    return results, elapsed_ms

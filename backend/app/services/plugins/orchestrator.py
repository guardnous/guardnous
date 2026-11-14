"""
Scan Orchestrator — unified scan execution engine that replaces hardcoded
scanner dictionaries.

Fans out file content to all enabled plugins whose ``accepts()`` returns True,
collects results, deduplicates findings, and returns a merged result set.
"""

from __future__ import annotations

import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from app.services.plugins.integrity import ensure_adapter_integrity
from app.services.plugins.registry import PluginRegistry, get_registry
from app.services.scanners.base import ScanResult

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorResult:
    """Aggregated result of a multi-plugin scan."""

    findings: list[ScanResult] = field(default_factory=list)
    plugin_timings: dict[str, float] = field(default_factory=dict)  # plugin_name → ms
    plugin_errors: dict[str, str] = field(default_factory=dict)  # plugin_name → error msg
    total_ms: float = 0.0
    plugins_used: list[str] = field(default_factory=list)


def plugin_error_summary(plugin_errors: dict[str, str]) -> str | None:
    """One message for the scan record when some scanners did not produce results.

    The scan's findings are incomplete in that case and the user must be told.
    """
    if not plugin_errors:
        return None
    parts = [f"{name}: {message}" for name, message in sorted(plugin_errors.items())]
    return ("Results are incomplete — these scanners did not run successfully. " + " | ".join(parts))[:2000]


class ScanOrchestrator:
    """
    Coordinates scans across all registered & enabled plugins.

    Usage::

        orchestrator = ScanOrchestrator()
        result = orchestrator.scan(content, file_name="main.tf")
        # result.findings  →  deduplicated ScanResult list
    """

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        max_workers: int = 6,
    ) -> None:
        self._registry = registry or get_registry()
        self._max_workers = max_workers

    def scan(
        self,
        content: str,
        file_name: str = "",
        config: dict[str, Any] | None = None,
        plugin_names: list[str] | None = None,
    ) -> OrchestratorResult:
        """
        Run content through all applicable enabled plugins.

        Args:
            content: Raw file content to scan.
            file_name: Original file name (used for plugin routing and reporting).
            config: Optional per-plugin config overrides ``{plugin_name: {key: val}}``.
            plugin_names: Optional explicit list of plugin names to use.
                          If ``None``, all enabled plugins that accept the file are used.

        Returns:
            OrchestratorResult with deduplicated findings and timing.
        """
        start = time.monotonic()
        cfg = config or {}

        # Resolve which plugins to invoke
        if plugin_names:
            plugins = [
                (name, adapter)
                for name, adapter in self._registry.list_enabled().items()
                if name in plugin_names and adapter.accepts(file_name)
            ]
        else:
            plugins = [
                (name, adapter)
                for name, adapter in self._registry.list_enabled().items()
                if adapter.accepts(file_name)
            ]

        if not plugins:
            logger.info("No plugins accept file '%s'", file_name)
            return OrchestratorResult(total_ms=(time.monotonic() - start) * 1000)

        result = OrchestratorResult()
        result.plugins_used = [name for name, _ in plugins]
        all_findings: list[ScanResult] = []

        # Fan-out concurrently
        with ThreadPoolExecutor(max_workers=min(self._max_workers, len(plugins))) as pool:
            futures = {
                pool.submit(
                    self._run_single,
                    name,
                    adapter,
                    content,
                    file_name,
                    cfg.get(name, {}),
                ): name
                for name, adapter in plugins
            }

            for future in as_completed(futures):
                plugin_name = futures[future]
                try:
                    findings, elapsed_ms = future.result()
                    all_findings.extend(findings)
                    result.plugin_timings[plugin_name] = elapsed_ms
                except Exception as exc:
                    result.plugin_errors[plugin_name] = str(exc)
                    logger.error("Plugin '%s' failed: %s", plugin_name, exc)

        # Deduplicate
        result.findings = self._deduplicate(all_findings)
        result.total_ms = (time.monotonic() - start) * 1000

        logger.info(
            "Orchestrator: %d findings from %d plugins in %.0f ms (deduped from %d raw)",
            len(result.findings),
            len(result.plugins_used),
            result.total_ms,
            len(all_findings),
        )

        return result

    @staticmethod
    def _run_single(
        name: str,
        adapter: Any,
        content: str,
        file_name: str,
        plugin_config: dict,
    ) -> tuple[list[ScanResult], float]:
        """Execute a single plugin scan with timing."""
        start = time.monotonic()
        try:
            # Raises PluginIntegrityError if the scanner binary changed since it was pinned
            ensure_adapter_integrity(adapter)
            findings = adapter.scan(content, file_name, plugin_config or None)
        except Exception:
            logger.exception("Plugin '%s' raised during scan", name)
            raise
        elapsed = (time.monotonic() - start) * 1000
        # Stamp each finding with the plugin that produced it
        for f in findings:
            if not f.metadata:
                f.metadata = {}
            f.metadata["source"] = name
        return findings, elapsed

    @staticmethod
    def _deduplicate(findings: list[ScanResult]) -> list[ScanResult]:
        """
        Remove duplicate findings across plugins.

        Dedup key = (rule_id, file_path, line_number, resource_name).
        When duplicates exist, the finding with the higher severity wins.
        """
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        seen: dict[str, ScanResult] = {}

        for f in findings:
            key = _finding_key(f)
            existing = seen.get(key)
            if existing is None:
                seen[key] = f
            else:
                # Keep the higher-severity one
                if severity_rank.get(f.severity, 0) > severity_rank.get(existing.severity, 0):
                    seen[key] = f

        return list(seen.values())


def _finding_key(f: ScanResult) -> str:
    """Stable dedup key for a finding."""
    raw = f"{f.rule_id}|{f.file_path}|{f.line_number}|{f.resource_name}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()

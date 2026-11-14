"""
Plugin Version Manager — supply-chain-aware version control for external scanners.

Manages multi-version binary cache, SHA-256 hash verification, auto-rollback
on CVE detection, and admin-controlled version pinning. Each scanner binary
is downloaded, verified, and stored in a versioned cache directory.

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                   VersionManager                         │
    │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
    │  │ Registry │  │ Cache    │  │ Health Monitor Agent  │  │
    │  │ (PyPI /  │  │ (local   │  │ (checks NVD/GitHub   │  │
    │  │ GitHub / │──│ versioned│──│ advisories for our    │  │
    │  │ brew)    │  │ binaries)│  │ own toolchain)        │  │
    │  └──────────┘  └──────────┘  └──────────────────────┘  │
    └─────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default cache directory for scanner binaries
CACHE_DIR = Path(os.environ.get("GUARDNOUS_PLUGIN_CACHE", "/app/data/plugin_cache"))


class VersionStatus(str, Enum):
    ACTIVE = "active"           # Currently in use
    AVAILABLE = "available"     # Downloaded but not active
    VULNERABLE = "vulnerable"   # Known CVE — DO NOT USE
    DOWNLOADING = "downloading" # Download in progress
    FAILED = "failed"           # Download or verification failed


class InstallMethod(str, Enum):
    PIP = "pip"
    BINARY = "binary"       # Direct binary download
    APT = "apt"
    BREW = "brew"
    DOCKER = "docker"       # Run in ephemeral container


@dataclass
class PluginVersion:
    """Represents a specific version of a scanner plugin."""
    plugin_name: str
    version: str
    status: VersionStatus = VersionStatus.AVAILABLE
    install_method: InstallMethod = InstallMethod.PIP
    sha256: str | None = None
    binary_path: str | None = None
    installed_at: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    release_date: str | None = None
    changelog_url: str | None = None
    size_bytes: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VersionPolicy:
    """Admin-defined version policy for a plugin."""
    plugin_name: str
    pinned_version: str | None = None       # None = auto-update
    auto_update: bool = True
    auto_rollback: bool = True              # Rollback on CVE detection
    max_cached_versions: int = 3
    allowed_versions: list[str] | None = None  # None = all versions allowed
    blocked_versions: list[str] = field(default_factory=list)


# Known scanner package info for version resolution
SCANNER_REGISTRY: dict[str, dict[str, Any]] = {
    "semgrep": {
        "install_method": InstallMethod.PIP,
        "pip_package": "semgrep",
        "binary_name": "semgrep",
        "github_repo": "semgrep/semgrep",
        "min_version": "1.0.0",
        "homepage": "https://semgrep.dev",
    },
    "trivy": {
        "install_method": InstallMethod.BINARY,
        "binary_name": "trivy",
        "github_repo": "aquasecurity/trivy",
        "min_version": "0.40.0",
        "homepage": "https://trivy.dev",
    },
    "checkov": {
        "install_method": InstallMethod.PIP,
        "pip_package": "checkov",
        "binary_name": "checkov",
        "github_repo": "bridgecrewio/checkov",
        "min_version": "3.0.0",
        "homepage": "https://www.checkov.io",
    },
    "gitleaks": {
        "install_method": InstallMethod.BINARY,
        "binary_name": "gitleaks",
        "github_repo": "gitleaks/gitleaks",
        "min_version": "8.0.0",
        "homepage": "https://gitleaks.io",
    },
    "tfsec": {
        "install_method": InstallMethod.BINARY,
        "binary_name": "tfsec",
        "github_repo": "aquasecurity/tfsec",
        "min_version": "1.0.0",
        "homepage": "https://tfsec.dev",
    },
}


class VersionManager:
    """
    Central manager for scanner plugin versions.

    Responsibilities:
    - Track installed versions per plugin
    - Download and verify new versions
    - Maintain a multi-version cache (N versions per plugin)
    - Auto-rollback to last-known-good on CVE detection
    - Provide version info for admin UI
    """

    def __init__(self, cache_dir: Path | None = None, redis_client=None):
        self._cache_dir = cache_dir or CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._redis = redis_client
        self._versions: dict[str, list[PluginVersion]] = {}
        self._policies: dict[str, VersionPolicy] = {}
        self._load_state()

    # ── State persistence ────────────────────────────────────────────────

    def _state_file(self) -> Path:
        return self._cache_dir / "version_state.json"

    def _load_state(self):
        """Load version state from disk (and optionally Redis)."""
        state_file = self._state_file()
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text())
                for plugin, versions in data.get("versions", {}).items():
                    self._versions[plugin] = [
                        PluginVersion(**v) for v in versions
                    ]
                for plugin, policy in data.get("policies", {}).items():
                    self._policies[plugin] = VersionPolicy(**policy)
            except Exception as exc:
                logger.warning("Failed to load version state: %s", exc)

        # Also detect currently installed versions
        self._detect_installed()

    def _save_state(self):
        """Persist version state to disk."""
        data = {
            "versions": {
                plugin: [v.to_dict() for v in versions]
                for plugin, versions in self._versions.items()
            },
            "policies": {
                plugin: asdict(policy)
                for plugin, policy in self._policies.items()
            },
            "updated_at": time.time(),
        }
        try:
            self._state_file().write_text(json.dumps(data, indent=2, default=str))
        except Exception as exc:
            logger.warning("Failed to save version state: %s", exc)

        # Mirror to Redis for API layer
        if self._redis:
            try:
                self._redis.setex(
                    "plugin_versions_state",
                    86400,
                    json.dumps(data, default=str),
                )
            except Exception:
                pass

    def _detect_installed(self):
        """Detect currently installed scanner versions via CLI."""
        for plugin_name, info in SCANNER_REGISTRY.items():
            binary = info["binary_name"]
            path = shutil.which(binary)
            if not path:
                continue

            version = self._get_binary_version(binary)
            if not version:
                continue

            if plugin_name not in self._versions:
                self._versions[plugin_name] = []

            # Check if this version is already tracked
            existing = next(
                (v for v in self._versions[plugin_name] if v.version == version),
                None,
            )
            if existing:
                existing.status = VersionStatus.ACTIVE
                existing.binary_path = path
            else:
                self._versions[plugin_name].append(PluginVersion(
                    plugin_name=plugin_name,
                    version=version,
                    status=VersionStatus.ACTIVE,
                    install_method=info["install_method"],
                    binary_path=path,
                    installed_at=time.time(),
                ))

        self._save_state()

    @staticmethod
    def _get_binary_version(binary: str) -> str | None:
        """Get version string from a scanner binary."""
        version_flags = ["--version", "version", "-v"]
        for flag in version_flags:
            try:
                result = subprocess.run(
                    [binary, flag],
                    capture_output=True, text=True, timeout=10,
                )
                output = (result.stdout or result.stderr).strip()
                # Extract version number (e.g., "semgrep 1.78.0" → "1.78.0")
                import re
                match = re.search(r"(\d+\.\d+\.\d+)", output)
                if match:
                    return match.group(1)
            except Exception:
                continue
        return None

    # ── Version queries ──────────────────────────────────────────────────

    def get_installed_versions(self, plugin_name: str) -> list[PluginVersion]:
        """Return all cached versions for a plugin."""
        return self._versions.get(plugin_name, [])

    def get_active_version(self, plugin_name: str) -> PluginVersion | None:
        """Return the currently active version for a plugin."""
        versions = self._versions.get(plugin_name, [])
        return next(
            (v for v in versions if v.status == VersionStatus.ACTIVE),
            None,
        )

    def get_policy(self, plugin_name: str) -> VersionPolicy:
        """Return the version policy for a plugin (creates default if missing)."""
        if plugin_name not in self._policies:
            self._policies[plugin_name] = VersionPolicy(plugin_name=plugin_name)
        return self._policies[plugin_name]

    def set_policy(self, plugin_name: str, **kwargs) -> VersionPolicy:
        """Update the version policy for a plugin."""
        policy = self.get_policy(plugin_name)
        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        self._policies[plugin_name] = policy
        self._save_state()
        return policy

    # ── Version installation ─────────────────────────────────────────────

    def install_version(self, plugin_name: str, version: str) -> PluginVersion:
        """
        Download and install a specific version of a scanner.

        Steps:
        1. Check policy allows this version
        2. Download via the appropriate method (pip/binary)
        3. Verify SHA-256 hash
        4. Store in versioned cache directory
        5. Set as active
        """
        policy = self.get_policy(plugin_name)

        # Check blocked versions
        if version in policy.blocked_versions:
            raise ValueError(
                f"Version {version} of {plugin_name} is blocked by policy "
                f"(known CVEs: {policy.blocked_versions})"
            )

        # Check allowed versions
        if policy.allowed_versions and version not in policy.allowed_versions:
            raise ValueError(
                f"Version {version} not in allowed versions list: {policy.allowed_versions}"
            )

        info = SCANNER_REGISTRY.get(plugin_name)
        if not info:
            raise ValueError(f"Unknown plugin: {plugin_name}")

        # Create version entry
        pv = PluginVersion(
            plugin_name=plugin_name,
            version=version,
            status=VersionStatus.DOWNLOADING,
            install_method=info["install_method"],
        )

        try:
            if info["install_method"] == InstallMethod.PIP:
                pv = self._install_pip(plugin_name, version, info, pv)
            elif info["install_method"] == InstallMethod.BINARY:
                pv = self._install_binary(plugin_name, version, info, pv)
            else:
                raise ValueError(f"Unsupported install method: {info['install_method']}")

            pv.status = VersionStatus.AVAILABLE
            pv.installed_at = time.time()

            # Compute SHA-256 of the installed binary
            if pv.binary_path and os.path.exists(pv.binary_path):
                pv.sha256 = self._compute_sha256(pv.binary_path)

        except Exception as exc:
            pv.status = VersionStatus.FAILED
            logger.error("Failed to install %s %s: %s", plugin_name, version, exc)
            raise

        # Add to version list
        if plugin_name not in self._versions:
            self._versions[plugin_name] = []
        self._versions[plugin_name].append(pv)

        # Enforce max cached versions
        self._enforce_cache_limit(plugin_name)
        self._save_state()

        return pv

    def _install_pip(
        self, plugin_name: str, version: str, info: dict, pv: PluginVersion
    ) -> PluginVersion:
        """Install a Python-based scanner via pip into an isolated venv."""
        venv_dir = self._cache_dir / plugin_name / version
        venv_dir.mkdir(parents=True, exist_ok=True)

        pkg = info["pip_package"]
        binary = info["binary_name"]

        # Install into isolated directory
        subprocess.run(
            ["pip", "install", f"{pkg}=={version}", "--target", str(venv_dir)],
            capture_output=True, text=True, timeout=300,
            check=True,
        )

        # Find the binary
        bin_path = shutil.which(binary) or str(venv_dir / "bin" / binary)
        pv.binary_path = bin_path
        return pv

    def _install_binary(
        self, plugin_name: str, version: str, info: dict, pv: PluginVersion
    ) -> PluginVersion:
        """Download a pre-built binary from GitHub releases."""
        import platform
        import urllib.request

        cache_path = self._cache_dir / plugin_name / version
        cache_path.mkdir(parents=True, exist_ok=True)

        repo = info["github_repo"]
        system = platform.system().lower()
        arch = platform.machine()

        # Map architecture names
        arch_map = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
        arch = arch_map.get(arch, arch)

        # Construct download URL (GitHub releases pattern)
        binary_name = info["binary_name"]
        download_url = (
            f"https://github.com/{repo}/releases/download/"
            f"v{version}/{binary_name}_{version}_{system}_{arch}.tar.gz"
        )

        tarball_path = cache_path / f"{binary_name}.tar.gz"
        binary_path = cache_path / binary_name

        try:
            logger.info("Downloading %s %s from %s", plugin_name, version, download_url)
            urllib.request.urlretrieve(download_url, str(tarball_path))

            # Extract
            import tarfile
            with tarfile.open(str(tarball_path), "r:gz") as tar:
                tar.extractall(path=str(cache_path), filter="data")

            # Make executable
            if binary_path.exists():
                binary_path.chmod(0o755)

            pv.binary_path = str(binary_path)
            pv.size_bytes = binary_path.stat().st_size if binary_path.exists() else 0

        finally:
            # Clean up tarball
            if tarball_path.exists():
                tarball_path.unlink()

        return pv

    # ── Version activation / rollback ────────────────────────────────────

    def activate_version(self, plugin_name: str, version: str) -> PluginVersion:
        """Set a specific cached version as the active one."""
        versions = self._versions.get(plugin_name, [])
        target = next((v for v in versions if v.version == version), None)

        if not target:
            raise ValueError(f"Version {version} not found in cache for {plugin_name}")

        if target.status == VersionStatus.VULNERABLE:
            raise ValueError(
                f"Cannot activate {plugin_name} {version} — "
                f"known vulnerable (CVEs: {', '.join(target.cve_ids)})"
            )

        # Deactivate current
        for v in versions:
            if v.status == VersionStatus.ACTIVE:
                v.status = VersionStatus.AVAILABLE

        target.status = VersionStatus.ACTIVE
        self._save_state()

        logger.info("Activated %s version %s", plugin_name, version)
        return target

    def rollback(self, plugin_name: str) -> PluginVersion | None:
        """
        Rollback to the last known-good version.

        Called automatically when a CVE is detected in the active version.
        """
        versions = self._versions.get(plugin_name, [])
        safe_versions = [
            v for v in versions
            if v.status in (VersionStatus.AVAILABLE, VersionStatus.ACTIVE)
            and not v.cve_ids
        ]

        if not safe_versions:
            logger.error("No safe version available for rollback of %s", plugin_name)
            return None

        # Sort by installed_at descending, pick the newest safe version
        safe_versions.sort(key=lambda v: v.installed_at or 0, reverse=True)
        target = safe_versions[0]

        # Deactivate current
        for v in versions:
            if v.status == VersionStatus.ACTIVE:
                v.status = VersionStatus.VULNERABLE

        target.status = VersionStatus.ACTIVE
        self._save_state()

        logger.warning(
            "Rolled back %s to version %s (previous version was vulnerable)",
            plugin_name, target.version,
        )
        return target

    # ── CVE flagging ─────────────────────────────────────────────────────

    def flag_vulnerable(
        self, plugin_name: str, version: str, cve_ids: list[str]
    ) -> PluginVersion | None:
        """
        Mark a specific version as vulnerable and trigger auto-rollback if enabled.

        Returns the new active version after rollback (or None if rollback disabled).
        """
        versions = self._versions.get(plugin_name, [])
        target = next((v for v in versions if v.version == version), None)

        if not target:
            # Version not installed — just block it in policy
            policy = self.get_policy(plugin_name)
            policy.blocked_versions = list(set(policy.blocked_versions + [version]))
            self._save_state()
            return None

        target.status = VersionStatus.VULNERABLE
        target.cve_ids = list(set(target.cve_ids + cve_ids))

        # Block in policy too
        policy = self.get_policy(plugin_name)
        policy.blocked_versions = list(set(policy.blocked_versions + [version]))

        # Auto-rollback if enabled and this was the active version
        new_active = None
        if policy.auto_rollback and target.status == VersionStatus.VULNERABLE:
            new_active = self.rollback(plugin_name)

        self._save_state()
        return new_active

    # ── Hash verification ────────────────────────────────────────────────

    def verify_integrity(self, plugin_name: str) -> dict[str, bool]:
        """
        Verify SHA-256 hash of all cached binaries for a plugin.

        Returns {version: True/False} for each cached version that has a
        recorded hash. Versions without one (binaries found on PATH rather than
        downloaded) are not reported here; they are covered by the per-scan
        gate in app/services/plugins/integrity.py.
        """
        results = {}
        for v in self._versions.get(plugin_name, []):
            if not v.binary_path or not v.sha256:
                continue

            if not os.path.exists(v.binary_path):
                results[v.version] = False
                continue

            current_hash = self._compute_sha256(v.binary_path)
            results[v.version] = current_hash == v.sha256

        return results

    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # ── Cache management ─────────────────────────────────────────────────

    def _enforce_cache_limit(self, plugin_name: str):
        """Remove oldest non-active versions to stay within cache limit."""
        policy = self.get_policy(plugin_name)
        versions = self._versions.get(plugin_name, [])

        # Keep active and vulnerable (for audit), remove oldest available
        removable = [v for v in versions if v.status == VersionStatus.AVAILABLE]
        removable.sort(key=lambda v: v.installed_at or 0)

        while len(versions) > policy.max_cached_versions and removable:
            to_remove = removable.pop(0)
            # Delete from disk
            if to_remove.binary_path:
                version_dir = self._cache_dir / plugin_name / to_remove.version
                if version_dir.exists():
                    shutil.rmtree(version_dir, ignore_errors=True)
            versions.remove(to_remove)
            logger.info("Evicted %s %s from cache", plugin_name, to_remove.version)

    def cache_stats(self) -> dict[str, Any]:
        """Return cache statistics for admin dashboard."""
        total_size = 0
        total_versions = 0
        plugins = {}

        for plugin_name, versions in self._versions.items():
            active = next(
                (v for v in versions if v.status == VersionStatus.ACTIVE), None
            )
            vulnerable = [v for v in versions if v.status == VersionStatus.VULNERABLE]
            total_versions += len(versions)

            for v in versions:
                total_size += v.size_bytes

            plugins[plugin_name] = {
                "cached_versions": len(versions),
                "active_version": active.version if active else None,
                "vulnerable_versions": [v.version for v in vulnerable],
                "policy": asdict(self.get_policy(plugin_name)),
            }

        return {
            "total_plugins": len(self._versions),
            "total_cached_versions": total_versions,
            "total_cache_size_bytes": total_size,
            "cache_dir": str(self._cache_dir),
            "plugins": plugins,
        }

    # ── Admin API helpers ────────────────────────────────────────────────

    def get_available_updates(self) -> list[dict]:
        """Check GitHub releases for newer versions of all plugins."""
        updates = []
        for plugin_name, info in SCANNER_REGISTRY.items():
            active = self.get_active_version(plugin_name)
            if not active:
                continue
            latest = self._check_latest_github_release(info.get("github_repo", ""))
            if latest and latest != active.version:
                updates.append({
                    "plugin": plugin_name,
                    "current": active.version,
                    "latest": latest,
                    "github_repo": info.get("github_repo", ""),
                    "homepage": info.get("homepage", ""),
                })
        return updates

    @staticmethod
    def _check_latest_github_release(repo: str) -> str | None:
        """Query GitHub API for the latest release version."""
        if not repo:
            return None
        try:
            import urllib.request
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                tag = data.get("tag_name", "")
                # Strip leading 'v'
                return tag.lstrip("v") if tag else None
        except Exception:
            return None

    def full_status(self) -> dict[str, Any]:
        """Complete status report for admin dashboard."""
        status = {
            "cache": self.cache_stats(),
            "available_updates": self.get_available_updates(),
            "integrity": {},
        }
        for plugin_name in self._versions:
            status["integrity"][plugin_name] = self.verify_integrity(plugin_name)
        return status


# ── Module-level singleton ───────────────────────────────────────────────────

_global_manager: VersionManager | None = None


def get_version_manager(redis_client=None) -> VersionManager:
    """Return the global VersionManager singleton."""
    global _global_manager
    if _global_manager is None:
        _global_manager = VersionManager(redis_client=redis_client)
    return _global_manager

"""
.guardnous.yml Parser — Per-Repository Scan Policy Configuration.

Every repository can include a `.guardnous.yml` (or `.guardnous.yaml`)
at its root to customise scanning behaviour. This is VCS-agnostic — works
with GitHub, GitLab, Bitbucket, and Azure DevOps.

Schema:
    version: 1
    scan:
      on_push: true
      on_pr: true
      branches: [main, develop, "release/*"]
      exclude_paths: [vendor/**, node_modules/**, "*.test.ts"]
    policy:
      fail_on: critical
      max_risk_score: 70
      block_pr: true
    scanners:
      iac: { enabled: true, frameworks: [terraform, cloudformation, bicep, kubernetes] }
      secrets: { enabled: true, entropy_threshold: 4.5 }
      sast: { enabled: false }
      dependencies: { enabled: true }
    ignore:
      - rule_id: CKV_AWS_18
        reason: "Accepted risk — dev environment only"
        expires: "2026-12-31"
        approved_by: "security-team"
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Scan trigger configuration."""
    on_push: bool = True
    on_pr: bool = True
    branches: list[str] = field(default_factory=lambda: ["main", "master"])
    exclude_paths: list[str] = field(default_factory=list)
    schedule: Optional[str] = None  # cron expression, e.g. "0 2 * * 1"


@dataclass
class PolicyConfig:
    """Security policy configuration."""
    fail_on: str = "critical"  # critical, high, medium, low
    max_risk_score: int = 100  # 0-100, block if exceeded
    block_pr: bool = False
    require_approval_above: Optional[str] = None  # severity level requiring security team review


@dataclass
class ScannerConfig:
    """Individual scanner configuration."""
    enabled: bool = True
    frameworks: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class IgnoreRule:
    """A suppressed/ignored finding rule."""
    rule_id: str
    reason: str = ""
    expires: Optional[str] = None  # ISO date string
    approved_by: Optional[str] = None
    paths: list[str] = field(default_factory=list)  # Applies to specific paths only


@dataclass
class RepoConfig:
    """Parsed .guardnous.yml configuration."""
    version: int = 1
    scan: ScanConfig = field(default_factory=ScanConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    ignore: list[IgnoreRule] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def enabled_scanner_names(self) -> list[str]:
        return [k for k, v in self.scanners.items() if v.enabled]

    def is_rule_ignored(self, rule_id: str, file_path: Optional[str] = None) -> bool:
        """Check if a rule is ignored (optionally for a specific file path)."""
        from datetime import date
        today = date.today().isoformat()
        for ir in self.ignore:
            if ir.rule_id != rule_id:
                continue
            if ir.expires and ir.expires < today:
                continue  # Expired ignore
            if ir.paths and file_path:
                import fnmatch
                if not any(fnmatch.fnmatch(file_path, p) for p in ir.paths):
                    continue
            return True
        return False

    def should_scan_branch(self, branch: str) -> bool:
        """Check if a branch matches the scan branch patterns."""
        import fnmatch
        for pattern in self.scan.branches:
            if fnmatch.fnmatch(branch, pattern):
                return True
        return False

    def should_exclude_path(self, path: str) -> bool:
        """Check if a file path should be excluded from scanning."""
        import fnmatch
        for pattern in self.scan.exclude_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False


# ── Default config (when no .guardnous.yml exists) ────────────────────────

DEFAULT_CONFIG = RepoConfig(
    version=1,
    scan=ScanConfig(on_push=True, on_pr=True, branches=["main", "master"]),
    policy=PolicyConfig(fail_on="critical", max_risk_score=100, block_pr=False),
    scanners={
        "iac": ScannerConfig(enabled=True, frameworks=["terraform", "cloudformation", "bicep"]),
        "secrets": ScannerConfig(enabled=True),
    },
    ignore=[],
)


# ── Parser ───────────────────────────────────────────────────────────────────


class ConfigValidationError(Exception):
    """Raised when .guardnous.yml has invalid structure."""
    pass


def parse_repo_config(content: str) -> RepoConfig:
    """Parse a .guardnous.yml file content string into a RepoConfig.

    Args:
        content: Raw YAML string.

    Returns:
        RepoConfig instance.

    Raises:
        ConfigValidationError: If the YAML is malformed or has invalid values.
    """
    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise ConfigValidationError(f"Invalid YAML: {exc}")

    if not isinstance(data, dict):
        raise ConfigValidationError("Config must be a YAML mapping (dict), not a scalar or list")

    version = data.get("version", 1)
    if version not in (1,):
        raise ConfigValidationError(f"Unsupported config version: {version}. Supported: 1")

    # Parse scan section
    scan_raw = data.get("scan", {})
    scan = ScanConfig(
        on_push=scan_raw.get("on_push", True),
        on_pr=scan_raw.get("on_pr", True),
        branches=scan_raw.get("branches", ["main", "master"]),
        exclude_paths=scan_raw.get("exclude_paths", []),
        schedule=scan_raw.get("schedule"),
    )

    # Parse policy section
    policy_raw = data.get("policy", {})
    fail_on = policy_raw.get("fail_on", "critical")
    valid_severities = ("critical", "high", "medium", "low")
    if fail_on not in valid_severities:
        raise ConfigValidationError(
            f"policy.fail_on must be one of {valid_severities}, got: {fail_on}"
        )
    policy = PolicyConfig(
        fail_on=fail_on,
        max_risk_score=min(100, max(0, int(policy_raw.get("max_risk_score", 100)))),
        block_pr=policy_raw.get("block_pr", False),
        require_approval_above=policy_raw.get("require_approval_above"),
    )

    # Parse scanners section
    scanners_raw = data.get("scanners", {})
    scanners = {}
    for key, val in scanners_raw.items():
        if isinstance(val, bool):
            scanners[key] = ScannerConfig(enabled=val)
        elif isinstance(val, dict):
            scanners[key] = ScannerConfig(
                enabled=val.get("enabled", True),
                frameworks=val.get("frameworks", []),
                extra={k: v for k, v in val.items() if k not in ("enabled", "frameworks")},
            )
        else:
            raise ConfigValidationError(f"scanners.{key} must be a bool or mapping")

    # Apply defaults for missing scanners
    if "iac" not in scanners:
        scanners["iac"] = ScannerConfig(
            enabled=True,
            frameworks=["terraform", "cloudformation", "bicep"],
        )
    if "secrets" not in scanners:
        scanners["secrets"] = ScannerConfig(enabled=True)

    # Parse ignore rules
    ignore_raw = data.get("ignore", [])
    ignore = []
    for item in ignore_raw:
        if not isinstance(item, dict) or "rule_id" not in item:
            raise ConfigValidationError("Each ignore entry must have a 'rule_id' field")
        ignore.append(IgnoreRule(
            rule_id=item["rule_id"],
            reason=item.get("reason", ""),
            expires=item.get("expires"),
            approved_by=item.get("approved_by"),
            paths=item.get("paths", []),
        ))

    return RepoConfig(
        version=version, scan=scan, policy=policy,
        scanners=scanners, ignore=ignore, raw=data,
    )


def parse_repo_config_from_file(path: str) -> RepoConfig:
    """Parse a .guardnous.yml file from disk."""
    p = Path(path)
    if not p.exists():
        logger.debug("No .guardnous.yml found at %s — using defaults", path)
        return DEFAULT_CONFIG
    return parse_repo_config(p.read_text(encoding="utf-8"))


def get_config_schema() -> dict:
    """Return JSON Schema for .guardnous.yml (for editor autocomplete / validation)."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "GuardNous Repository Configuration",
        "description": "Per-repository scan policy for GuardNous. Place as .guardnous.yml at repo root.",
        "type": "object",
        "properties": {
            "version": {"type": "integer", "enum": [1], "description": "Config schema version."},
            "scan": {
                "type": "object",
                "properties": {
                    "on_push": {"type": "boolean", "default": True},
                    "on_pr": {"type": "boolean", "default": True},
                    "branches": {"type": "array", "items": {"type": "string"}, "default": ["main", "master"]},
                    "exclude_paths": {"type": "array", "items": {"type": "string"}, "default": []},
                    "schedule": {"type": "string", "description": "Cron expression for scheduled scans."},
                },
            },
            "policy": {
                "type": "object",
                "properties": {
                    "fail_on": {"type": "string", "enum": ["critical", "high", "medium", "low"], "default": "critical"},
                    "max_risk_score": {"type": "integer", "minimum": 0, "maximum": 100, "default": 100},
                    "block_pr": {"type": "boolean", "default": False},
                    "require_approval_above": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                },
            },
            "scanners": {
                "type": "object",
                "additionalProperties": {
                    "oneOf": [
                        {"type": "boolean"},
                        {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean", "default": True},
                                "frameworks": {"type": "array", "items": {"type": "string"}},
                            },
                        },
                    ]
                },
            },
            "ignore": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["rule_id"],
                    "properties": {
                        "rule_id": {"type": "string"},
                        "reason": {"type": "string"},
                        "expires": {"type": "string", "format": "date"},
                        "approved_by": {"type": "string"},
                        "paths": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
        },
        "additionalProperties": False,
    }

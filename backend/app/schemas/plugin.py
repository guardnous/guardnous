"""Pydantic schemas for Plugin API responses."""

from __future__ import annotations

from pydantic import BaseModel


class PluginHealthResponse(BaseModel):
    available: bool
    version: str | None = None
    message: str | None = None
    latency_ms: float | None = None


class PluginMetadataResponse(BaseModel):
    name: str
    display_name: str
    version: str
    description: str
    homepage: str
    icon: str
    capabilities: list[str]
    is_native: bool = False
    plugin_type: str = "external"
    requires_binary: bool = False
    default_config: dict = {}
    severity_levels: list[str] = []
    total_rules: int = 0


class PluginListItem(BaseModel):
    name: str
    display_name: str
    description: str
    icon: str
    capabilities: list[str]
    is_native: bool = False
    plugin_type: str = "external"
    enabled: bool = True
    health: PluginHealthResponse
    severity_levels: list[str] = []
    total_rules: int = 0


class PluginDetailResponse(BaseModel):
    metadata: PluginMetadataResponse
    health: PluginHealthResponse
    enabled: bool = True
    plugin_type: str = "external"
    severity_levels: list[str] = []
    total_rules: int = 0


class PluginToggleRequest(BaseModel):
    enabled: bool


class PluginToggleResponse(BaseModel):
    name: str
    enabled: bool
    message: str


class PluginsListResponse(BaseModel):
    plugins: list[PluginListItem]
    total: int
    enabled_count: int
    native_count: int
    external_count: int


# ── Version Management Schemas ──────────────────────────────────────────────


class PluginVersionResponse(BaseModel):
    plugin_name: str
    version: str
    status: str  # active, available, vulnerable, downloading, failed
    install_method: str
    sha256: str | None = None
    binary_path: str | None = None
    installed_at: float | None = None
    cve_ids: list[str] = []
    release_date: str | None = None
    size_bytes: int = 0


class PluginVersionListResponse(BaseModel):
    plugin_name: str
    versions: list[PluginVersionResponse]
    active_version: str | None = None
    total: int


class PluginVersionPolicyResponse(BaseModel):
    plugin_name: str
    pinned_version: str | None = None
    auto_update: bool = True
    auto_rollback: bool = True
    max_cached_versions: int = 3
    allowed_versions: list[str] | None = None
    blocked_versions: list[str] = []


class PluginVersionPolicyUpdate(BaseModel):
    pinned_version: str | None = None
    auto_update: bool | None = None
    auto_rollback: bool | None = None
    max_cached_versions: int | None = None


class PluginInstallRequest(BaseModel):
    version: str


class PluginActivateRequest(BaseModel):
    version: str


class PluginCacheStatsResponse(BaseModel):
    total_plugins: int
    total_cached_versions: int
    total_cache_size_bytes: int
    cache_dir: str
    plugins: dict


class SupplyChainAlertResponse(BaseModel):
    alert_id: str
    severity: str
    plugin_name: str
    alert_type: str
    title: str
    description: str
    cve_ids: list[str] = []
    affected_version: str | None = None
    fixed_version: str | None = None
    auto_remediated: bool = False
    remediation_action: str | None = None
    timestamp: float


class SupplyChainReportResponse(BaseModel):
    timestamp: float
    duration_ms: float
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    alerts: list[SupplyChainAlertResponse]
    plugins_checked: list[str]
    auto_remediations: int

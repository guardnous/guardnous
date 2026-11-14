"""
Plugin management API — list, inspect, enable/disable, health-check plugins.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.org_settings import OrgSettings
from app.models.user import User
from app.services.plugins.registry import get_registry
from app.schemas.plugin import (
    PluginDetailResponse,
    PluginHealthResponse,
    PluginListItem,
    PluginMetadataResponse,
    PluginsListResponse,
    PluginToggleRequest,
    PluginToggleResponse,
    PluginVersionResponse,
    PluginVersionListResponse,
    PluginVersionPolicyResponse,
    PluginVersionPolicyUpdate,
    PluginInstallRequest,
    PluginActivateRequest,
    PluginCacheStatsResponse,
    SupplyChainReportResponse,
)

router = APIRouter()


async def _get_or_create_settings(db: AsyncSession, org_id: int) -> OrgSettings:
    """Fetch (or lazily create) the OrgSettings row for an organization."""
    result = await db.execute(
        select(OrgSettings).where(OrgSettings.organization_id == org_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = OrgSettings(organization_id=org_id, notification_prefs={}, plugin_settings={})
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


async def _apply_persisted_state(db: AsyncSession, org_id: int, registry) -> None:
    """Load the org's persisted plugin enabled-map and apply it to the registry.

    The registry is a process-global singleton whose in-memory enabled-map is
    reset on every restart, so we re-hydrate it from the DB before each read.
    """
    row = await _get_or_create_settings(db, org_id)
    persisted = row.plugin_settings or {}
    if persisted:
        registry.set_enabled_map(persisted)

# Rule count estimates per plugin (based on built-in rule sets)
PLUGIN_RULE_COUNTS = {
    "native_terraform": 25,
    "native_cloudformation": 25,
    "native_bicep": 25,
    "native_secrets": 18,
    "checkov": 1000,
    "trivy": 500,
    "gitleaks": 150,
    "semgrep": 2000,
    "tfsec": 350,
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


@router.get("", response_model=PluginsListResponse)
async def list_plugins(
    current_user: User = Depends(require_permission("settings", "read")),
    db: AsyncSession = Depends(get_db),
):
    """List all registered plugins with their current health and status."""
    registry = get_registry()
    await _apply_persisted_state(db, current_user.organization_id, registry)
    all_plugins = registry.list_all()
    enabled_names = set(registry.list_enabled().keys())

    items: list[PluginListItem] = []
    native_count = 0
    external_count = 0

    for name, adapter in all_plugins.items():
        meta = adapter.metadata()
        health = adapter.health()
        is_enabled = name in enabled_names
        plugin_type = "native" if meta.is_native else "external"

        if meta.is_native:
            native_count += 1
        else:
            external_count += 1

        items.append(
            PluginListItem(
                name=meta.name,
                display_name=meta.display_name,
                description=meta.description,
                icon=meta.icon,
                capabilities=[c.value for c in meta.capabilities],
                is_native=meta.is_native,
                plugin_type=plugin_type,
                enabled=is_enabled,
                health=PluginHealthResponse(
                    available=health.available,
                    version=health.version,
                    message=health.message,
                    latency_ms=health.latency_ms,
                ),
                severity_levels=SEVERITY_LEVELS,
                total_rules=PLUGIN_RULE_COUNTS.get(meta.name, 50),
            )
        )

    return PluginsListResponse(
        plugins=items,
        total=len(items),
        enabled_count=len(enabled_names),
        native_count=native_count,
        external_count=external_count,
    )


# ── Supply Chain (MUST be before /{plugin_name} wildcard) ─────────────────────


@router.get("/supply-chain/health", response_model=SupplyChainReportResponse)
async def get_supply_chain_health(
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Run a full supply-chain health check across all scanner plugins."""
    from app.services.plugins.health_monitor import PluginHealthMonitor

    monitor = PluginHealthMonitor()
    report = monitor.run_full_check()
    return SupplyChainReportResponse(**report)


@router.get("/supply-chain/cache", response_model=PluginCacheStatsResponse)
async def get_cache_stats(
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Get scanner binary cache statistics."""
    from app.services.plugins.version_manager import get_version_manager

    vm = get_version_manager()
    stats = vm.cache_stats()
    return PluginCacheStatsResponse(**stats)


@router.get("/load-errors")
async def get_plugin_load_errors(
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Adapter files in the adapters directory that could not be loaded at startup.

    Empty in a healthy installation. Each item names the module, the class when
    known, and the error; the same text is in the server log.
    """
    from app.services.plugins.registry import get_load_errors

    errors = get_load_errors()
    return {"load_errors": errors, "total": len(errors)}


@router.get("/integrity")
async def get_plugin_integrity(
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Pinned-hash status of every external scanner binary.

    Read-only: a binary that has never been run is reported but not pinned here.
    """
    from app.core.config import settings
    from app.services.plugins.integrity import PluginIntegrityError, get_integrity

    integrity = get_integrity()
    items = []
    for name, adapter in get_registry().list_all().items():
        binary = getattr(adapter, "_binary", None)
        if not binary or not adapter.metadata().requires_binary:
            continue
        try:
            status = integrity.check(binary, pin_if_new=False).to_dict()
        except PluginIntegrityError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        if status["status"] == "pinned":
            status["status"] = "not_pinned_yet"
        items.append({"plugin": name, **status})
    return {"mode": settings.PLUGIN_INTEGRITY_MODE, "items": items}


@router.post("/{plugin_name}/integrity/approve")
async def approve_plugin_binary(
    plugin_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "manage")),
):
    """Accept the scanner binary as it is now (after a deliberate upgrade).

    Scanner binaries are shared by the whole installation, so only an
    installation superuser may approve one.
    """
    from app.core.audit import write_audit_log
    from app.core.rbac import is_superuser
    from app.services.plugins.integrity import get_integrity

    if not is_superuser(current_user):
        raise HTTPException(status_code=403, detail="Only an installation administrator can approve a scanner binary")
    adapter = get_registry().get(plugin_name)
    binary = getattr(adapter, "_binary", None) if adapter else None
    if not binary or not adapter.metadata().requires_binary:
        raise HTTPException(status_code=404, detail="Not an external scanner plugin")
    integrity = get_integrity()
    before = integrity.check(binary, pin_if_new=False)
    try:
        after = integrity.approve(binary, approved_by=current_user.email)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"{binary} is not installed on the server")
    await write_audit_log(
        db, action="approve", resource_type="plugin_binary", user=current_user,
        details={"plugin": plugin_name, "path": after.path,
                 "previous_sha256": before.expected_sha256, "sha256": after.sha256},
    )
    return {"plugin": plugin_name, **after.to_dict()}


# ── Per-Plugin Endpoints ──────────────────────────────────────────────────────


@router.get("/{plugin_name}", response_model=PluginDetailResponse)
async def get_plugin(
    plugin_name: str,
    current_user: User = Depends(require_permission("settings", "read")),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed info about a single plugin."""
    registry = get_registry()
    await _apply_persisted_state(db, current_user.organization_id, registry)
    all_plugins = registry.list_all()
    adapter = all_plugins.get(plugin_name)

    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")

    meta = adapter.metadata()
    health = adapter.health()
    is_enabled = plugin_name in registry.list_enabled()
    plugin_type = "native" if meta.is_native else "external"

    return PluginDetailResponse(
        metadata=PluginMetadataResponse(
            name=meta.name,
            display_name=meta.display_name,
            version=meta.version,
            description=meta.description,
            homepage=meta.homepage,
            icon=meta.icon,
            capabilities=[c.value for c in meta.capabilities],
            is_native=meta.is_native,
            plugin_type=plugin_type,
            requires_binary=meta.requires_binary,
            default_config=meta.default_config,
            severity_levels=SEVERITY_LEVELS,
            total_rules=PLUGIN_RULE_COUNTS.get(meta.name, 50),
        ),
        health=PluginHealthResponse(
            available=health.available,
            version=health.version,
            message=health.message,
            latency_ms=health.latency_ms,
        ),
        enabled=is_enabled,
        plugin_type=plugin_type,
        severity_levels=SEVERITY_LEVELS,
        total_rules=PLUGIN_RULE_COUNTS.get(meta.name, 50),
    )


@router.get("/{plugin_name}/health", response_model=PluginHealthResponse)
async def check_plugin_health(plugin_name: str, current_user: User = Depends(require_permission("settings", "read"))):
    """Health-check a specific plugin."""
    registry = get_registry()
    adapter = registry.list_all().get(plugin_name)

    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")

    health = adapter.health()
    return PluginHealthResponse(
        available=health.available,
        version=health.version,
        message=health.message,
        latency_ms=health.latency_ms,
    )


@router.post("/{plugin_name}/toggle", response_model=PluginToggleResponse)
async def toggle_plugin(
    plugin_name: str,
    body: PluginToggleRequest,
    current_user: User = Depends(require_permission("settings", "manage")),
    db: AsyncSession = Depends(get_db),
):
    """Enable or disable a plugin (persisted to the org's settings)."""
    registry = get_registry()
    all_plugins = registry.list_all()

    if plugin_name not in all_plugins:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")

    if body.enabled:
        registry.enable(plugin_name)
        msg = f"Plugin '{plugin_name}' enabled"
    else:
        registry.disable(plugin_name)
        msg = f"Plugin '{plugin_name}' disabled"

    # Persist to DB so the toggle survives API restarts.
    settings = await _get_or_create_settings(db, current_user.organization_id)
    persisted = dict(settings.plugin_settings or {})
    persisted[plugin_name] = body.enabled
    settings.plugin_settings = persisted
    # Reassign so SQLAlchemy detects the JSON mutation.
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(settings, "plugin_settings")
    await db.commit()

    return PluginToggleResponse(name=plugin_name, enabled=body.enabled, message=msg)


# ── Version Management Endpoints ──────────────────────────────────────────────


@router.get("/{plugin_name}/versions", response_model=PluginVersionListResponse)
async def list_plugin_versions(
    plugin_name: str,
    current_user: User = Depends(require_permission("settings", "read")),
):
    """List all cached versions for a plugin."""
    from app.services.plugins.version_manager import get_version_manager

    vm = get_version_manager()
    versions = vm.get_installed_versions(plugin_name)
    active = vm.get_active_version(plugin_name)

    return PluginVersionListResponse(
        plugin_name=plugin_name,
        versions=[
            PluginVersionResponse(
                plugin_name=v.plugin_name,
                version=v.version,
                status=v.status.value if hasattr(v.status, "value") else v.status,
                install_method=v.install_method.value if hasattr(v.install_method, "value") else v.install_method,
                sha256=v.sha256,
                binary_path=v.binary_path,
                installed_at=v.installed_at,
                cve_ids=v.cve_ids,
                release_date=v.release_date,
                size_bytes=v.size_bytes,
            )
            for v in versions
        ],
        active_version=active.version if active else None,
        total=len(versions),
    )


@router.post("/{plugin_name}/versions/install")
async def install_plugin_version(
    plugin_name: str,
    body: PluginInstallRequest,
    current_user: User = Depends(require_permission("settings", "manage")),
):
    """Download and install a specific version of a plugin."""
    from app.services.plugins.version_manager import get_version_manager

    vm = get_version_manager()
    try:
        pv = vm.install_version(plugin_name, body.version)
        return {
            "status": "success",
            "message": f"Installed {plugin_name} {body.version}",
            "version": PluginVersionResponse(
                plugin_name=pv.plugin_name,
                version=pv.version,
                status=pv.status.value if hasattr(pv.status, "value") else pv.status,
                install_method=pv.install_method.value if hasattr(pv.install_method, "value") else pv.install_method,
                sha256=pv.sha256,
                binary_path=pv.binary_path,
                installed_at=pv.installed_at,
                cve_ids=pv.cve_ids,
                size_bytes=pv.size_bytes,
            ).model_dump(),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Installation failed: {exc}")


@router.post("/{plugin_name}/versions/activate")
async def activate_plugin_version(
    plugin_name: str,
    body: PluginActivateRequest,
    current_user: User = Depends(require_permission("settings", "manage")),
):
    """Activate a specific cached version."""
    from app.services.plugins.version_manager import get_version_manager

    vm = get_version_manager()
    try:
        pv = vm.activate_version(plugin_name, body.version)
        return {
            "status": "success",
            "message": f"Activated {plugin_name} {body.version}",
            "active_version": pv.version,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{plugin_name}/versions/rollback")
async def rollback_plugin_version(
    plugin_name: str,
    current_user: User = Depends(require_permission("settings", "manage")),
):
    """Rollback to the last known-good version."""
    from app.services.plugins.version_manager import get_version_manager

    vm = get_version_manager()
    new_active = vm.rollback(plugin_name)
    if new_active:
        return {
            "status": "success",
            "message": f"Rolled back {plugin_name} to {new_active.version}",
            "active_version": new_active.version,
        }
    else:
        raise HTTPException(
            status_code=400,
            detail=f"No safe version available for rollback of {plugin_name}",
        )


@router.get("/{plugin_name}/versions/policy", response_model=PluginVersionPolicyResponse)
async def get_version_policy(
    plugin_name: str,
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Get the version policy for a plugin."""
    from app.services.plugins.version_manager import get_version_manager

    vm = get_version_manager()
    policy = vm.get_policy(plugin_name)
    return PluginVersionPolicyResponse(
        plugin_name=policy.plugin_name,
        pinned_version=policy.pinned_version,
        auto_update=policy.auto_update,
        auto_rollback=policy.auto_rollback,
        max_cached_versions=policy.max_cached_versions,
        allowed_versions=policy.allowed_versions,
        blocked_versions=policy.blocked_versions,
    )


@router.put("/{plugin_name}/versions/policy", response_model=PluginVersionPolicyResponse)
async def update_version_policy(
    plugin_name: str,
    body: PluginVersionPolicyUpdate,
    current_user: User = Depends(require_permission("settings", "manage")),
):
    """Update the version policy for a plugin."""
    from app.services.plugins.version_manager import get_version_manager

    vm = get_version_manager()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    policy = vm.set_policy(plugin_name, **updates)
    return PluginVersionPolicyResponse(
        plugin_name=policy.plugin_name,
        pinned_version=policy.pinned_version,
        auto_update=policy.auto_update,
        auto_rollback=policy.auto_rollback,
        max_cached_versions=policy.max_cached_versions,
        allowed_versions=policy.allowed_versions,
        blocked_versions=policy.blocked_versions,
    )



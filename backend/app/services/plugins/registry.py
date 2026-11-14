"""
Plugin Registry — singleton that holds all registered scanner adapters.

Adapters are discovered on first use: every module in
``app.services.plugins.adapters`` is imported and each concrete ``PluginAdapter``
subclass defined in it is registered (see ``discover_adapters``). The
ScanOrchestrator queries the registry to find which plugins are available and
healthy.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from typing import Optional

from app.services.plugins.base import PluginAdapter, PluginHealth, PluginMetadata

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Thread-safe registry of all scanner plugins.

    Usage::

        registry = PluginRegistry()
        registry.register(CheckovAdapter())
        for meta in registry.list_plugins():
            print(meta.name, meta.display_name)
    """

    def __init__(self) -> None:
        self._plugins: dict[str, PluginAdapter] = {}
        self._enabled: dict[str, bool] = {}

    # ── Registration ──────────────────────────────────────────────────────

    def register(self, adapter: PluginAdapter) -> None:
        """Register (or re-register) an adapter under its metadata name."""
        meta = adapter.metadata()
        slug = meta.name
        if slug in self._plugins:
            logger.debug("Plugin '%s' re-registered (replaced)", slug)
        self._plugins[slug] = adapter
        # Default to enabled
        self._enabled.setdefault(slug, True)
        logger.info("Plugin registered: %s (%s)", meta.display_name, slug)

    def unregister(self, name: str) -> None:
        """Remove a plugin by slug."""
        self._plugins.pop(name, None)
        self._enabled.pop(name, None)

    # ── Enable / disable ──────────────────────────────────────────────────

    def enable(self, name: str) -> bool:
        if name in self._plugins:
            self._enabled[name] = True
            return True
        return False

    def disable(self, name: str) -> bool:
        if name in self._plugins:
            self._enabled[name] = False
            return True
        return False

    def is_enabled(self, name: str) -> bool:
        return self._enabled.get(name, False)

    def set_enabled_map(self, enabled_map: dict[str, bool]) -> None:
        """Bulk update enabled status (e.g. from DB-stored org config)."""
        for name, enabled in enabled_map.items():
            if name in self._plugins:
                self._enabled[name] = enabled

    # ── Queries ───────────────────────────────────────────────────────────

    def get(self, name: str) -> Optional[PluginAdapter]:
        return self._plugins.get(name)

    def list_plugins(self, only_enabled: bool = False) -> list[PluginMetadata]:
        """Return metadata for all (or only enabled) plugins."""
        results = []
        for slug, adapter in self._plugins.items():
            if only_enabled and not self._enabled.get(slug, False):
                continue
            results.append(adapter.metadata())
        return results

    def list_all(self) -> dict[str, PluginAdapter]:
        """Return all registered adapters keyed by slug."""
        return dict(self._plugins)

    def list_enabled(self) -> dict[str, PluginAdapter]:
        """Return adapter instances for all enabled plugins keyed by slug."""
        return {
            slug: adapter
            for slug, adapter in self._plugins.items()
            if self._enabled.get(slug, False)
        }

    def health_check_all(self) -> dict[str, PluginHealth]:
        """Run health checks on every registered plugin."""
        results: dict[str, PluginHealth] = {}
        for slug, adapter in self._plugins.items():
            try:
                results[slug] = adapter.health()
            except Exception as exc:
                results[slug] = PluginHealth(available=False, message=str(exc))
        return results

    @property
    def count(self) -> int:
        return len(self._plugins)


# ── Module-level singleton ────────────────────────────────────────────────────

_global_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """
    Return the global plugin registry, creating it and auto-discovering
    built-in adapters on first call.
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
        _auto_discover(_global_registry)
    return _global_registry


def get_load_errors() -> list[dict[str, str]]:
    """Adapter modules or classes that could not be loaded at startup: ``{"module", "adapter", "error"}``."""
    get_registry()
    return [dict(error) for error in _load_errors]


# Adapters are Python code that runs inside the API and the workers. Discovery looks
# only in this package, which ships with the application. It must never be pointed at
# a configurable or user-writable location.
ADAPTERS_PACKAGE = "app.services.plugins.adapters"

# The adapters shipped with GuardNous keep their historical registration order
# (native first, then external). Any other module follows, sorted by name.
_SHIPPED_MODULE_ORDER = (
    "native_adapter", "checkov_adapter", "trivy_adapter", "gitleaks_adapter", "semgrep_adapter", "tfsec_adapter",
)

_load_errors: list[dict[str, str]] = []


def _adapter_classes(module) -> list[type[PluginAdapter]]:
    """Concrete adapters defined in ``module`` itself, in the order they are written."""
    return [
        obj for name, obj in vars(module).items()
        if inspect.isclass(obj)
        and obj.__module__ == module.__name__          # defined here, not imported
        and issubclass(obj, PluginAdapter)
        and not inspect.isabstract(obj)
        and not name.startswith("_")
    ]


def discover_adapters(registry: PluginRegistry, package_name: str = ADAPTERS_PACKAGE) -> list[dict[str, str]]:
    """Register every adapter found in the modules of ``package_name``. Returns what could not be loaded.

    A module is any ``.py`` file directly in the package whose name does not start with
    an underscore. Each concrete ``PluginAdapter`` subclass defined in it is created with
    no arguments and registered. An adapter whose ``health()`` reports it is not available
    (for example, its command-line tool is not installed) is registered but disabled.

    One broken file does not stop the others: the error is logged with the module name
    and returned. When two adapters use the same name, the first is kept and the second
    is reported.

    ``package_name`` exists for the tests. The application always uses ``ADAPTERS_PACKAGE``.
    """
    errors: list[dict[str, str]] = []

    def failed(module: str, adapter: str, error: str) -> None:
        errors.append({"module": module, "adapter": adapter, "error": error})
        logger.error("Scanner adapter not loaded: module %s%s: %s", module, f", class {adapter}" if adapter else "", error)

    try:
        package = importlib.import_module(package_name)
    except Exception as exc:  # noqa: BLE001
        failed(package_name, "", f"{type(exc).__name__}: {exc}")
        return errors

    found = sorted(
        info.name for info in pkgutil.iter_modules(package.__path__)
        if not info.ispkg and not info.name.startswith("_")
    )
    shipped = [name for name in _SHIPPED_MODULE_ORDER if name in found] if package_name == ADAPTERS_PACKAGE else []
    owner: dict[str, str] = {}             # adapter name -> "module.Class" that registered it

    for module_name in [*shipped, *(name for name in found if name not in shipped)]:
        qualified = f"{package_name}.{module_name}"
        try:
            module = importlib.import_module(qualified)
        except Exception as exc:  # noqa: BLE001 - a broken adapter file must not take the application down
            failed(qualified, "", f"{type(exc).__name__}: {exc}")
            continue
        for cls in _adapter_classes(module):
            try:
                adapter = cls()
                name = adapter.metadata().name
            except Exception as exc:  # noqa: BLE001
                failed(qualified, cls.__name__, f"{type(exc).__name__}: {exc}")
                continue
            if name in owner or registry.get(name) is not None:
                failed(qualified, cls.__name__,
                       f"Duplicate adapter name '{name}': already registered by {owner.get(name, 'another adapter')}")
                continue
            owner[name] = f"{qualified}.{cls.__name__}"
            registry.register(adapter)
            # Enabled only when usable: native adapters always are, external ones need their tool installed
            try:
                health = adapter.health()
            except Exception as exc:  # noqa: BLE001
                health = PluginHealth(available=False, message=f"health check failed: {exc}")
            if not health.available:
                registry.disable(name)
                logger.info("Plugin '%s' disabled (not available: %s)", name, health.message)
    return errors


def _auto_discover(registry: PluginRegistry) -> None:
    """Register every adapter in the adapters package and remember what failed to load."""
    _load_errors[:] = discover_adapters(registry)

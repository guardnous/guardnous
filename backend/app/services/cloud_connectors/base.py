"""Base class for all cloud connectors — defines the discovery contract."""

from __future__ import annotations

import abc
import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class CloudSDKMissingError(RuntimeError):
    """The provider's SDK is not installed, so nothing can be read from the cloud."""


def sdk_missing(provider: str) -> CloudSDKMissingError:
    return CloudSDKMissingError(
        f"The {provider} SDK is not installed on the GuardNous server, so {provider} accounts "
        "cannot be validated or synced. Install backend/requirements-cloud.txt."
    )


def require_modules(*modules: str) -> None:
    """Raise ImportError naming every missing SDK module.

    Called before discovery so a partially installed SDK fails loudly instead of
    silently skipping the resource types whose client library is absent.
    """
    import importlib.util

    missing = []
    for name in modules:
        try:
            if importlib.util.find_spec(name) is None:
                missing.append(name)
        except ModuleNotFoundError:
            missing.append(name)
    if missing:
        raise ImportError(f"Missing cloud SDK modules: {', '.join(missing)}")


def demo_data_enabled() -> bool:
    """Sample resources are returned only on explicitly flagged demo installations."""
    from app.core.config import settings

    return settings.DEMO_DATA_ENABLED


@dataclass
class DiscoveredResource:
    """A cloud resource discovered during a sync operation."""
    provider: str                  # aws, azure, gcp
    resource_type: str             # e.g. aws_s3_bucket, azurerm_storage_account
    resource_id: str               # ARN / Azure resource ID / GCP self_link
    resource_name: str             # human-readable name
    region: str                    # us-east-1, eastus, us-central1
    account_id: str                # AWS account ID / subscription ID / project ID
    config: dict = field(default_factory=dict)   # full configuration for policy evaluation
    tags: dict = field(default_factory=dict)

    @property
    def config_hash(self) -> str:
        """SHA-256 of config for drift detection."""
        canonical = json.dumps(self.config, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


class BaseCloudConnector(abc.ABC):
    """Abstract base for cloud provider connectors.

    Each connector must implement `discover()` which yields DiscoveredResource objects.
    Connectors are stateless — credentials are passed at construction time.
    """

    PROVIDER: str = ""
    SUPPORTED_RESOURCE_TYPES: list[str] = []

    def __init__(self, credentials: dict, regions: list[str] | None = None):
        self.credentials = credentials
        self.regions = regions or []
        self._client_cache: dict[str, Any] = {}

    @abc.abstractmethod
    async def discover(
        self,
        resource_types: list[str] | None = None,
    ) -> list[DiscoveredResource]:
        """Discover all resources from this provider.

        Args:
            resource_types: If provided, only discover these types.
                            If None, discover all supported types.
        Returns:
            List of DiscoveredResource objects with full configuration.
        """
        ...

    @abc.abstractmethod
    async def test_connection(self) -> dict:
        """Test if credentials are valid. Returns {"status": "connected"|"error", ...}."""
        ...

    def _filter_types(self, resource_types: list[str] | None) -> list[str]:
        """Return the resource types to discover."""
        if resource_types:
            return [t for t in resource_types if t in self.SUPPORTED_RESOURCE_TYPES]
        return self.SUPPORTED_RESOURCE_TYPES

    @staticmethod
    def _safe_get(d: dict, *keys, default=None):
        """Safely traverse nested dicts."""
        current = d
        for k in keys:
            if isinstance(current, dict):
                current = current.get(k, default)
            else:
                return default
        return current

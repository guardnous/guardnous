"""Cloud Connectors — real resource discovery from AWS, Azure, and GCP."""

from app.services.cloud_connectors.base import BaseCloudConnector, DiscoveredResource
from app.services.cloud_connectors.aws_connector import AWSConnector
from app.services.cloud_connectors.azure_connector import AzureConnector
from app.services.cloud_connectors.gcp_connector import GCPConnector
from app.services.cloud_connectors.sync_orchestrator import SyncOrchestrator

CONNECTOR_MAP = {
    "aws": AWSConnector,
    "azure": AzureConnector,
    "gcp": GCPConnector,
}


def get_connector(provider: str, credentials: dict, regions: list[str] | None = None) -> BaseCloudConnector:
    """Factory — return the right connector for a provider."""
    cls = CONNECTOR_MAP.get(provider)
    if not cls:
        raise ValueError(f"Unsupported provider: {provider}")
    return cls(credentials=credentials, regions=regions)


__all__ = [
    "BaseCloudConnector", "DiscoveredResource",
    "AWSConnector", "AzureConnector", "GCPConnector",
    "SyncOrchestrator", "get_connector",
]

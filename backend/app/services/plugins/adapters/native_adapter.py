"""
Native Adapters — wraps GuardNous's built-in scanners as PluginAdapters.

This ensures native scanners participate in the same plugin lifecycle as
external tools (registry, health check, enable/disable, orchestration).
"""

from __future__ import annotations

from typing import Any

from app.services.plugins.base import (
    PluginAdapter,
    PluginCapability,
    PluginHealth,
    PluginMetadata,
)
from app.services.scanners.base import ScanResult


class NativeTerraformAdapter(PluginAdapter):
    """Built-in Terraform/HCL security scanner."""

    def __init__(self) -> None:
        from app.services.scanners.terraform_scanner import TerraformScanner
        self._scanner = TerraformScanner()

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="native_terraform",
            display_name="GuardNous Terraform Scanner",
            version="1.0.0",
            description="25 built-in security rules for Terraform/HCL covering AWS, GCP, and Azure resources.",
            homepage="https://github.com/guardnous/guardnous",
            icon="FileCode",
            capabilities=[PluginCapability.IAC_TERRAFORM],
            is_native=True,
        )

    def health(self) -> PluginHealth:
        return PluginHealth(available=True, version="1.0.0", message="Built-in scanner")

    def scan(self, content: str, file_name: str = "", config: dict[str, Any] | None = None) -> list[ScanResult]:
        return self._scanner.scan(content, file_name)


class NativeCloudFormationAdapter(PluginAdapter):
    """Built-in CloudFormation security scanner."""

    def __init__(self) -> None:
        from app.services.scanners.cloudformation_scanner import CloudFormationScanner
        self._scanner = CloudFormationScanner()

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="native_cloudformation",
            display_name="GuardNous CloudFormation Scanner",
            version="1.0.0",
            description="25 built-in security rules for AWS CloudFormation templates.",
            homepage="https://github.com/guardnous/guardnous",
            icon="Cloud",
            capabilities=[PluginCapability.IAC_CLOUDFORMATION],
            is_native=True,
        )

    def health(self) -> PluginHealth:
        return PluginHealth(available=True, version="1.0.0", message="Built-in scanner")

    def scan(self, content: str, file_name: str = "", config: dict[str, Any] | None = None) -> list[ScanResult]:
        return self._scanner.scan(content, file_name)


class NativeBicepAdapter(PluginAdapter):
    """Built-in Azure Bicep security scanner."""

    def __init__(self) -> None:
        from app.services.scanners.bicep_scanner import BicepScanner
        self._scanner = BicepScanner()

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="native_bicep",
            display_name="GuardNous Bicep Scanner",
            version="1.0.0",
            description="25 built-in security rules for Azure Bicep/ARM templates.",
            homepage="https://github.com/guardnous/guardnous",
            icon="Server",
            capabilities=[PluginCapability.IAC_BICEP],
            is_native=True,
        )

    def health(self) -> PluginHealth:
        return PluginHealth(available=True, version="1.0.0", message="Built-in scanner")

    def scan(self, content: str, file_name: str = "", config: dict[str, Any] | None = None) -> list[ScanResult]:
        return self._scanner.scan(content, file_name)


class NativeSecretsAdapter(PluginAdapter):
    """Built-in secrets/credential detection scanner."""

    def __init__(self) -> None:
        from app.services.secrets.scanner import SecretsScanner
        self._scanner = SecretsScanner()

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="native_secrets",
            display_name="GuardNous Secrets Scanner",
            version="1.0.0",
            description="18 secret/credential detection patterns covering AWS, GCP, Azure, GitHub, and generic passwords.",
            homepage="https://github.com/guardnous/guardnous",
            icon="KeyRound",
            capabilities=[PluginCapability.SECRETS],
            is_native=True,
        )

    def health(self) -> PluginHealth:
        return PluginHealth(available=True, version="1.0.0", message="Built-in scanner")

    def scan(self, content: str, file_name: str = "", config: dict[str, Any] | None = None) -> list[ScanResult]:
        return self._scanner.scan(content, file_name)

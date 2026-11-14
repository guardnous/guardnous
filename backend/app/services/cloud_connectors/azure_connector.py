"""Azure Cloud Connector — discovers Storage Accounts, NSGs, SQL, Key Vaults, VMs, RBAC."""

from __future__ import annotations

import logging

from app.services.cloud_connectors.base import (
    BaseCloudConnector, DiscoveredResource, demo_data_enabled, require_modules, sdk_missing,
)

logger = logging.getLogger(__name__)


class AzureConnector(BaseCloudConnector):
    PROVIDER = "azure"
    SUPPORTED_RESOURCE_TYPES = [
        "azurerm_storage_account",
        "azurerm_network_security_group",
        "azurerm_mssql_server",
        "azurerm_key_vault",
        "azurerm_virtual_machine",
        "azurerm_role_assignment",
    ]

    def _get_credential(self):
        require_modules(
            "azure.identity", "azure.mgmt.resource", "azure.mgmt.storage", "azure.mgmt.network",
            "azure.mgmt.sql", "azure.mgmt.keyvault", "azure.mgmt.compute", "azure.mgmt.authorization",
        )
        from azure.identity import ClientSecretCredential
        return ClientSecretCredential(
            tenant_id=self.credentials["tenant_id"],
            client_id=self.credentials["client_id"],
            client_secret=self.credentials["client_secret"],
        )

    @property
    def _sub_id(self) -> str:
        return self.credentials["subscription_id"]

    async def test_connection(self) -> dict:
        try:
            from azure.mgmt.resource import ResourceManagementClient
            cred = self._get_credential()
            client = ResourceManagementClient(cred, self._sub_id)
            rgs = list(client.resource_groups.list())
            return {"status": "connected", "details": {
                "subscription_id": self._sub_id,
                "resource_groups_found": len(rgs),
            }}
        except ImportError:
            return {"status": "error", "error": str(sdk_missing("Azure"))}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def discover(self, resource_types: list[str] | None = None) -> list[DiscoveredResource]:
        types_to_discover = self._filter_types(resource_types)
        resources: list[DiscoveredResource] = []

        try:
            cred = self._get_credential()
        except ImportError:
            if demo_data_enabled():
                logger.warning("azure SDK not installed — DEMO_DATA_ENABLED, returning sample resources")
                return self._simulated_resources()
            raise sdk_missing("Azure")
        except Exception as e:
            logger.error(f"Azure credential error: {e}")
            raise

        sub_id = self._sub_id

        if "azurerm_storage_account" in types_to_discover:
            resources.extend(self._discover_storage_accounts(cred, sub_id))
        if "azurerm_network_security_group" in types_to_discover:
            resources.extend(self._discover_nsgs(cred, sub_id))
        if "azurerm_mssql_server" in types_to_discover:
            resources.extend(self._discover_sql_servers(cred, sub_id))
        if "azurerm_key_vault" in types_to_discover:
            resources.extend(self._discover_key_vaults(cred, sub_id))
        if "azurerm_virtual_machine" in types_to_discover:
            resources.extend(self._discover_vms(cred, sub_id))
        if "azurerm_role_assignment" in types_to_discover:
            resources.extend(self._discover_role_assignments(cred, sub_id))

        logger.info(f"Azure discovery complete: {len(resources)} resources found")
        return resources

    # ── Storage Accounts ─────────────────────────────────────────────────────

    def _discover_storage_accounts(self, cred, sub_id: str) -> list[DiscoveredResource]:
        results = []
        try:
            from azure.mgmt.storage import StorageManagementClient
            client = StorageManagementClient(cred, sub_id)
            for sa in client.storage_accounts.list():
                config = {
                    "name": sa.name,
                    "kind": sa.kind,
                    "sku_name": sa.sku.name if sa.sku else None,
                    "location": sa.location,
                    "https_only": sa.enable_https_traffic_only,
                    "min_tls_version": sa.minimum_tls_version,
                    "allow_blob_public_access": getattr(sa, "allow_blob_public_access", None),
                    "network_default_action": sa.network_rule_set.default_action if sa.network_rule_set else "Allow",
                    "encryption_services": {
                        "blob": bool(sa.encryption and sa.encryption.services and sa.encryption.services.blob),
                        "file": bool(sa.encryption and sa.encryption.services and sa.encryption.services.file),
                    },
                    "infrastructure_encryption_enabled": getattr(sa, "require_infrastructure_encryption", False),
                }
                tags = dict(sa.tags) if sa.tags else {}
                results.append(DiscoveredResource(
                    provider="azure",
                    resource_type="azurerm_storage_account",
                    resource_id=sa.id,
                    resource_name=sa.name,
                    region=sa.location,
                    account_id=sub_id,
                    config=config, tags=tags,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Azure storage discovery failed: {e}")
        return results

    # ── NSGs ─────────────────────────────────────────────────────────────────

    def _discover_nsgs(self, cred, sub_id: str) -> list[DiscoveredResource]:
        results = []
        try:
            from azure.mgmt.network import NetworkManagementClient
            client = NetworkManagementClient(cred, sub_id)
            for nsg in client.network_security_groups.list_all():
                inbound_rules = []
                for rule in (nsg.security_rules or []):
                    if rule.direction == "Inbound":
                        inbound_rules.append({
                            "name": rule.name,
                            "priority": rule.priority,
                            "access": rule.access,
                            "protocol": rule.protocol,
                            "source_address_prefix": rule.source_address_prefix,
                            "destination_port_range": rule.destination_port_range,
                        })
                config = {
                    "name": nsg.name,
                    "location": nsg.location,
                    "inbound_rules": inbound_rules,
                    "allows_ssh_from_internet": any(
                        r["source_address_prefix"] in ("*", "Internet", "0.0.0.0/0")
                        and r["access"] == "Allow" and r.get("destination_port_range") in ("22", "*")
                        for r in inbound_rules
                    ),
                    "allows_rdp_from_internet": any(
                        r["source_address_prefix"] in ("*", "Internet", "0.0.0.0/0")
                        and r["access"] == "Allow" and r.get("destination_port_range") in ("3389", "*")
                        for r in inbound_rules
                    ),
                }
                tags = dict(nsg.tags) if nsg.tags else {}
                results.append(DiscoveredResource(
                    provider="azure",
                    resource_type="azurerm_network_security_group",
                    resource_id=nsg.id,
                    resource_name=nsg.name,
                    region=nsg.location,
                    account_id=sub_id,
                    config=config, tags=tags,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Azure NSG discovery failed: {e}")
        return results

    # ── SQL Servers ──────────────────────────────────────────────────────────

    def _discover_sql_servers(self, cred, sub_id: str) -> list[DiscoveredResource]:
        results = []
        try:
            from azure.mgmt.sql import SqlManagementClient
            client = SqlManagementClient(cred, sub_id)
            for srv in client.servers.list():
                # Get auditing settings
                audit_enabled = False
                try:
                    rg = srv.id.split("/")[4]
                    audit = client.server_blob_auditing_policies.get(rg, srv.name)
                    audit_enabled = audit.state == "Enabled"
                except Exception:
                    pass

                config = {
                    "name": srv.name,
                    "location": srv.location,
                    "version": srv.version,
                    "administrator_login": srv.administrator_login,
                    "fully_qualified_domain_name": srv.fully_qualified_domain_name,
                    "public_network_access": getattr(srv, "public_network_access", "Enabled"),
                    "minimal_tls_version": getattr(srv, "minimal_tls_version", "1.0"),
                    "auditing_enabled": audit_enabled,
                }
                tags = dict(srv.tags) if srv.tags else {}
                results.append(DiscoveredResource(
                    provider="azure",
                    resource_type="azurerm_mssql_server",
                    resource_id=srv.id,
                    resource_name=srv.name,
                    region=srv.location,
                    account_id=sub_id,
                    config=config, tags=tags,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Azure SQL discovery failed: {e}")
        return results

    # ── Key Vaults ───────────────────────────────────────────────────────────

    def _discover_key_vaults(self, cred, sub_id: str) -> list[DiscoveredResource]:
        results = []
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            client = KeyVaultManagementClient(cred, sub_id)
            for vault in client.vaults.list():
                props = vault.properties
                config = {
                    "name": vault.name,
                    "location": vault.location,
                    "sku_name": props.sku.name if props.sku else None,
                    "soft_delete_enabled": getattr(props, "enable_soft_delete", True),
                    "purge_protection_enabled": getattr(props, "enable_purge_protection", False),
                    "enable_rbac_authorization": getattr(props, "enable_rbac_authorization", False),
                    "public_network_access": getattr(props, "public_network_access", "Enabled"),
                    "network_acls_default_action": (
                        props.network_acls.default_action if props.network_acls else "Allow"
                    ),
                }
                tags = dict(vault.tags) if vault.tags else {}
                results.append(DiscoveredResource(
                    provider="azure",
                    resource_type="azurerm_key_vault",
                    resource_id=vault.id,
                    resource_name=vault.name,
                    region=vault.location,
                    account_id=sub_id,
                    config=config, tags=tags,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Azure Key Vault discovery failed: {e}")
        return results

    # ── Virtual Machines ─────────────────────────────────────────────────────

    def _discover_vms(self, cred, sub_id: str) -> list[DiscoveredResource]:
        results = []
        try:
            from azure.mgmt.compute import ComputeManagementClient
            client = ComputeManagementClient(cred, sub_id)
            for vm in client.virtual_machines.list_all():
                os_profile = vm.os_profile or type("O", (), {"linux_configuration": None, "windows_configuration": None})()
                config = {
                    "name": vm.name,
                    "location": vm.location,
                    "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                    "os_type": "linux" if os_profile.linux_configuration else "windows",
                    "os_disk_encryption": bool(
                        vm.storage_profile and vm.storage_profile.os_disk
                        and vm.storage_profile.os_disk.encryption_settings
                    ),
                    "data_disks_count": len(vm.storage_profile.data_disks) if vm.storage_profile else 0,
                    "managed_identity": bool(vm.identity),
                    "identity_type": vm.identity.type if vm.identity else None,
                    "availability_zone": vm.zones[0] if vm.zones else None,
                }
                tags = dict(vm.tags) if vm.tags else {}
                results.append(DiscoveredResource(
                    provider="azure",
                    resource_type="azurerm_virtual_machine",
                    resource_id=vm.id,
                    resource_name=vm.name,
                    region=vm.location,
                    account_id=sub_id,
                    config=config, tags=tags,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Azure VM discovery failed: {e}")
        return results

    # ── Role Assignments ─────────────────────────────────────────────────────

    def _discover_role_assignments(self, cred, sub_id: str) -> list[DiscoveredResource]:
        results = []
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
            client = AuthorizationManagementClient(cred, sub_id)
            role_defs = {}
            for rd in client.role_definitions.list(scope=f"/subscriptions/{sub_id}"):
                role_defs[rd.id] = rd.role_name

            for ra in client.role_assignments.list_for_subscription():
                role_name = role_defs.get(ra.role_definition_id, "Unknown")
                config = {
                    "principal_id": ra.principal_id,
                    "principal_type": ra.principal_type,
                    "role_definition_name": role_name,
                    "scope": ra.scope,
                    "is_subscription_scope": ra.scope == f"/subscriptions/{sub_id}",
                    "is_owner_or_contributor": role_name in ("Owner", "Contributor"),
                }
                results.append(DiscoveredResource(
                    provider="azure",
                    resource_type="azurerm_role_assignment",
                    resource_id=ra.id,
                    resource_name=f"{role_name} → {ra.principal_id[:8]}",
                    region="global",
                    account_id=sub_id,
                    config=config,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Azure role assignment discovery failed: {e}")
        return results

    # ── Simulated ─────────────────────────────────────────────────────────────

    def _simulated_resources(self) -> list[DiscoveredResource]:
        sub_id = self._sub_id
        return [
            DiscoveredResource(
                provider="azure", resource_type="azurerm_storage_account",
                resource_id=f"/subscriptions/{sub_id}/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/prodappstorage",
                resource_name="prodappstorage", region="eastus", account_id=sub_id,
                config={
                    "name": "prodappstorage", "kind": "StorageV2",
                    "https_only": True, "min_tls_version": "TLS1_2",
                    "allow_blob_public_access": False,
                    "network_default_action": "Deny",
                    "encryption_services": {"blob": True, "file": True},
                    "infrastructure_encryption_enabled": True,
                },
            ),
            DiscoveredResource(
                provider="azure", resource_type="azurerm_storage_account",
                resource_id=f"/subscriptions/{sub_id}/resourceGroups/rg-dev/providers/Microsoft.Storage/storageAccounts/devteststorage",
                resource_name="devteststorage", region="eastus", account_id=sub_id,
                config={
                    "name": "devteststorage", "kind": "StorageV2",
                    "https_only": False, "min_tls_version": "TLS1_0",
                    "allow_blob_public_access": True,
                    "network_default_action": "Allow",
                    "encryption_services": {"blob": True, "file": False},
                    "infrastructure_encryption_enabled": False,
                },
            ),
            DiscoveredResource(
                provider="azure", resource_type="azurerm_network_security_group",
                resource_id=f"/subscriptions/{sub_id}/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
                resource_name="nsg-web", region="eastus", account_id=sub_id,
                config={
                    "name": "nsg-web", "location": "eastus",
                    "inbound_rules": [
                        {"name": "AllowSSH", "priority": 100, "access": "Allow",
                         "protocol": "Tcp", "source_address_prefix": "*", "destination_port_range": "22"},
                    ],
                    "allows_ssh_from_internet": True,
                    "allows_rdp_from_internet": False,
                },
            ),
            DiscoveredResource(
                provider="azure", resource_type="azurerm_key_vault",
                resource_id=f"/subscriptions/{sub_id}/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod-app",
                resource_name="kv-prod-app", region="eastus", account_id=sub_id,
                config={
                    "name": "kv-prod-app",
                    "soft_delete_enabled": True, "purge_protection_enabled": False,
                    "enable_rbac_authorization": True,
                    "public_network_access": "Enabled",
                    "network_acls_default_action": "Allow",
                },
            ),
            DiscoveredResource(
                provider="azure", resource_type="azurerm_mssql_server",
                resource_id=f"/subscriptions/{sub_id}/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-prod-main",
                resource_name="sql-prod-main", region="eastus", account_id=sub_id,
                config={
                    "name": "sql-prod-main",
                    "version": "12.0", "public_network_access": "Enabled",
                    "minimal_tls_version": "1.0", "auditing_enabled": False,
                },
            ),
        ]

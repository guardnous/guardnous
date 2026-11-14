import re
from app.services.scanners.base import BaseScanner, ScanResult


class BicepScanner(BaseScanner):
    """Azure Bicep (.bicep) file security scanner with 40 enterprise checks."""

    def detect_cloud_provider(self, content: str) -> str:
        return "azure"

    def scan(self, content: str, file_name: str = "") -> list[ScanResult]:
        results = []
        lines = content.split("\n")

        checks = [
            self._check_public_access_storage,
            self._check_unencrypted_storage,
            self._check_public_ip,
            self._check_nsg_allow_all,
            self._check_http_allowed,
            self._check_sql_public_access,
            self._check_sql_no_encryption,
            self._check_missing_keyvault_sku,
            self._check_missing_diagnostics,
            self._check_hardcoded_secrets,
            self._check_missing_tags,
            self._check_insecure_tls,
            self._check_admin_username,
            self._check_ssh_password_auth,
            self._check_missing_nsg,
            self._check_overly_permissive_rbac,
            self._check_public_container_registry,
            self._check_missing_backup_vault,
            self._check_unencrypted_disk,
            self._check_missing_logging,
            self._check_function_app_http2,
            self._check_web_app_managed_identity,
            self._check_cosmos_public_access,
            self._check_redis_non_ssl,
            self._check_missing_network_watcher,
            # Enterprise checks 26-40
            self._check_aks_rbac,
            self._check_aks_network_policy,
            self._check_keyvault_soft_delete,
            self._check_storage_min_tls,
            self._check_sql_firewall_allow_all,
            self._check_app_service_ftps,
            self._check_private_endpoint,
            self._check_app_service_auth,
            self._check_sql_auditing,
            self._check_vm_encryption_at_host,
            self._check_app_gateway_waf,
            self._check_container_instance_public,
            self._check_storage_soft_delete,
            self._check_event_hub_encryption,
            self._check_service_bus_premium,
        ]

        for check in checks:
            results.extend(check(content, lines, file_name))

        return results

    def _find_line(self, lines: list[str], pattern: str) -> int:
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 0

    def _get_snippet(self, lines: list[str], line_num: int, context: int = 2) -> str:
        if line_num <= 0:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return "\n".join(lines[start:end])

    # CHECK 1: Public Access on Storage Account
    def _check_public_access_storage(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"allowBlobPublicAccess\s*:\s*true"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-001",
                title="Storage account allows public blob access",
                description="Azure storage account has allowBlobPublicAccess enabled.",
                severity="CRITICAL",
                cloud_provider="azure",
                resource_type="Microsoft.Storage/storageAccounts",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Set allowBlobPublicAccess to false.",
            ))
        return results

    # CHECK 2: Missing encryption on storage
    def _check_unencrypted_storage(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts", content):
            ln = content[:match.start()].count("\n") + 1
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            # Azure Storage is encrypted by default (SSE) since 2017.
            # Only flag if no CMK encryption is configured — omitting encryption block
            # just means using Microsoft-managed keys, which is acceptable.
            if "encryption" not in block:
                results.append(ScanResult(
                    rule_id="SD-BI-002",
                    title="Storage account using default Microsoft-managed encryption keys",
                    description="Storage account does not configure customer-managed keys (CMK) for encryption. Azure Storage is encrypted by default with Microsoft-managed keys, but CMK provides additional control.",
                    severity="LOW",
                    cloud_provider="azure",
                    resource_type="Microsoft.Storage/storageAccounts",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Consider adding customer-managed key encryption via Key Vault for sensitive data.",
                ))
        return results

    # CHECK 3: Public IP
    def _check_public_ip(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Network/publicIPAddresses", content):
            ln = content[:match.start()].count("\n") + 1
            # Public IPs are legitimate for load balancers, app gateways, bastions, NAT gateways.
            # Only flag as informational — the real risk is when a public IP is directly
            # attached to a VM NIC without an NSG.
            results.append(ScanResult(
                rule_id="SD-BI-003",
                title="Public IP address resource detected",
                description="Public IP address found. Public IPs are acceptable for load balancers, app gateways, and bastion hosts, but should be avoided for direct VM attachment without NSG protection.",
                severity="INFO",
                cloud_provider="azure",
                resource_type="Microsoft.Network/publicIPAddresses",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Ensure this public IP is attached to a load balancer, app gateway, or bastion — not directly to a VM NIC. If attached to a VM, ensure an NSG is present.",
            ))
        return results

    # CHECK 4: NSG Allow All
    def _check_nsg_allow_all(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"sourceAddressPrefix\s*:\s*'?\*'?"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            context_start = max(0, match.start() - 100)
            context = content[context_start:match.end() + 100]
            if "Allow" in context:
                results.append(ScanResult(
                    rule_id="SD-BI-004",
                    title="NSG rule allows traffic from all sources (*)",
                    description="Network Security Group has a rule allowing traffic from any source.",
                    severity="CRITICAL",
                    cloud_provider="azure",
                    resource_type="Microsoft.Network/networkSecurityGroups",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Restrict sourceAddressPrefix to specific IP ranges.",
                ))
        return results

    # CHECK 5: HTTP Allowed (not HTTPS only)
    def _check_http_allowed(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"httpsOnly\s*:\s*false"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-005",
                title="Web app/Function app allows non-HTTPS traffic",
                description="httpsOnly is set to false, allowing unencrypted HTTP traffic.",
                severity="HIGH",
                cloud_provider="azure",
                resource_type="Microsoft.Web/sites",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Set httpsOnly to true.",
            ))
        return results

    # CHECK 6: SQL Public Access
    def _check_sql_public_access(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"publicNetworkAccess\s*:\s*'Enabled'"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-006",
                title="SQL Server has public network access enabled",
                description="Azure SQL Server is accessible from public networks.",
                severity="CRITICAL",
                cloud_provider="azure",
                resource_type="Microsoft.Sql/servers",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Set publicNetworkAccess to 'Disabled' and use private endpoints.",
            ))
        return results

    # CHECK 7: SQL No TDE
    def _check_sql_no_encryption(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Sql/servers/databases", content):
            ln = content[:match.start()].count("\n") + 1
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "transparentDataEncryption" not in block and "encryptionProtector" not in content:
                results.append(ScanResult(
                    rule_id="SD-BI-007",
                    title="SQL Database missing transparent data encryption",
                    description="Azure SQL Database does not have TDE configured.",
                    severity="HIGH",
                    cloud_provider="azure",
                    resource_type="Microsoft.Sql/servers/databases",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Enable Transparent Data Encryption (TDE).",
                ))
        return results

    # CHECK 8: Key Vault SKU
    def _check_missing_keyvault_sku(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.KeyVault/vaults", content):
            ln = content[:match.start()].count("\n") + 1
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "enablePurgeProtection" not in block:
                results.append(ScanResult(
                    rule_id="SD-BI-008",
                    title="Key Vault missing purge protection",
                    description="Azure Key Vault does not have purge protection enabled.",
                    severity="HIGH",
                    cloud_provider="azure",
                    resource_type="Microsoft.KeyVault/vaults",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set enablePurgeProtection to true.",
                ))
        return results

    # CHECK 9: Missing Diagnostics
    def _check_missing_diagnostics(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        # Only flag diagnostics-capable resources (not every Microsoft.* resource)
        diag_resource_types = [
            "Microsoft.Sql/servers",
            "Microsoft.Web/sites",
            "Microsoft.KeyVault/vaults",
            "Microsoft.Network/applicationGateways",
            "Microsoft.Network/azureFirewalls",
            "Microsoft.Network/loadBalancers",
            "Microsoft.ContainerService/managedClusters",
            "Microsoft.Compute/virtualMachines",
            "Microsoft.Storage/storageAccounts",
        ]
        if "diagnosticSettings" not in content and "Microsoft.Insights" not in content:
            flagged = False
            for res_type in diag_resource_types:
                escaped = res_type.replace(".", r"\.")
                pattern = rf"resource\s+\w+\s+'{escaped}"
                for match in re.finditer(pattern, content):
                    ln = content[:match.start()].count("\n") + 1
                    results.append(ScanResult(
                        rule_id="SD-BI-009",
                        title=f"Resource missing diagnostic settings ({res_type.split('/')[-1]})",
                        description=f"No diagnostic settings found in template for {res_type}. Diagnostic logging is recommended for monitoring and compliance.",
                        severity="MEDIUM",
                        cloud_provider="azure",
                        file_path=file_name, line_number=ln,
                        code_snippet=self._get_snippet(lines, ln),
                        remediation="Add Microsoft.Insights/diagnosticSettings resource for key infrastructure components.",
                    ))
                    flagged = True
                    break  # one finding per resource type is enough
                if flagged:
                    break  # one finding per template is enough to surface the issue
        return results

    # CHECK 10: Hardcoded Secrets
    def _check_hardcoded_secrets(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        patterns = [
            (r"(?:password|secret|key)\s*:\s*'([^']{8,})'", "Hardcoded secret"),
            (r"(?:password|secret|key)\s*=\s*'([^']{8,})'", "Hardcoded parameter"),
            (r"\w*(?:Password|Secret|Key)\w*\s+\w+\s*=\s*'([^']{8,})'", "Hardcoded param value"),
        ]
        for pat, desc in patterns:
            for match in re.finditer(pat, content, re.IGNORECASE):
                val = match.group(1) if match.lastindex else ""
                if not val.startswith("@") and "reference" not in val.lower():
                    ln = content[:match.start()].count("\n") + 1
                    results.append(ScanResult(
                        rule_id="SD-BI-010",
                        title=f"Potential hardcoded secret: {desc}",
                        description=f"Found {desc} in Bicep template.",
                        severity="CRITICAL",
                        category="secrets",
                        cloud_provider="azure",
                        file_path=file_name, line_number=ln,
                        code_snippet=self._get_snippet(lines, ln),
                        remediation="Use Key Vault references or @secure() decorator.",
                    ))
        return results

    # CHECK 11: Missing Tags
    def _check_missing_tags(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'(Microsoft\.\w+/\w+)", content):
            res_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "tags" not in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-011",
                    title=f"Resource '{res_name}' missing tags",
                    description="Azure resource does not have tags configured.",
                    severity="LOW",
                    cloud_provider="azure",
                    resource_type=match.group(2),
                    resource_name=res_name,
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add tags property with Environment, Owner, CostCenter.",
                ))
        return results

    # CHECK 12: Insecure TLS
    def _check_insecure_tls(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"minTlsVersion\s*:\s*'?(TLS1_0|TLS1_1|1\.0|1\.1)'?"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-012",
                title=f"Insecure TLS version: {match.group(1)}",
                description="Resource uses outdated TLS version.",
                severity="HIGH",
                cloud_provider="azure",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Set minTlsVersion to 'TLS1_2' or higher.",
            ))
        return results

    # CHECK 13: Admin username
    def _check_admin_username(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"administratorLogin\s*:\s*'(admin|root|administrator|sa)'"
        for match in re.finditer(pattern, content, re.IGNORECASE):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-013",
                title=f"Default admin username: {match.group(1)}",
                description="Using default/common admin username.",
                severity="MEDIUM",
                cloud_provider="azure",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Use a unique administrator username.",
            ))
        return results

    # CHECK 14: SSH Password Auth
    def _check_ssh_password_auth(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"disablePasswordAuthentication\s*:\s*false"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-014",
                title="VM allows SSH password authentication",
                description="Password authentication for SSH is enabled. Use SSH keys instead.",
                severity="HIGH",
                cloud_provider="azure",
                resource_type="Microsoft.Compute/virtualMachines",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Set disablePasswordAuthentication to true and use SSH keys.",
            ))
        return results

    # CHECK 15: Missing NSG
    def _check_missing_nsg(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Network/networkInterfaces", content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "networkSecurityGroup" not in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-015",
                    title="Network interface missing NSG",
                    description="Network interface does not have a Network Security Group attached.",
                    severity="HIGH",
                    cloud_provider="azure",
                    resource_type="Microsoft.Network/networkInterfaces",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Attach a networkSecurityGroup to the NIC.",
                ))
        return results

    # CHECK 16: Overly permissive RBAC
    def _check_overly_permissive_rbac(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"roleDefinitionId\s*:.*(?:Owner|Contributor)"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-016",
                title="Overly permissive RBAC role assignment",
                description="Owner or Contributor role assigned. Use least-privilege roles.",
                severity="HIGH",
                cloud_provider="azure",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Use custom RBAC roles with minimum required permissions.",
            ))
        return results

    # CHECK 17: Public Container Registry
    def _check_public_container_registry(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.ContainerRegistry/registries", content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "publicNetworkAccess" not in block or "Enabled" in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-017",
                    title="Container registry allows public access",
                    description="Azure Container Registry allows public network access.",
                    severity="MEDIUM",
                    cloud_provider="azure",
                    resource_type="Microsoft.ContainerRegistry/registries",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set publicNetworkAccess to 'Disabled' and use private endpoints.",
                ))
        return results

    # CHECK 18: Missing Backup
    def _check_missing_backup_vault(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        if "Microsoft.RecoveryServices" not in content:
            for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines", content):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-018",
                    title="No backup vault configured for VMs",
                    description="Template does not include Recovery Services vault for VM backup.",
                    severity="MEDIUM",
                    cloud_provider="azure",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add Microsoft.RecoveryServices/vaults for backup.",
                ))
                break
        return results

    # CHECK 19: Unencrypted Disk
    def _check_unencrypted_disk(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Compute/disks", content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            # Azure managed disks are encrypted at rest by default with platform-managed keys (PMK).
            # Only flag when customer-managed keys (CMK) are not configured.
            if "encryptionSettingsCollection" not in block and "diskEncryptionSet" not in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-019",
                    title="Managed disk using platform-managed encryption keys",
                    description="Azure managed disk is encrypted by default with platform-managed keys, but does not use customer-managed keys (CMK). CMK provides additional control over encryption keys via Azure Key Vault.",
                    severity="LOW",
                    cloud_provider="azure",
                    resource_type="Microsoft.Compute/disks",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Consider using diskEncryptionSetId to enable customer-managed key encryption via Key Vault for sensitive workloads.",
                ))
        return results

    # CHECK 20: Missing Logging
    def _check_missing_logging(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Web/sites", content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "httpLoggingEnabled" not in block and "detailedErrorLoggingEnabled" not in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-020",
                    title="Web app missing HTTP logging",
                    description="App Service does not have HTTP logging enabled.",
                    severity="MEDIUM",
                    cloud_provider="azure",
                    resource_type="Microsoft.Web/sites",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Enable httpLoggingEnabled and detailedErrorLoggingEnabled.",
                ))
        return results

    # CHECK 21-25: Remaining Azure checks
    def _check_function_app_http2(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Web/sites", content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "http20Enabled" not in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-021",
                    title="Web/Function app not using HTTP/2",
                    description="App is not configured to use HTTP/2.",
                    severity="LOW",
                    cloud_provider="azure",
                    resource_type="Microsoft.Web/sites",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set http20Enabled to true.",
                ))
        return results

    def _check_web_app_managed_identity(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.Web/sites", content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "identity" not in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-022",
                    title="Web app missing managed identity",
                    description="App Service does not use managed identity.",
                    severity="MEDIUM",
                    cloud_provider="azure",
                    resource_type="Microsoft.Web/sites",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add identity block with type: 'SystemAssigned'.",
                ))
        return results

    def _check_cosmos_public_access(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+\w+\s+'Microsoft\.DocumentDB/databaseAccounts", content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "publicNetworkAccess" not in block or "Enabled" in block:
                ln = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-023",
                    title="Cosmos DB allows public network access",
                    description="Cosmos DB account is accessible from public networks.",
                    severity="HIGH",
                    cloud_provider="azure",
                    resource_type="Microsoft.DocumentDB/databaseAccounts",
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set publicNetworkAccess to 'Disabled'.",
                ))
        return results

    def _check_redis_non_ssl(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        pattern = r"enableNonSslPort\s*:\s*true"
        for match in re.finditer(pattern, content):
            ln = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-BI-024",
                title="Redis Cache allows non-SSL connections",
                description="Azure Redis Cache has non-SSL port enabled.",
                severity="HIGH",
                cloud_provider="azure",
                resource_type="Microsoft.Cache/redis",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Set enableNonSslPort to false.",
            ))
        return results

    def _check_missing_network_watcher(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        if "Microsoft.Network/virtualNetworks" in content and "Microsoft.Network/networkWatchers" not in content:
            ln = self._find_line(lines, "virtualNetworks")
            results.append(ScanResult(
                rule_id="SD-BI-025",
                title="Missing Network Watcher",
                description="Template has VNets but no Network Watcher for monitoring.",
                severity="LOW",
                cloud_provider="azure",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Add Microsoft.Network/networkWatchers resource.",
            ))
        return results

    # === CHECK 26: AKS RBAC Enabled ===
    def _check_aks_rbac(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        if "Microsoft.ContainerService/managedClusters" not in content:
            return results
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.ContainerService/managedClusters@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            block_lower = block.lower()
            rbac_pos = block_lower.find("enablerbac")
            if rbac_pos == -1 or "false" in block_lower[rbac_pos:rbac_pos+30]:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-026", title=f"AKS cluster '{name}' RBAC not enabled",
                    description="AKS cluster does not have Kubernetes RBAC enabled. Without RBAC, all users have unrestricted cluster access.",
                    severity="HIGH", cloud_provider="azure", resource_type="managedClusters",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set enableRbac: true in the AKS resource properties.",
                ))
        return results

    # === CHECK 27: AKS Network Policy ===
    def _check_aks_network_policy(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        if "Microsoft.ContainerService/managedClusters" not in content:
            return results
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.ContainerService/managedClusters@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "networkPolicy" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-027", title=f"AKS cluster '{name}' missing network policy",
                    description="AKS cluster has no network policy configured. Pods can communicate freely without network segmentation.",
                    severity="MEDIUM", cloud_provider="azure", resource_type="managedClusters",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set networkProfile.networkPolicy to 'azure' or 'calico'.",
                ))
        return results

    # === CHECK 28: Key Vault Soft Delete ===
    def _check_keyvault_soft_delete(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.KeyVault/vaults@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            purge_pos = block.find("enablePurgeProtection")
            if purge_pos == -1 or "false" in block[purge_pos:purge_pos+40]:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-028", title=f"Key Vault '{name}' missing purge protection",
                    description="Key Vault does not have purge protection enabled. Deleted vaults and secrets can be permanently lost.",
                    severity="HIGH", cloud_provider="azure", resource_type="vaults",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set enableSoftDelete: true and enablePurgeProtection: true.",
                ))
        return results

    # === CHECK 29: Storage Minimum TLS ===
    def _check_storage_min_tls(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Storage/storageAccounts@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            tls_match = re.search(r"minimumTlsVersion:\s*'(TLS\d_\d)'", block)
            if tls_match and tls_match.group(1) in ("TLS1_0", "TLS1_1"):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-029", title=f"Storage account '{name}' allows insecure TLS",
                    description=f"Storage account allows {tls_match.group(1)} which has known vulnerabilities.",
                    severity="HIGH", cloud_provider="azure", resource_type="storageAccounts",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set minimumTlsVersion: 'TLS1_2'.",
                ))
            elif "minimumTlsVersion" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-029", title=f"Storage account '{name}' does not enforce minimum TLS",
                    description="Storage account has no minimumTlsVersion set. The default may allow insecure TLS versions.",
                    severity="MEDIUM", cloud_provider="azure", resource_type="storageAccounts",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set minimumTlsVersion: 'TLS1_2'.",
                ))
        return results

    # === CHECK 30: SQL Firewall Allow All ===
    def _check_sql_firewall_allow_all(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Sql/servers/firewallRules@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if re.search(r"startIpAddress:\s*'0\.0\.0\.0'", block) and re.search(r"endIpAddress:\s*'255\.255\.255\.255'", block):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-030", title=f"SQL firewall rule '{name}' allows all IP addresses",
                    description="SQL Server firewall rule allows traffic from all IP addresses (0.0.0.0-255.255.255.255). This exposes the database to the entire internet.",
                    severity="CRITICAL", cloud_provider="azure", resource_type="firewallRules",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Restrict startIpAddress/endIpAddress to specific trusted IPs.",
                ))
        return results

    # === CHECK 31: App Service FTPS ===
    def _check_app_service_ftps(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Web/sites@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "ftpsState" not in block or re.search(r"ftpsState:\s*'AllAllowed'", block):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-031", title=f"App Service '{name}' allows insecure FTP",
                    description="App Service allows plain FTP which transmits credentials in cleartext.",
                    severity="HIGH", cloud_provider="azure", resource_type="sites",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set ftpsState: 'FtpsOnly' or 'Disabled'.",
                ))
        return results

    # === CHECK 32: Private Endpoint ===
    def _check_private_endpoint(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        has_private_endpoint = "Microsoft.Network/privateEndpoints" in content
        sensitive_types = [
            "Microsoft.Sql/servers", "Microsoft.Storage/storageAccounts",
            "Microsoft.KeyVault/vaults", "Microsoft.DocumentDB/databaseAccounts",
        ]
        for stype in sensitive_types:
            if stype in content and not has_private_endpoint:
                short = stype.split("/")[-1]
                ln = self._find_line(lines, short)
                results.append(ScanResult(
                    rule_id="SD-BI-032", title=f"No private endpoint for {short}",
                    description=f"Template contains {short} resources but no Private Endpoints. Data-plane traffic traverses the public internet.",
                    severity="MEDIUM", cloud_provider="azure", resource_type=short,
                    file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation=f"Add Microsoft.Network/privateEndpoints for {short} with appropriate private DNS zone.",
                ))
                break
        return results

    # === CHECK 33: App Service Auth ===
    def _check_app_service_auth(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Web/sites@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "authSettings" not in block and "authSettingsV2" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-033", title=f"App Service '{name}' missing authentication",
                    description="App Service does not configure authSettings. Anonymous users can access the application without identity verification.",
                    severity="MEDIUM", cloud_provider="azure", resource_type="sites",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add authSettingsV2 with an identity provider (AAD recommended).",
                ))
        return results

    # === CHECK 34: SQL Auditing ===
    def _check_sql_auditing(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        has_auditing = "Microsoft.Sql/servers/auditingSettings" in content
        if "Microsoft.Sql/servers" in content and not has_auditing:
            ln = self._find_line(lines, "Microsoft.Sql/servers")
            results.append(ScanResult(
                rule_id="SD-BI-034", title="SQL Server missing auditing configuration",
                description="SQL Server does not have auditing enabled. Database operations are not being logged for compliance and security analysis.",
                severity="HIGH", cloud_provider="azure", resource_type="servers",
                file_path=file_name, line_number=ln,
                code_snippet=self._get_snippet(lines, ln),
                remediation="Add Microsoft.Sql/servers/auditingSettings with state: 'Enabled' and a storage endpoint.",
            ))
        return results

    # === CHECK 35: VM Encryption at Host ===
    def _check_vm_encryption_at_host(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Compute/virtualMachines@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            enc_pos = block.find("encryptionAtHost")
            if enc_pos == -1 or "false" in block[enc_pos:enc_pos+30]:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-035", title=f"VM '{name}' encryption at host not enabled",
                    description="Virtual Machine does not have encryption at host enabled. Temp disks, caches, and data flowing between host and storage are unencrypted.",
                    severity="HIGH", cloud_provider="azure", resource_type="virtualMachines",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set securityProfile.encryptionAtHost: true.",
                ))
        return results

    # === CHECK 36: Application Gateway WAF ===
    def _check_app_gateway_waf(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Network/applicationGateways@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "WAF" not in block and "webApplicationFirewallConfiguration" not in block and "firewallPolicy" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-036", title=f"Application Gateway '{name}' missing WAF",
                    description="Application Gateway does not use WAF_v2 SKU or have WAF policy attached. Web applications are exposed to OWASP Top 10 attacks.",
                    severity="HIGH", cloud_provider="azure", resource_type="applicationGateways",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Use WAF_v2 SKU tier and attach a web application firewall policy.",
                ))
        return results

    # === CHECK 37: Container Instance Public IP ===
    def _check_container_instance_public(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.ContainerInstance/containerGroups@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if re.search(r"(ipAddressType|type):\s*'Public'", block, re.IGNORECASE):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-037", title=f"Container group '{name}' has public IP",
                    description="Container instance group is exposed with a public IP address. This exposes containers directly to the internet.",
                    severity="HIGH", cloud_provider="azure", resource_type="containerGroups",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set ipAddressType: 'Private' and deploy in a virtual network.",
                ))
        return results

    # === CHECK 38: Storage Soft Delete ===
    def _check_storage_soft_delete(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Storage/storageAccounts@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "deleteRetentionPolicy" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-038", title=f"Storage account '{name}' missing blob soft delete",
                    description="Storage account does not configure blob soft delete retention. Accidentally deleted blobs cannot be recovered.",
                    severity="MEDIUM", cloud_provider="azure", resource_type="storageAccounts",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add deleteRetentionPolicy with enabled: true and days: 7 (or more).",
                ))
        return results

    # === CHECK 39: Event Hub Encryption ===
    def _check_event_hub_encryption(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.EventHub/namespaces@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "encryption" not in block and "clusterArmId" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-039", title=f"Event Hub namespace '{name}' missing CMK encryption",
                    description="Event Hub namespace does not use customer-managed key encryption. Data at rest uses only Microsoft-managed keys.",
                    severity="MEDIUM", cloud_provider="azure", resource_type="namespaces",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Configure encryption with a Key Vault-backed customer-managed key.",
                ))
        return results

    # === CHECK 40: Service Bus Premium SKU ===
    def _check_service_bus_premium(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r"resource\s+(\w+)\s+'Microsoft\.ServiceBus/namespaces@[^']*'", content):
            name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if re.search(r"name:\s*'(Basic|Standard)'", block):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-BI-040", title=f"Service Bus '{name}' not using Premium SKU",
                    description="Service Bus namespace uses Basic/Standard SKU which lacks VNet integration, CMK encryption, and zone redundancy.",
                    severity="MEDIUM", cloud_provider="azure", resource_type="namespaces",
                    resource_name=name, file_path=file_name, line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Use Premium SKU for production workloads requiring encryption and network isolation.",
                ))
        return results

    def _find_block_end(self, content: str, start: int) -> int:
        depth = 0
        i = start
        while i < len(content):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return len(content)

"""GCP Cloud Connector — discovers GCS, Firewall, Cloud SQL, IAM, GCE resources."""

from __future__ import annotations

import json
import logging

from app.services.cloud_connectors.base import (
    BaseCloudConnector, DiscoveredResource, demo_data_enabled, require_modules, sdk_missing,
)

logger = logging.getLogger(__name__)


class GCPConnector(BaseCloudConnector):
    PROVIDER = "gcp"
    SUPPORTED_RESOURCE_TYPES = [
        "google_storage_bucket",
        "google_compute_firewall",
        "google_sql_database_instance",
        "google_compute_instance",
        "google_project_iam_binding",
    ]

    def _get_credentials(self):
        require_modules("google.oauth2", "google.cloud.storage", "googleapiclient.discovery")
        from google.oauth2 import service_account
        sa_info = self.credentials.get("service_account_json", {})
        if isinstance(sa_info, str):
            sa_info = json.loads(sa_info)
        return service_account.Credentials.from_service_account_info(
            sa_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )

    @property
    def _project_id(self) -> str:
        return self.credentials.get("project_id", "")

    async def test_connection(self) -> dict:
        try:
            cred = self._get_credentials()
            from googleapiclient.discovery import build
            service = build("cloudresourcemanager", "v1", credentials=cred)
            project = service.projects().get(projectId=self._project_id).execute()
            return {"status": "connected", "details": {
                "project_id": project.get("projectId"),
                "project_name": project.get("name"),
            }}
        except ImportError:
            return {"status": "error", "error": str(sdk_missing("GCP"))}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def discover(self, resource_types: list[str] | None = None) -> list[DiscoveredResource]:
        types_to_discover = self._filter_types(resource_types)
        resources: list[DiscoveredResource] = []

        try:
            cred = self._get_credentials()
        except ImportError:
            if demo_data_enabled():
                logger.warning("google SDK not installed — DEMO_DATA_ENABLED, returning sample resources")
                return self._simulated_resources()
            raise sdk_missing("GCP")
        except Exception as e:
            logger.error(f"GCP credential error: {e}")
            raise

        project = self._project_id

        if "google_storage_bucket" in types_to_discover:
            resources.extend(self._discover_gcs_buckets(cred, project))
        if "google_compute_firewall" in types_to_discover:
            resources.extend(self._discover_firewall_rules(cred, project))
        if "google_sql_database_instance" in types_to_discover:
            resources.extend(self._discover_sql_instances(cred, project))
        if "google_compute_instance" in types_to_discover:
            resources.extend(self._discover_compute_instances(cred, project))
        if "google_project_iam_binding" in types_to_discover:
            resources.extend(self._discover_iam_bindings(cred, project))

        logger.info(f"GCP discovery complete: {len(resources)} resources found")
        return resources

    # ── GCS Buckets ──────────────────────────────────────────────────────────

    def _discover_gcs_buckets(self, cred, project: str) -> list[DiscoveredResource]:
        results = []
        try:
            from google.cloud import storage
            client = storage.Client(project=project, credentials=cred)
            for bucket in client.list_buckets():
                iam_config = getattr(bucket, "iam_configuration", None)
                config = {
                    "name": bucket.name,
                    "location": bucket.location,
                    "storage_class": bucket.storage_class,
                    "versioning_enabled": bucket.versioning_enabled,
                    "uniform_bucket_level_access": (
                        iam_config.uniform_bucket_level_access_enabled
                        if iam_config else False
                    ),
                    "public_access_prevention": getattr(iam_config, "public_access_prevention", "inherited"),
                    "default_encryption_key": bucket.default_kms_key_name,
                    "logging_enabled": bucket.get_logging() is not None,
                    "retention_policy": bool(bucket.retention_policy_effective_time),
                    "labels": dict(bucket.labels) if bucket.labels else {},
                }
                results.append(DiscoveredResource(
                    provider="gcp", resource_type="google_storage_bucket",
                    resource_id=f"projects/{project}/buckets/{bucket.name}",
                    resource_name=bucket.name, region=bucket.location, account_id=project,
                    config=config, tags=dict(bucket.labels) if bucket.labels else {},
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"GCS bucket discovery failed: {e}")
        return results

    # ── Firewall Rules ───────────────────────────────────────────────────────

    def _discover_firewall_rules(self, cred, project: str) -> list[DiscoveredResource]:
        results = []
        try:
            from googleapiclient.discovery import build
            compute = build("compute", "v1", credentials=cred)
            req = compute.firewalls().list(project=project)
            while req:
                resp = req.execute()
                for fw in resp.get("items", []):
                    allowed = fw.get("allowed", [])
                    source_ranges = fw.get("sourceRanges", [])

                    config = {
                        "name": fw["name"],
                        "network": fw.get("network", "").split("/")[-1],
                        "direction": fw.get("direction", "INGRESS"),
                        "priority": fw.get("priority"),
                        "source_ranges": source_ranges,
                        "allowed": [
                            {"protocol": a.get("IPProtocol"), "ports": a.get("ports", [])}
                            for a in allowed
                        ],
                        "allows_all_from_internet": (
                            "0.0.0.0/0" in source_ranges
                            and any(a.get("IPProtocol") == "all" for a in allowed)
                        ),
                        "allows_ssh_from_internet": (
                            "0.0.0.0/0" in source_ranges
                            and any(
                                a.get("IPProtocol") == "tcp"
                                and "22" in a.get("ports", [])
                                for a in allowed
                            )
                        ),
                        "disabled": fw.get("disabled", False),
                    }
                    results.append(DiscoveredResource(
                        provider="gcp", resource_type="google_compute_firewall",
                        resource_id=fw.get("selfLink", f"projects/{project}/global/firewalls/{fw['name']}"),
                        resource_name=fw["name"], region="global", account_id=project,
                        config=config,
                    ))
                req = compute.firewalls().list_next(previous_request=req, previous_response=resp)
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"GCP firewall discovery failed: {e}")
        return results

    # ── Cloud SQL ────────────────────────────────────────────────────────────

    def _discover_sql_instances(self, cred, project: str) -> list[DiscoveredResource]:
        results = []
        try:
            from googleapiclient.discovery import build
            sqladmin = build("sqladmin", "v1beta4", credentials=cred)
            resp = sqladmin.instances().list(project=project).execute()
            for inst in resp.get("items", []):
                settings = inst.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})
                backup_config = settings.get("backupConfiguration", {})

                config = {
                    "name": inst["name"],
                    "database_version": inst.get("databaseVersion"),
                    "region": inst.get("region"),
                    "tier": settings.get("tier"),
                    "availability_type": settings.get("availabilityType", "ZONAL"),
                    "require_ssl": ip_config.get("requireSsl", False),
                    "ipv4_enabled": ip_config.get("ipv4Enabled", True),
                    "authorized_networks": [
                        n.get("value") for n in ip_config.get("authorizedNetworks", [])
                    ],
                    "publicly_accessible": ip_config.get("ipv4Enabled", True)
                        and len(ip_config.get("authorizedNetworks", [])) > 0,
                    "backup_enabled": backup_config.get("enabled", False),
                    "point_in_time_recovery_enabled": backup_config.get("pointInTimeRecoveryEnabled", False),
                    "deletion_protection": settings.get("deletionProtectionEnabled", False),
                    "maintenance_window": bool(settings.get("maintenanceWindow")),
                }
                results.append(DiscoveredResource(
                    provider="gcp", resource_type="google_sql_database_instance",
                    resource_id=f"projects/{project}/instances/{inst['name']}",
                    resource_name=inst["name"], region=inst.get("region", "unknown"), account_id=project,
                    config=config,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"GCP SQL discovery failed: {e}")
        return results

    # ── Compute Instances ────────────────────────────────────────────────────

    def _discover_compute_instances(self, cred, project: str) -> list[DiscoveredResource]:
        results = []
        try:
            from googleapiclient.discovery import build
            compute = build("compute", "v1", credentials=cred)
            req = compute.instances().aggregatedList(project=project)
            resp = req.execute()
            for zone_group in resp.get("items", {}).values():
                for inst in zone_group.get("instances", []):
                    zone = inst.get("zone", "").split("/")[-1]
                    region = "-".join(zone.split("-")[:-1])

                    # Check for external IP
                    has_external_ip = False
                    for iface in inst.get("networkInterfaces", []):
                        if iface.get("accessConfigs"):
                            has_external_ip = True

                    config = {
                        "name": inst["name"],
                        "machine_type": inst.get("machineType", "").split("/")[-1],
                        "zone": zone,
                        "status": inst.get("status"),
                        "has_external_ip": has_external_ip,
                        "can_ip_forward": inst.get("canIpForward", False),
                        "deletion_protection": inst.get("deletionProtection", False),
                        "shielded_instance_config": bool(inst.get("shieldedInstanceConfig")),
                        "service_accounts": [
                            {"email": sa.get("email"), "scopes": sa.get("scopes", [])}
                            for sa in inst.get("serviceAccounts", [])
                        ],
                        "metadata_items": [m.get("key") for m in inst.get("metadata", {}).get("items", [])],
                        "labels": inst.get("labels", {}),
                    }
                    results.append(DiscoveredResource(
                        provider="gcp", resource_type="google_compute_instance",
                        resource_id=inst.get("selfLink", f"projects/{project}/zones/{zone}/instances/{inst['name']}"),
                        resource_name=inst["name"], region=region, account_id=project,
                        config=config, tags=inst.get("labels", {}),
                    ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"GCP compute instance discovery failed: {e}")
        return results

    # ── IAM Bindings ─────────────────────────────────────────────────────────

    def _discover_iam_bindings(self, cred, project: str) -> list[DiscoveredResource]:
        results = []
        try:
            from googleapiclient.discovery import build
            crm = build("cloudresourcemanager", "v1", credentials=cred)
            policy = crm.projects().getIamPolicy(resource=project, body={}).execute()
            for binding in policy.get("bindings", []):
                role = binding["role"]
                members = binding.get("members", [])
                config = {
                    "role": role,
                    "members": members,
                    "member_count": len(members),
                    "has_all_users": "allUsers" in members,
                    "has_all_authenticated_users": "allAuthenticatedUsers" in members,
                    "is_owner_role": role == "roles/owner",
                    "is_editor_role": role == "roles/editor",
                    "is_privileged": role in ("roles/owner", "roles/editor", "roles/iam.securityAdmin"),
                }
                results.append(DiscoveredResource(
                    provider="gcp", resource_type="google_project_iam_binding",
                    resource_id=f"projects/{project}/iamPolicy/{role}",
                    resource_name=role.split("/")[-1], region="global", account_id=project,
                    config=config,
                ))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"GCP IAM discovery failed: {e}")
        return results

    # ── Simulated ─────────────────────────────────────────────────────────────

    def _simulated_resources(self) -> list[DiscoveredResource]:
        project = self._project_id or "my-gcp-project"
        return [
            DiscoveredResource(
                provider="gcp", resource_type="google_storage_bucket",
                resource_id=f"projects/{project}/buckets/prod-data-{project}",
                resource_name=f"prod-data-{project}", region="US", account_id=project,
                config={
                    "name": f"prod-data-{project}",
                    "storage_class": "STANDARD",
                    "versioning_enabled": True,
                    "uniform_bucket_level_access": True,
                    "public_access_prevention": "enforced",
                    "logging_enabled": True,
                },
            ),
            DiscoveredResource(
                provider="gcp", resource_type="google_storage_bucket",
                resource_id=f"projects/{project}/buckets/dev-temp-{project}",
                resource_name=f"dev-temp-{project}", region="US", account_id=project,
                config={
                    "name": f"dev-temp-{project}",
                    "storage_class": "STANDARD",
                    "versioning_enabled": False,
                    "uniform_bucket_level_access": False,
                    "public_access_prevention": "inherited",
                    "logging_enabled": False,
                },
            ),
            DiscoveredResource(
                provider="gcp", resource_type="google_compute_firewall",
                resource_id=f"projects/{project}/global/firewalls/allow-all-ingress",
                resource_name="allow-all-ingress", region="global", account_id=project,
                config={
                    "name": "allow-all-ingress", "network": "default",
                    "direction": "INGRESS", "priority": 1000,
                    "source_ranges": ["0.0.0.0/0"],
                    "allowed": [{"protocol": "tcp", "ports": ["22", "3389"]}],
                    "allows_all_from_internet": False,
                    "allows_ssh_from_internet": True,
                    "disabled": False,
                },
            ),
            DiscoveredResource(
                provider="gcp", resource_type="google_sql_database_instance",
                resource_id=f"projects/{project}/instances/prod-sql-main",
                resource_name="prod-sql-main", region="us-central1", account_id=project,
                config={
                    "name": "prod-sql-main", "database_version": "POSTGRES_15",
                    "tier": "db-custom-4-16384", "availability_type": "REGIONAL",
                    "require_ssl": False, "ipv4_enabled": True,
                    "authorized_networks": ["0.0.0.0/0"],
                    "publicly_accessible": True,
                    "backup_enabled": True, "point_in_time_recovery_enabled": False,
                    "deletion_protection": False,
                },
            ),
            DiscoveredResource(
                provider="gcp", resource_type="google_project_iam_binding",
                resource_id=f"projects/{project}/iamPolicy/roles/editor",
                resource_name="editor", region="global", account_id=project,
                config={
                    "role": "roles/editor",
                    "members": ["user:dev@example.com", "allAuthenticatedUsers"],
                    "member_count": 2,
                    "has_all_users": False,
                    "has_all_authenticated_users": True,
                    "is_editor_role": True, "is_privileged": True,
                },
            ),
        ]

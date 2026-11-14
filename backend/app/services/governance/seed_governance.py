"""Seed realistic cloud resources and policy-as-code conditions for the governance engine.

Run once after migration 021 to populate the system with demo data.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_resource import CloudResource
from app.models.governance import SecurityPolicy

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# Cloud Resources — realistic configs that policies will evaluate
# ─────────────────────────────────────────────────────────────────────

SEED_RESOURCES = [
    # ── AWS S3 Buckets ──
    {
        "provider": "aws",
        "resource_type": "aws_s3_bucket",
        "resource_id": "arn:aws:s3:::prod-app-data-bucket",
        "resource_name": "prod-app-data-bucket",
        "region": "us-east-1",
        "account_id": "123456789012",
        "config": {
            "bucket_name": "prod-app-data-bucket",
            "versioning": {"status": "Enabled", "mfa_delete": False},
            "encryption": {
                "sse_algorithm": "aws:kms",
                "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
            },
            "public_access_block": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
            "logging": {"target_bucket": "prod-access-logs", "target_prefix": "s3/"},
            "lifecycle_rules": [
                {"id": "archive-90d", "status": "Enabled", "transition_days": 90, "storage_class": "GLACIER"}
            ],
            "tags": {"Environment": "production", "Team": "platform", "CostCenter": "CC-1001"},
        },
        "tags": {"Environment": "production", "Team": "platform"},
    },
    {
        "provider": "aws",
        "resource_type": "aws_s3_bucket",
        "resource_id": "arn:aws:s3:::dev-temp-uploads",
        "resource_name": "dev-temp-uploads",
        "region": "us-east-1",
        "account_id": "123456789012",
        "config": {
            "bucket_name": "dev-temp-uploads",
            "versioning": {"status": "Suspended", "mfa_delete": False},
            "encryption": {"sse_algorithm": "AES256", "kms_key_id": None},
            "public_access_block": {
                "block_public_acls": False,
                "block_public_policy": False,
                "ignore_public_acls": False,
                "restrict_public_buckets": False,
            },
            "logging": None,
            "lifecycle_rules": [],
            "tags": {"Environment": "development"},
        },
        "tags": {"Environment": "development"},
    },
    {
        "provider": "aws",
        "resource_type": "aws_s3_bucket",
        "resource_id": "arn:aws:s3:::marketing-website-assets",
        "resource_name": "marketing-website-assets",
        "region": "us-west-2",
        "account_id": "123456789012",
        "config": {
            "bucket_name": "marketing-website-assets",
            "versioning": {"status": "Enabled", "mfa_delete": False},
            "encryption": {"sse_algorithm": "AES256", "kms_key_id": None},
            "public_access_block": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
            "logging": {"target_bucket": "prod-access-logs", "target_prefix": "marketing/"},
            "tags": {"Environment": "production", "Team": "marketing"},
        },
        "tags": {"Environment": "production", "Team": "marketing"},
    },

    # ── AWS Security Groups ──
    {
        "provider": "aws",
        "resource_type": "aws_security_group",
        "resource_id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123def456",
        "resource_name": "prod-web-sg",
        "region": "us-east-1",
        "account_id": "123456789012",
        "config": {
            "group_name": "prod-web-sg",
            "description": "Production web servers",
            "vpc_id": "vpc-0abc123",
            "ingress_rules": [
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"], "description": "HTTPS"},
                {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"], "description": "HTTP"},
            ],
            "egress_rules": [
                {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"], "description": "All outbound"},
            ],
            "tags": {"Environment": "production", "Role": "web"},
        },
        "tags": {"Environment": "production", "Role": "web"},
    },
    {
        "provider": "aws",
        "resource_type": "aws_security_group",
        "resource_id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0bad567bad890",
        "resource_name": "legacy-open-sg",
        "region": "us-east-1",
        "account_id": "123456789012",
        "config": {
            "group_name": "legacy-open-sg",
            "description": "Legacy open security group",
            "vpc_id": "vpc-0abc123",
            "ingress_rules": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"], "description": "SSH from anywhere"},
                {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_blocks": ["0.0.0.0/0"], "description": "RDP from anywhere"},
                {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"], "description": "All traffic"},
            ],
            "egress_rules": [
                {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]},
            ],
            "tags": {"Environment": "production", "Role": "legacy"},
        },
        "tags": {"Environment": "production", "Role": "legacy"},
    },

    # ── AWS RDS Instances ──
    {
        "provider": "aws",
        "resource_type": "aws_rds_instance",
        "resource_id": "arn:aws:rds:us-east-1:123456789012:db:prod-main-db",
        "resource_name": "prod-main-db",
        "region": "us-east-1",
        "account_id": "123456789012",
        "config": {
            "db_instance_identifier": "prod-main-db",
            "engine": "postgres",
            "engine_version": "15.4",
            "instance_class": "db.r6g.xlarge",
            "multi_az": True,
            "storage_encrypted": True,
            "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/rds-key-1234",
            "publicly_accessible": False,
            "backup_retention_period": 30,
            "deletion_protection": True,
            "auto_minor_version_upgrade": True,
            "performance_insights_enabled": True,
            "iam_database_authentication_enabled": True,
            "monitoring_interval": 60,
            "tags": {"Environment": "production", "Team": "data"},
        },
        "tags": {"Environment": "production", "Team": "data"},
    },
    {
        "provider": "aws",
        "resource_type": "aws_rds_instance",
        "resource_id": "arn:aws:rds:us-east-1:123456789012:db:staging-analytics-db",
        "resource_name": "staging-analytics-db",
        "region": "us-east-1",
        "account_id": "123456789012",
        "config": {
            "db_instance_identifier": "staging-analytics-db",
            "engine": "mysql",
            "engine_version": "8.0.35",
            "instance_class": "db.t3.medium",
            "multi_az": False,
            "storage_encrypted": False,
            "kms_key_id": None,
            "publicly_accessible": True,
            "backup_retention_period": 1,
            "deletion_protection": False,
            "auto_minor_version_upgrade": False,
            "performance_insights_enabled": False,
            "iam_database_authentication_enabled": False,
            "monitoring_interval": 0,
            "tags": {"Environment": "staging"},
        },
        "tags": {"Environment": "staging"},
    },

    # ── AWS IAM ──
    {
        "provider": "aws",
        "resource_type": "aws_iam_user",
        "resource_id": "arn:aws:iam::123456789012:user/deploy-bot",
        "resource_name": "deploy-bot",
        "region": "global",
        "account_id": "123456789012",
        "config": {
            "user_name": "deploy-bot",
            "mfa_enabled": False,
            "access_keys": [
                {"key_id": "AKIA1234ABCD", "status": "Active", "age_days": 180},
                {"key_id": "AKIA5678EFGH", "status": "Active", "age_days": 45},
            ],
            "inline_policies": ["DeployPolicy"],
            "attached_policies": [
                "arn:aws:iam::aws:policy/AdministratorAccess",
            ],
            "last_activity": "2026-11-08T10:30:00Z",
            "tags": {},
        },
        "tags": {},
    },
    {
        "provider": "aws",
        "resource_type": "aws_iam_user",
        "resource_id": "arn:aws:iam::123456789012:user/jane.doe",
        "resource_name": "jane.doe",
        "region": "global",
        "account_id": "123456789012",
        "config": {
            "user_name": "jane.doe",
            "mfa_enabled": True,
            "access_keys": [
                {"key_id": "AKIA9999ZZZZ", "status": "Active", "age_days": 30},
            ],
            "inline_policies": [],
            "attached_policies": [
                "arn:aws:iam::aws:policy/ReadOnlyAccess",
            ],
            "last_activity": "2026-11-09T08:00:00Z",
            "tags": {"Department": "Engineering"},
        },
        "tags": {"Department": "Engineering"},
    },

    # ── Azure Resources ──
    {
        "provider": "azure",
        "resource_type": "azurerm_storage_account",
        "resource_id": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/proddata01",
        "resource_name": "proddata01",
        "region": "eastus",
        "account_id": "sub-123",
        "config": {
            "account_name": "proddata01",
            "account_tier": "Standard",
            "account_replication_type": "GRS",
            "min_tls_version": "TLS1_2",
            "allow_blob_public_access": False,
            "enable_https_traffic_only": True,
            "network_rules": {
                "default_action": "Deny",
                "ip_rules": ["10.0.0.0/8"],
                "virtual_network_subnet_ids": ["subnet-prod-01"],
            },
            "encryption": {"services": {"blob": True, "file": True, "queue": True, "table": True}},
            "tags": {"Environment": "production", "ManagedBy": "Terraform"},
        },
        "tags": {"Environment": "production", "ManagedBy": "Terraform"},
    },
    {
        "provider": "azure",
        "resource_type": "azurerm_storage_account",
        "resource_id": "/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.Storage/storageAccounts/devtemp99",
        "resource_name": "devtemp99",
        "region": "eastus",
        "account_id": "sub-123",
        "config": {
            "account_name": "devtemp99",
            "account_tier": "Standard",
            "account_replication_type": "LRS",
            "min_tls_version": "TLS1_0",
            "allow_blob_public_access": True,
            "enable_https_traffic_only": False,
            "network_rules": {
                "default_action": "Allow",
                "ip_rules": [],
                "virtual_network_subnet_ids": [],
            },
            "encryption": {"services": {"blob": True, "file": False, "queue": False, "table": False}},
            "tags": {"Environment": "development"},
        },
        "tags": {"Environment": "development"},
    },

    # ── GCP Resources ──
    {
        "provider": "gcp",
        "resource_type": "google_compute_instance",
        "resource_id": "projects/my-project/zones/us-central1-a/instances/prod-api-server",
        "resource_name": "prod-api-server",
        "region": "us-central1",
        "account_id": "my-project",
        "config": {
            "name": "prod-api-server",
            "machine_type": "e2-standard-4",
            "zone": "us-central1-a",
            "can_ip_forward": False,
            "shielded_instance_config": {
                "enable_secure_boot": True,
                "enable_vtpm": True,
                "enable_integrity_monitoring": True,
            },
            "service_account": {
                "email": "prod-api@my-project.iam.gserviceaccount.com",
                "scopes": ["cloud-platform"],
            },
            "network_interfaces": [
                {"network": "prod-vpc", "subnetwork": "prod-subnet", "access_config": None}
            ],
            "metadata": {"enable-oslogin": "TRUE", "block-project-ssh-keys": "TRUE"},
            "labels": {"env": "production", "team": "platform"},
        },
        "tags": {"env": "production", "team": "platform"},
    },
    {
        "provider": "gcp",
        "resource_type": "google_compute_instance",
        "resource_id": "projects/my-project/zones/us-central1-a/instances/dev-test-box",
        "resource_name": "dev-test-box",
        "region": "us-central1",
        "account_id": "my-project",
        "config": {
            "name": "dev-test-box",
            "machine_type": "e2-medium",
            "zone": "us-central1-a",
            "can_ip_forward": True,
            "shielded_instance_config": {
                "enable_secure_boot": False,
                "enable_vtpm": False,
                "enable_integrity_monitoring": False,
            },
            "service_account": {
                "email": "default@my-project.iam.gserviceaccount.com",
                "scopes": ["cloud-platform"],
            },
            "network_interfaces": [
                {"network": "default", "subnetwork": "default", "access_config": {"nat_ip": "35.192.0.1"}}
            ],
            "metadata": {},
            "labels": {"env": "dev"},
        },
        "tags": {"env": "dev"},
    },
]


# ─────────────────────────────────────────────────────────────────────
# Policies with REAL evaluatable conditions (Policy-as-Code)
# ─────────────────────────────────────────────────────────────────────

SEED_POLICIES = [
    {
        "name": "S3 Buckets Must Block Public Access",
        "description": "All S3 buckets must have all four public access block settings enabled to prevent accidental data exposure.",
        "policy_type": "data_protection",
        "severity": "critical",
        "rules": {
            "resource_types": ["aws_s3_bucket"],
            "condition": {
                "all": [
                    {"field": "config.public_access_block.block_public_acls", "op": "eq", "value": True},
                    {"field": "config.public_access_block.block_public_policy", "op": "eq", "value": True},
                    {"field": "config.public_access_block.ignore_public_acls", "op": "eq", "value": True},
                    {"field": "config.public_access_block.restrict_public_buckets", "op": "eq", "value": True},
                ]
            },
            "remediation": {
                "description": "Enable all S3 Block Public Access settings on the bucket",
                "auto_fixable": True,
                "fix_action": "s3:put_public_access_block",
            },
        },
    },
    {
        "name": "S3 Buckets Must Have Encryption Enabled",
        "description": "All S3 buckets must have server-side encryption using KMS or AES-256.",
        "policy_type": "encryption",
        "severity": "high",
        "rules": {
            "resource_types": ["aws_s3_bucket"],
            "condition": {
                "any": [
                    {"field": "config.encryption.sse_algorithm", "op": "eq", "value": "aws:kms"},
                    {"field": "config.encryption.sse_algorithm", "op": "eq", "value": "AES256"},
                ]
            },
            "remediation": {
                "description": "Enable default server-side encryption on the S3 bucket using KMS or AES-256",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "S3 Buckets Must Have Versioning Enabled",
        "description": "S3 buckets must have versioning enabled for data protection and recovery.",
        "policy_type": "data_protection",
        "severity": "medium",
        "rules": {
            "resource_types": ["aws_s3_bucket"],
            "condition": {
                "all": [
                    {"field": "config.versioning.status", "op": "eq", "value": "Enabled"},
                ]
            },
            "remediation": {
                "description": "Enable bucket versioning to protect against accidental deletion",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "S3 Buckets Must Have Access Logging",
        "description": "S3 buckets must have server access logging enabled for audit trails.",
        "policy_type": "logging",
        "severity": "medium",
        "rules": {
            "resource_types": ["aws_s3_bucket"],
            "condition": {
                "all": [
                    {"field": "config.logging", "op": "exists", "value": True},
                    {"field": "config.logging.target_bucket", "op": "is_not_empty", "value": None},
                ]
            },
            "remediation": {
                "description": "Enable S3 server access logging and specify a target bucket",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "No Unrestricted SSH/RDP Access in Security Groups",
        "description": "Security groups must not allow SSH (22) or RDP (3389) from 0.0.0.0/0.",
        "policy_type": "network",
        "severity": "critical",
        "rules": {
            "resource_types": ["aws_security_group"],
            "condition": {
                "none": [
                    {
                        "all": [
                            {"field": "config.ingress_rules[*].from_port", "op": "contains", "value": 22},
                            {"field": "config.ingress_rules[*].cidr_blocks", "op": "contains", "value": ["0.0.0.0/0"]},
                        ]
                    },
                ]
            },
            "remediation": {
                "description": "Restrict SSH/RDP access to specific CIDR ranges instead of 0.0.0.0/0",
                "auto_fixable": False,
            },
        },
    },
    {
        "name": "RDS Instances Must Be Encrypted",
        "description": "All RDS database instances must have storage encryption enabled.",
        "policy_type": "encryption",
        "severity": "critical",
        "rules": {
            "resource_types": ["aws_rds_instance"],
            "condition": {
                "all": [
                    {"field": "config.storage_encrypted", "op": "eq", "value": True},
                ]
            },
            "remediation": {
                "description": "Enable storage encryption on the RDS instance (requires recreation for existing instances)",
                "auto_fixable": False,
            },
        },
    },
    {
        "name": "RDS Must Not Be Publicly Accessible",
        "description": "RDS instances must not be publicly accessible from the internet.",
        "policy_type": "network",
        "severity": "critical",
        "rules": {
            "resource_types": ["aws_rds_instance"],
            "condition": {
                "all": [
                    {"field": "config.publicly_accessible", "op": "eq", "value": False},
                ]
            },
            "remediation": {
                "description": "Disable public accessibility on the RDS instance",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "RDS Must Have Multi-AZ Enabled",
        "description": "Production RDS instances must have Multi-AZ deployment for high availability.",
        "policy_type": "availability",
        "severity": "high",
        "rules": {
            "resource_types": ["aws_rds_instance"],
            "condition": {
                "all": [
                    {"field": "config.multi_az", "op": "eq", "value": True},
                ]
            },
            "remediation": {
                "description": "Enable Multi-AZ deployment for high availability",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "RDS Must Have Adequate Backup Retention",
        "description": "RDS instances must retain backups for at least 7 days.",
        "policy_type": "data_protection",
        "severity": "high",
        "rules": {
            "resource_types": ["aws_rds_instance"],
            "condition": {
                "all": [
                    {"field": "config.backup_retention_period", "op": "gte", "value": 7},
                ]
            },
            "remediation": {
                "description": "Increase backup retention period to at least 7 days",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "IAM Users Must Have MFA Enabled",
        "description": "All IAM users must have multi-factor authentication enabled.",
        "policy_type": "access_control",
        "severity": "critical",
        "rules": {
            "resource_types": ["aws_iam_user"],
            "condition": {
                "all": [
                    {"field": "config.mfa_enabled", "op": "eq", "value": True},
                ]
            },
            "remediation": {
                "description": "Enable MFA on the IAM user account",
                "auto_fixable": False,
            },
        },
    },
    {
        "name": "IAM Users Must Not Have AdministratorAccess",
        "description": "IAM users should not have the AdministratorAccess managed policy attached directly.",
        "policy_type": "access_control",
        "severity": "critical",
        "rules": {
            "resource_types": ["aws_iam_user"],
            "condition": {
                "all": [
                    {"field": "config.attached_policies", "op": "not_contains", "value": "arn:aws:iam::aws:policy/AdministratorAccess"},
                ]
            },
            "remediation": {
                "description": "Remove AdministratorAccess and assign least-privilege policies",
                "auto_fixable": False,
            },
        },
    },
    {
        "name": "IAM Access Keys Must Be Rotated Within 90 Days",
        "description": "Active IAM access keys must not be older than 90 days.",
        "policy_type": "access_control",
        "severity": "high",
        "rules": {
            "resource_types": ["aws_iam_user"],
            "condition": {
                "none": [
                    {
                        "all": [
                            {"field": "config.access_keys[*].status", "op": "contains", "value": "Active"},
                            {"field": "config.access_keys[*].age_days", "op": "contains", "value": 91},
                        ]
                    },
                ]
            },
            "remediation": {
                "description": "Rotate access keys that are older than 90 days",
                "auto_fixable": False,
            },
        },
    },
    {
        "name": "Azure Storage Must Enforce HTTPS",
        "description": "Azure storage accounts must require HTTPS-only traffic.",
        "policy_type": "encryption",
        "severity": "high",
        "rules": {
            "resource_types": ["azurerm_storage_account"],
            "condition": {
                "all": [
                    {"field": "config.enable_https_traffic_only", "op": "eq", "value": True},
                    {"field": "config.min_tls_version", "op": "in", "value": ["TLS1_2", "TLS1_3"]},
                ]
            },
            "remediation": {
                "description": "Enable HTTPS-only traffic and set minimum TLS version to 1.2",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "Azure Storage Must Deny Public Network Access",
        "description": "Azure storage accounts must use network rules with default deny.",
        "policy_type": "network",
        "severity": "high",
        "rules": {
            "resource_types": ["azurerm_storage_account"],
            "condition": {
                "all": [
                    {"field": "config.network_rules.default_action", "op": "eq", "value": "Deny"},
                    {"field": "config.allow_blob_public_access", "op": "eq", "value": False},
                ]
            },
            "remediation": {
                "description": "Set network default action to Deny and disable public blob access",
                "auto_fixable": True,
            },
        },
    },
    {
        "name": "GCP Compute Instances Must Enable Shielded VM",
        "description": "GCP compute instances must have Shielded VM features enabled (secure boot, vTPM, integrity monitoring).",
        "policy_type": "compute",
        "severity": "high",
        "rules": {
            "resource_types": ["google_compute_instance"],
            "condition": {
                "all": [
                    {"field": "config.shielded_instance_config.enable_secure_boot", "op": "eq", "value": True},
                    {"field": "config.shielded_instance_config.enable_vtpm", "op": "eq", "value": True},
                    {"field": "config.shielded_instance_config.enable_integrity_monitoring", "op": "eq", "value": True},
                ]
            },
            "remediation": {
                "description": "Enable all Shielded VM features on the compute instance",
                "auto_fixable": False,
            },
        },
    },
    {
        "name": "GCP Compute Must Not Have Public IP",
        "description": "GCP compute instances should not have external IP addresses assigned.",
        "policy_type": "network",
        "severity": "high",
        "rules": {
            "resource_types": ["google_compute_instance"],
            "condition": {
                "all": [
                    {"field": "config.network_interfaces[0].access_config", "op": "not_exists", "value": None},
                ]
            },
            "remediation": {
                "description": "Remove external IP address and use IAP or Cloud NAT for internet access",
                "auto_fixable": True,
            },
        },
    },
]


async def _remove_sample_resources(db: AsyncSession, organization_id: int) -> int:

    from app.models.governance import PolicyViolation

    rows = (await db.execute(
        select(CloudResource).where(
            CloudResource.organization_id == organization_id,
            CloudResource.source == "seed",
        )
    )).scalars().all()
    if not rows:
        return 0
    resource_ids = [r.resource_id for r in rows]
    violations = (await db.execute(
        select(PolicyViolation).where(
            PolicyViolation.organization_id == organization_id,
            PolicyViolation.resource_id.in_(resource_ids),
            PolicyViolation.status.in_(("open", "accepted")),
        )
    )).scalars().all()
    for v in violations:
        v.status = "resolved"
        v.resolved_at = datetime.now(timezone.utc)
    for r in rows:
        await db.delete(r)
    return len(rows)


async def seed_governance_data(db: AsyncSession, organization_id: int) -> dict:
    """Load the built-in cloud-resource policies for an organization.

    Sample cloud resources are only inserted when DEMO_DATA_ENABLED is set.

    Returns summary of what was created.
    """
    from app.core.config import settings

    stats = {"resources_created": 0, "resources_removed": 0, "policies_created": 0, "policies_updated": 0}

    if not settings.DEMO_DATA_ENABLED:
        # Sample resources are fiction; outside demo mode, remove any left by
        # earlier versions together with the violations raised against them.
        stats["resources_removed"] = await _remove_sample_resources(db, organization_id)

    # ── Sample cloud resources (demo installations only) ──
    for resource_data in (SEED_RESOURCES if settings.DEMO_DATA_ENABLED else []):
        # Check if already exists
        existing = await db.execute(
            select(CloudResource).where(
                CloudResource.organization_id == organization_id,
                CloudResource.provider == resource_data["provider"],
                CloudResource.resource_id == resource_data["resource_id"],
            )
        )
        if existing.scalar_one_or_none():
            continue

        resource = CloudResource(
            organization_id=organization_id,
            provider=resource_data["provider"],
            resource_type=resource_data["resource_type"],
            resource_id=resource_data["resource_id"],
            resource_name=resource_data["resource_name"],
            region=resource_data.get("region"),
            account_id=resource_data.get("account_id"),
            config=resource_data["config"],
            tags=resource_data.get("tags", {}),
            source="seed",
        )
        db.add(resource)
        stats["resources_created"] += 1

    # ── Seed or Update Policies with real conditions ──
    for policy_data in SEED_POLICIES:
        existing = await db.execute(
            select(SecurityPolicy).where(
                SecurityPolicy.organization_id == organization_id,
                SecurityPolicy.name == policy_data["name"],
            )
        )
        policy = existing.scalar_one_or_none()

        if policy:
            # Update with real conditions
            policy.rules = policy_data["rules"]
            policy.description = policy_data["description"]
            policy.severity = policy_data["severity"]
            stats["policies_updated"] += 1
        else:
            policy = SecurityPolicy(
                organization_id=organization_id,
                name=policy_data["name"],
                description=policy_data["description"],
                policy_type=policy_data["policy_type"],
                severity=policy_data["severity"],
                rules=policy_data["rules"],
                is_enabled=True,
                is_enforced=False,
                is_builtin=True,
            )
            db.add(policy)
            stats["policies_created"] += 1

    await db.commit()

    logger.info(
        f"Governance seed complete for org {organization_id}: "
        f"{stats['resources_created']} resources, "
        f"{stats['policies_created']} new policies, "
        f"{stats['policies_updated']} updated policies"
    )
    return stats

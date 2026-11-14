"""AWS Cloud Connector — discovers S3, EC2 SGs, RDS, IAM, Lambda, EBS resources via boto3."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.services.cloud_connectors.aws_extra import (
    EXTRA_RESOURCE_TYPES, GLOBAL_COLLECTORS, REGIONAL_COLLECTORS,
)
from app.services.cloud_connectors.base import (
    BaseCloudConnector, DiscoveredResource, demo_data_enabled, sdk_missing,
)

logger = logging.getLogger(__name__)

# Scanned only when the account's enabled regions cannot be listed
DEFAULT_AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
REGION_WORKERS = 8      # regions read at the same time


class _LockedSession:
    """A boto3 session shared between region threads. Creating a client is not
    thread-safe in boto3, so it happens under a lock; the clients themselves are."""

    def __init__(self, session):
        self._session, self._lock = session, threading.Lock()

    def client(self, *args, **kwargs):
        with self._lock:
            return self._session.client(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._session, name)


class AWSConnector(BaseCloudConnector):
    PROVIDER = "aws"
    SUPPORTED_RESOURCE_TYPES = [
        "aws_s3_bucket",
        "aws_security_group",
        "aws_rds_instance",
        "aws_iam_user",
        "aws_iam_role",
        "aws_lambda_function",
        "aws_ebs_volume",
        "aws_ec2_instance",
        *EXTRA_RESOURCE_TYPES,
    ]

    def _get_session(self):
        """Create a boto3 session with the stored credentials."""
        import boto3

        creds = self.credentials
        if creds.get("auth") == "oidc":
            # No stored secret: GuardNous signs a token and AWS exchanges it for
            # one-hour credentials (see app/services/federation).
            from app.services.federation.aws import assume_role

            return assume_role(creds)
        if creds.get("role_arn"):
            sts = boto3.client("sts")
            assume_kwargs = {
                "RoleArn": creds["role_arn"],
                "RoleSessionName": "guardnous-discovery",
                "DurationSeconds": 3600,
            }
            if creds.get("external_id"):
                assume_kwargs["ExternalId"] = creds["external_id"]
            resp = sts.assume_role(**assume_kwargs)
            temp = resp["Credentials"]
            return boto3.Session(
                aws_access_key_id=temp["AccessKeyId"],
                aws_secret_access_key=temp["SecretAccessKey"],
                aws_session_token=temp["SessionToken"],
            )
        else:
            return boto3.Session(
                aws_access_key_id=creds.get("access_key_id"),
                aws_secret_access_key=creds.get("secret_access_key"),
            )

    def _get_account_id(self, session) -> str:
        sts = session.client("sts")
        return sts.get_caller_identity()["Account"]

    async def test_connection(self) -> dict:
        try:
            session = self._get_session()
            identity = session.client("sts").get_caller_identity()
            return {
                "status": "connected",
                "details": {
                    "account": identity["Account"],
                    "arn": identity["Arn"],
                },
            }
        except ImportError:
            return {"status": "error", "error": str(sdk_missing("AWS"))}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def discover(self, resource_types: list[str] | None = None) -> list[DiscoveredResource]:
        types_to_discover = self._filter_types(resource_types)
        resources: list[DiscoveredResource] = []

        try:
            session = self._get_session()
            account_id = self._get_account_id(session)
        except ImportError:
            if demo_data_enabled():
                logger.warning("boto3 not installed — DEMO_DATA_ENABLED, returning sample AWS resources")
                return self._simulated_resources()
            raise sdk_missing("AWS")
        except Exception as e:
            logger.error(f"AWS session error: {e}")
            raise

        regions = self._regions_to_scan(session)
        self.scanned_regions = regions

        # Global resources (IAM — region-independent)
        if "aws_iam_user" in types_to_discover:
            resources.extend(self._discover_iam_users(session, account_id))
        if "aws_iam_role" in types_to_discover:
            resources.extend(self._discover_iam_roles(session, account_id))

        # S3 — global listing, regional location
        if "aws_s3_bucket" in types_to_discover:
            resources.extend(self._discover_s3_buckets(session, account_id))

        for rtype, collect in GLOBAL_COLLECTORS.items():
            if rtype in types_to_discover:
                resources.extend(self._collect(rtype, "global", collect, session, account_id))

        # Regional resources. Regions are independent, so they are read side by
        # side; results are added in region order so a sync is repeatable.
        shared = _LockedSession(session)

        def scan(region: str) -> list[DiscoveredResource]:
            logger.info(f"Scanning AWS region: {region}")
            found: list[DiscoveredResource] = []
            for rtype, collect in REGIONAL_COLLECTORS.items():
                if rtype in types_to_discover:
                    found.extend(self._collect(rtype, region, collect, shared, account_id, region))
            for rtype, discover in (
                ("aws_security_group", self._discover_security_groups),
                ("aws_rds_instance", self._discover_rds_instances),
                ("aws_lambda_function", self._discover_lambda_functions),
                ("aws_ebs_volume", self._discover_ebs_volumes),
                ("aws_ec2_instance", self._discover_ec2_instances),
            ):
                if rtype in types_to_discover:
                    found.extend(self._collect(rtype, region, discover, shared, account_id, region))
            return found

        with ThreadPoolExecutor(max_workers=min(REGION_WORKERS, max(1, len(regions)))) as pool:
            for found in pool.map(scan, regions):
                resources.extend(found)

        logger.info(f"AWS discovery complete: {len(resources)} resources found in {len(regions)} regions")
        return resources

    def _regions_to_scan(self, session) -> list[str]:
        """The regions chosen for this account, or every region enabled in it.

        Something left running in a region nobody looks at is exactly what a
        posture check should find, so no region is skipped by default. If the
        account does not allow listing regions, the default set is used.
        """
        if self.regions:
            return list(self.regions)
        try:
            listed = session.client("ec2", region_name="us-east-1").describe_regions(AllRegions=False)
            enabled = sorted({r["RegionName"] for r in listed.get("Regions", []) if r.get("RegionName")})
            if enabled:
                return enabled
        except Exception as exc:  # noqa: BLE001 - not allowed, or no network: fall back
            logger.warning("Could not list enabled AWS regions (%s); scanning the default regions", exc)
        return list(DEFAULT_AWS_REGIONS)

    @staticmethod
    def _collect(rtype: str, where: str, collect, *args) -> list[DiscoveredResource]:
        """Run one collector; a failure in one service must not stop the others."""
        try:
            return collect(*args)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AWS %s discovery failed in %s: %s", rtype, where, exc)
            return []

    # ── S3 ───────────────────────────────────────────────────────────────────

    def _discover_s3_buckets(self, session, account_id: str) -> list[DiscoveredResource]:
        results = []
        s3 = session.client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            logger.warning(f"S3 list_buckets failed: {e}")
            return results

        for bucket in buckets:
            name = bucket["Name"]
            try:
                # Get bucket location
                loc = s3.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"

                # Skip if region filtering and bucket not in requested regions
                if self.regions and region not in self.regions:
                    continue

                config: dict[str, Any] = {
                    "bucket_name": name,
                    "creation_date": bucket.get("CreationDate", "").isoformat() if hasattr(bucket.get("CreationDate", ""), "isoformat") else str(bucket.get("CreationDate", "")),
                    "region": region,
                }

                # Public access block
                try:
                    pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                    config["public_access_block"] = {
                        "block_public_acls": pab.get("BlockPublicAcls", False),
                        "ignore_public_acls": pab.get("IgnorePublicAcls", False),
                        "block_public_policy": pab.get("BlockPublicPolicy", False),
                        "restrict_public_buckets": pab.get("RestrictPublicBuckets", False),
                    }
                except Exception:
                    config["public_access_block"] = None

                # Encryption
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if rules:
                        sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                        config["encryption"] = {
                            "sse_algorithm": sse.get("SSEAlgorithm"),
                            "kms_key_id": sse.get("KMSMasterKeyID"),
                            "bucket_key_enabled": rules[0].get("BucketKeyEnabled", False),
                        }
                    else:
                        config["encryption"] = None
                except Exception:
                    config["encryption"] = None

                # Versioning
                try:
                    ver = s3.get_bucket_versioning(Bucket=name)
                    config["versioning"] = {
                        "status": ver.get("Status", "Disabled"),
                        "mfa_delete": ver.get("MFADelete", "Disabled"),
                    }
                except Exception:
                    config["versioning"] = {"status": "Disabled"}

                # Logging
                try:
                    log = s3.get_bucket_logging(Bucket=name)
                    config["logging_enabled"] = "LoggingEnabled" in log
                except Exception:
                    config["logging_enabled"] = False

                # Tags
                tags = {}
                try:
                    tag_resp = s3.get_bucket_tagging(Bucket=name)
                    for t in tag_resp.get("TagSet", []):
                        tags[t["Key"]] = t["Value"]
                except Exception:
                    pass

                results.append(DiscoveredResource(
                    provider="aws",
                    resource_type="aws_s3_bucket",
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_name=name,
                    region=region,
                    account_id=account_id,
                    config=config,
                    tags=tags,
                ))
            except Exception as e:
                logger.warning(f"Error inspecting S3 bucket {name}: {e}")

        return results

    # ── Security Groups ──────────────────────────────────────────────────────

    def _discover_security_groups(self, session, account_id: str, region: str) -> list[DiscoveredResource]:
        results = []
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    ingress_rules = []
                    for rule in sg.get("IpPermissions", []):
                        for cidr in rule.get("IpRanges", []):
                            ingress_rules.append({
                                "protocol": rule.get("IpProtocol", "-1"),
                                "from_port": rule.get("FromPort"),
                                "to_port": rule.get("ToPort"),
                                "cidr": cidr.get("CidrIp"),
                                "description": cidr.get("Description"),
                            })

                    egress_rules = []
                    for rule in sg.get("IpPermissionsEgress", []):
                        for cidr in rule.get("IpRanges", []):
                            egress_rules.append({
                                "protocol": rule.get("IpProtocol", "-1"),
                                "from_port": rule.get("FromPort"),
                                "to_port": rule.get("ToPort"),
                                "cidr": cidr.get("CidrIp"),
                            })

                    config = {
                        "group_id": sg["GroupId"],
                        "group_name": sg.get("GroupName", ""),
                        "description": sg.get("Description", ""),
                        "vpc_id": sg.get("VpcId"),
                        "ingress_rules": ingress_rules,
                        "egress_rules": egress_rules,
                        "ingress_open_to_world": any(
                            r["cidr"] in ("0.0.0.0/0", "::/0") for r in ingress_rules
                        ),
                        "allows_ssh_from_world": any(
                            r["cidr"] in ("0.0.0.0/0", "::/0")
                            and r.get("from_port") in (22, None)
                            and (r.get("to_port") is None or r.get("to_port") >= 22)
                            for r in ingress_rules
                        ),
                        "allows_rdp_from_world": any(
                            r["cidr"] in ("0.0.0.0/0", "::/0")
                            and r.get("from_port") in (3389, None)
                            and (r.get("to_port") is None or r.get("to_port") >= 3389)
                            for r in ingress_rules
                        ),
                    }

                    tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}

                    results.append(DiscoveredResource(
                        provider="aws",
                        resource_type="aws_security_group",
                        resource_id=f"arn:aws:ec2:{region}:{account_id}:security-group/{sg['GroupId']}",
                        resource_name=sg.get("GroupName", sg["GroupId"]),
                        region=region,
                        account_id=account_id,
                        config=config,
                        tags=tags,
                    ))
        except Exception as e:
            logger.warning(f"Security group discovery failed in {region}: {e}")

        return results

    # ── RDS ───────────────────────────────────────────────────────────────────

    def _discover_rds_instances(self, session, account_id: str, region: str) -> list[DiscoveredResource]:
        results = []
        rds = session.client("rds", region_name=region)

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    config = {
                        "db_instance_identifier": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "instance_class": db.get("DBInstanceClass"),
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "multi_az": db.get("MultiAZ", False),
                        "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", False),
                        "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                        "deletion_protection": db.get("DeletionProtection", False),
                        "iam_database_authentication_enabled": db.get("IAMDatabaseAuthenticationEnabled", False),
                        "performance_insights_enabled": db.get("PerformanceInsightsEnabled", False),
                        "storage_type": db.get("StorageType"),
                        "allocated_storage": db.get("AllocatedStorage"),
                        "vpc_security_groups": [
                            sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])
                        ],
                        "ca_certificate_identifier": db.get("CACertificateIdentifier"),
                    }

                    tags = {}
                    try:
                        tag_resp = rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"])
                        for t in tag_resp.get("TagList", []):
                            tags[t["Key"]] = t["Value"]
                    except Exception:
                        pass

                    results.append(DiscoveredResource(
                        provider="aws",
                        resource_type="aws_rds_instance",
                        resource_id=db["DBInstanceArn"],
                        resource_name=db["DBInstanceIdentifier"],
                        region=region,
                        account_id=account_id,
                        config=config,
                        tags=tags,
                    ))
        except Exception as e:
            logger.warning(f"RDS discovery failed in {region}: {e}")

        return results

    # ── IAM Users ─────────────────────────────────────────────────────────────

    def _discover_iam_users(self, session, account_id: str) -> list[DiscoveredResource]:
        results = []
        iam = session.client("iam")

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

                    # Get MFA devices
                    try:
                        mfa = iam.list_mfa_devices(UserName=username)
                        mfa_enabled = len(mfa.get("MFADevices", [])) > 0
                    except Exception:
                        # Unknown, not "no MFA": the credentials may lack iam:ListMFADevices
                        mfa_enabled = None

                    # Get access keys
                    access_keys = []
                    try:
                        keys = iam.list_access_keys(UserName=username)
                        for k in keys.get("AccessKeyMetadata", []):
                            access_keys.append({
                                "access_key_id": k["AccessKeyId"],
                                "status": k["Status"],
                                "created": k.get("CreateDate", "").isoformat() if hasattr(k.get("CreateDate", ""), "isoformat") else str(k.get("CreateDate", "")),
                            })
                    except Exception:
                        pass

                    # Get attached policies
                    attached_policies = []
                    try:
                        pols = iam.list_attached_user_policies(UserName=username)
                        attached_policies = [p["PolicyName"] for p in pols.get("AttachedPolicies", [])]
                    except Exception:
                        pass

                    # Console access
                    has_console_access = False
                    try:
                        iam.get_login_profile(UserName=username)
                        has_console_access = True
                    except Exception:
                        pass

                    config = {
                        "user_name": username,
                        "user_id": user.get("UserId"),
                        "arn": user["Arn"],
                        "created": user.get("CreateDate", "").isoformat() if hasattr(user.get("CreateDate", ""), "isoformat") else "",
                        "password_last_used": user.get("PasswordLastUsed", "").isoformat() if hasattr(user.get("PasswordLastUsed", ""), "isoformat") else None,
                        "mfa_enabled": mfa_enabled,
                        "access_keys": access_keys,
                        "has_console_access": has_console_access,
                        "attached_policies": attached_policies,
                        "has_admin_access": "AdministratorAccess" in attached_policies,
                    }

                    tags = {t["Key"]: t["Value"] for t in user.get("Tags", [])}

                    results.append(DiscoveredResource(
                        provider="aws",
                        resource_type="aws_iam_user",
                        resource_id=user["Arn"],
                        resource_name=username,
                        region="global",
                        account_id=account_id,
                        config=config,
                        tags=tags,
                    ))
        except Exception as e:
            logger.warning(f"IAM user discovery failed: {e}")

        return results

    # ── IAM Roles ─────────────────────────────────────────────────────────────

    def _discover_iam_roles(self, session, account_id: str) -> list[DiscoveredResource]:
        results = []
        iam = session.client("iam")

        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    # Skip AWS service-linked roles
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue

                    trust_policy = role.get("AssumeRolePolicyDocument", {})
                    principals = []
                    if isinstance(trust_policy, dict):
                        for stmt in trust_policy.get("Statement", []):
                            principal = stmt.get("Principal", {})
                            if isinstance(principal, str):
                                principals.append(principal)
                            elif isinstance(principal, dict):
                                for v in principal.values():
                                    if isinstance(v, list):
                                        principals.extend(v)
                                    else:
                                        principals.append(v)

                    # Get attached policies
                    attached_policies = []
                    try:
                        pols = iam.list_attached_role_policies(RoleName=role["RoleName"])
                        attached_policies = [p["PolicyName"] for p in pols.get("AttachedPolicies", [])]
                    except Exception:
                        pass

                    config = {
                        "role_name": role["RoleName"],
                        "role_id": role.get("RoleId"),
                        "arn": role["Arn"],
                        "created": role.get("CreateDate", "").isoformat() if hasattr(role.get("CreateDate", ""), "isoformat") else "",
                        "max_session_duration": role.get("MaxSessionDuration", 3600),
                        "trust_policy_principals": principals,
                        "allows_cross_account": any("arn:aws:iam::" in str(p) and account_id not in str(p) for p in principals),
                        "attached_policies": attached_policies,
                        "has_admin_access": "AdministratorAccess" in attached_policies,
                    }

                    tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}

                    results.append(DiscoveredResource(
                        provider="aws",
                        resource_type="aws_iam_role",
                        resource_id=role["Arn"],
                        resource_name=role["RoleName"],
                        region="global",
                        account_id=account_id,
                        config=config,
                        tags=tags,
                    ))
        except Exception as e:
            logger.warning(f"IAM role discovery failed: {e}")

        return results

    # ── Lambda ────────────────────────────────────────────────────────────────

    def _discover_lambda_functions(self, session, account_id: str, region: str) -> list[DiscoveredResource]:
        results = []
        lam = session.client("lambda", region_name=region)

        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    config = {
                        "function_name": fn["FunctionName"],
                        "runtime": fn.get("Runtime"),
                        "handler": fn.get("Handler"),
                        "memory_size": fn.get("MemorySize"),
                        "timeout": fn.get("Timeout"),
                        "last_modified": fn.get("LastModified"),
                        "code_size": fn.get("CodeSize"),
                        "environment_variables": list((fn.get("Environment") or {}).get("Variables", {}).keys()),
                        "has_env_secrets": any(
                            k.lower() in ("password", "secret", "api_key", "token", "private_key")
                            for k in (fn.get("Environment") or {}).get("Variables", {}).keys()
                        ),
                        "vpc_config": bool(fn.get("VpcConfig", {}).get("VpcId")),
                        "kms_key_arn": fn.get("KMSKeyArn"),
                        "tracing_config": fn.get("TracingConfig", {}).get("Mode", "PassThrough"),
                        "architectures": fn.get("Architectures", ["x86_64"]),
                    }

                    tags = fn.get("Tags", {})

                    results.append(DiscoveredResource(
                        provider="aws",
                        resource_type="aws_lambda_function",
                        resource_id=fn["FunctionArn"],
                        resource_name=fn["FunctionName"],
                        region=region,
                        account_id=account_id,
                        config=config,
                        tags=tags,
                    ))
        except Exception as e:
            logger.warning(f"Lambda discovery failed in {region}: {e}")

        return results

    # ── EBS Volumes ───────────────────────────────────────────────────────────

    def _discover_ebs_volumes(self, session, account_id: str, region: str) -> list[DiscoveredResource]:
        results = []
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                    name = tags.get("Name", vol["VolumeId"])

                    config = {
                        "volume_id": vol["VolumeId"],
                        "volume_type": vol.get("VolumeType"),
                        "size": vol.get("Size"),
                        "encrypted": vol.get("Encrypted", False),
                        "kms_key_id": vol.get("KmsKeyId"),
                        "state": vol.get("State"),
                        "iops": vol.get("Iops"),
                        "throughput": vol.get("Throughput"),
                        "availability_zone": vol.get("AvailabilityZone"),
                        "attached_instances": [
                            a.get("InstanceId") for a in vol.get("Attachments", [])
                        ],
                        "is_attached": len(vol.get("Attachments", [])) > 0,
                        "snapshot_id": vol.get("SnapshotId"),
                    }

                    results.append(DiscoveredResource(
                        provider="aws",
                        resource_type="aws_ebs_volume",
                        resource_id=f"arn:aws:ec2:{region}:{account_id}:volume/{vol['VolumeId']}",
                        resource_name=name,
                        region=region,
                        account_id=account_id,
                        config=config,
                        tags=tags,
                    ))
        except Exception as e:
            logger.warning(f"EBS discovery failed in {region}: {e}")

        return results

    # ── EC2 Instances ─────────────────────────────────────────────────────────

    def _discover_ec2_instances(self, session, account_id: str, region: str) -> list[DiscoveredResource]:
        results = []
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for inst in reservation["Instances"]:
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        name = tags.get("Name", inst["InstanceId"])

                        config = {
                            "instance_id": inst["InstanceId"],
                            "instance_type": inst.get("InstanceType"),
                            "state": inst.get("State", {}).get("Name"),
                            "platform": inst.get("Platform", "linux"),
                            "ami_id": inst.get("ImageId"),
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "public_ip": inst.get("PublicIpAddress"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "has_public_ip": inst.get("PublicIpAddress") is not None,
                            "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
                            "security_groups": [
                                sg["GroupId"] for sg in inst.get("SecurityGroups", [])
                            ],
                            "monitoring_state": inst.get("Monitoring", {}).get("State", "disabled"),
                            "ebs_optimized": inst.get("EbsOptimized", False),
                            "metadata_options": {
                                "http_tokens": inst.get("MetadataOptions", {}).get("HttpTokens", "optional"),
                                "http_endpoint": inst.get("MetadataOptions", {}).get("HttpEndpoint", "enabled"),
                            },
                            "imdsv2_required": inst.get("MetadataOptions", {}).get("HttpTokens") == "required",
                        }

                        results.append(DiscoveredResource(
                            provider="aws",
                            resource_type="aws_ec2_instance",
                            resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/{inst['InstanceId']}",
                            resource_name=name,
                            region=region,
                            account_id=account_id,
                            config=config,
                            tags=tags,
                        ))
        except Exception as e:
            logger.warning(f"EC2 discovery failed in {region}: {e}")

        return results

    # ── Simulated resources (when boto3 not installed) ────────────────────────

    def _simulated_resources(self) -> list[DiscoveredResource]:
        """Return realistic simulated resources for demo mode."""
        account_id = self.credentials.get("account_id", "123456789012")
        return [
            DiscoveredResource(
                provider="aws", resource_type="aws_s3_bucket",
                resource_id=f"arn:aws:s3:::prod-app-data-{account_id}",
                resource_name=f"prod-app-data-{account_id}",
                region="us-east-1", account_id=account_id,
                config={
                    "bucket_name": f"prod-app-data-{account_id}",
                    "public_access_block": {"block_public_acls": True, "ignore_public_acls": True,
                                             "block_public_policy": True, "restrict_public_buckets": True},
                    "encryption": {"sse_algorithm": "aws:kms", "bucket_key_enabled": True},
                    "versioning": {"status": "Enabled"},
                    "logging_enabled": True,
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_s3_bucket",
                resource_id=f"arn:aws:s3:::dev-logs-{account_id}",
                resource_name=f"dev-logs-{account_id}",
                region="us-east-1", account_id=account_id,
                config={
                    "bucket_name": f"dev-logs-{account_id}",
                    "public_access_block": None,
                    "encryption": None,
                    "versioning": {"status": "Disabled"},
                    "logging_enabled": False,
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_security_group",
                resource_id=f"arn:aws:ec2:us-east-1:{account_id}:security-group/sg-0abc123",
                resource_name="web-server-sg",
                region="us-east-1", account_id=account_id,
                config={
                    "group_id": "sg-0abc123", "group_name": "web-server-sg",
                    "vpc_id": "vpc-0123456",
                    "ingress_rules": [
                        {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},
                    ],
                    "ingress_open_to_world": True,
                    "allows_ssh_from_world": True,
                    "allows_rdp_from_world": False,
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_rds_instance",
                resource_id=f"arn:aws:rds:us-east-1:{account_id}:db:prod-main-db",
                resource_name="prod-main-db",
                region="us-east-1", account_id=account_id,
                config={
                    "db_instance_identifier": "prod-main-db",
                    "engine": "postgres", "engine_version": "15.4",
                    "instance_class": "db.r6g.xlarge",
                    "storage_encrypted": True, "publicly_accessible": False,
                    "multi_az": True, "backup_retention_period": 7,
                    "deletion_protection": True,
                    "iam_database_authentication_enabled": True,
                    "auto_minor_version_upgrade": True,
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_rds_instance",
                resource_id=f"arn:aws:rds:us-east-1:{account_id}:db:dev-test-db",
                resource_name="dev-test-db",
                region="us-east-1", account_id=account_id,
                config={
                    "db_instance_identifier": "dev-test-db",
                    "engine": "mysql", "engine_version": "8.0.35",
                    "instance_class": "db.t3.medium",
                    "storage_encrypted": False, "publicly_accessible": True,
                    "multi_az": False, "backup_retention_period": 0,
                    "deletion_protection": False,
                    "iam_database_authentication_enabled": False,
                    "auto_minor_version_upgrade": False,
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_iam_user",
                resource_id=f"arn:aws:iam::{account_id}:user/deploy-bot",
                resource_name="deploy-bot",
                region="global", account_id=account_id,
                config={
                    "user_name": "deploy-bot",
                    "mfa_enabled": False,
                    "access_keys": [{"access_key_id": "AKIAEXAMPLE1", "status": "Active", "created": "2024-01-15"}],
                    "has_console_access": False,
                    "attached_policies": ["AdministratorAccess"],
                    "has_admin_access": True,
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_iam_user",
                resource_id=f"arn:aws:iam::{account_id}:user/jane.doe",
                resource_name="jane.doe",
                region="global", account_id=account_id,
                config={
                    "user_name": "jane.doe",
                    "mfa_enabled": True,
                    "access_keys": [],
                    "has_console_access": True,
                    "attached_policies": ["ReadOnlyAccess"],
                    "has_admin_access": False,
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_ec2_instance",
                resource_id=f"arn:aws:ec2:us-east-1:{account_id}:instance/i-0abc123def",
                resource_name="prod-web-server-1",
                region="us-east-1", account_id=account_id,
                config={
                    "instance_id": "i-0abc123def",
                    "instance_type": "m5.xlarge",
                    "state": "running", "platform": "linux",
                    "has_public_ip": True,
                    "public_ip": "54.123.45.67",
                    "imdsv2_required": False,
                    "monitoring_state": "disabled",
                    "ebs_optimized": True,
                    "metadata_options": {"http_tokens": "optional", "http_endpoint": "enabled"},
                },
            ),
            DiscoveredResource(
                provider="aws", resource_type="aws_lambda_function",
                resource_id=f"arn:aws:lambda:us-east-1:{account_id}:function:data-processor",
                resource_name="data-processor",
                region="us-east-1", account_id=account_id,
                config={
                    "function_name": "data-processor",
                    "runtime": "python3.11", "timeout": 300, "memory_size": 512,
                    "environment_variables": ["DB_HOST", "DB_PASSWORD", "API_KEY"],
                    "has_env_secrets": True,
                    "vpc_config": False, "kms_key_arn": None,
                    "tracing_config": "PassThrough",
                },
            ),
        ]

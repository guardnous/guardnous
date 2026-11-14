"""AWS collectors beyond the original eight resource types.

Every collector is read-only and returns :class:`DiscoveredResource` objects.

A value that could not be read (usually a missing IAM permission) is never
reported as "disabled": the field is left out and its name is appended to
``config["_unreadable"]`` so posture rules can say "could not be checked"
instead of raising a false finding.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from app.services.cloud_connectors.base import DiscoveredResource

logger = logging.getLogger(__name__)

# Error codes that mean "this is not configured", as opposed to "we may not look".
_NOT_CONFIGURED = {
    "NoSuchEntity", "NoSuchPublicAccessBlockConfiguration", "WAFNonexistentItemException",
    "ResourceNotFoundException", "NotFoundException", "TrailNotFoundException",
}


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "") or type(exc).__name__


def _read(config: dict, field: str, fn: Callable[[], Any], absent: Any = None) -> Any:
    """Call ``fn`` and store its result under ``field``.

    "Not configured" errors store ``absent``. Any other error marks the field
    unreadable and stores nothing.
    """
    try:
        value = fn()
    except Exception as exc:  # noqa: BLE001 - botocore raises generated classes
        if _error_code(exc) in _NOT_CONFIGURED:
            config[field] = absent
            return absent
        config.setdefault("_unreadable", []).append(field)
        logger.info("AWS: could not read %s (%s)", field, _error_code(exc))
        return None
    config[field] = value
    return value


def _tags(items: list[dict] | None, key: str = "Key", value: str = "Value") -> dict:
    return {t[key]: t.get(value, "") for t in items or [] if key in t}


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


def _pages(client, operation: str, result_key: str, **kwargs) -> list:
    items: list = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def _resource(rtype: str, rid: str, name: str, region: str, account_id: str, config: dict, tags: dict | None = None):
    return DiscoveredResource(
        provider="aws", resource_type=rtype, resource_id=rid, resource_name=name, region=region,
        account_id=account_id, config=config, tags=tags or {},
    )


# ── account-wide ────────────────────────────────────────────────────

def discover_account(session, account_id: str) -> list[DiscoveredResource]:
    """Account-level settings: root user, password policy, S3 public access block."""
    iam = session.client("iam")
    config: dict[str, Any] = {"account_id": account_id}

    summary = _read(config, "summary", lambda: iam.get_account_summary()["SummaryMap"])
    if summary is not None:
        config["summary"] = {
            "root_mfa_enabled": bool(summary.get("AccountMFAEnabled")),
            "root_access_keys_present": bool(summary.get("AccountAccessKeysPresent")),
            "users": summary.get("Users", 0),
        }

    def password_policy():
        p = iam.get_account_password_policy()["PasswordPolicy"]
        return {
            "minimum_length": p.get("MinimumPasswordLength", 0),
            "require_symbols": p.get("RequireSymbols", False),
            "require_numbers": p.get("RequireNumbers", False),
            "require_uppercase": p.get("RequireUppercaseCharacters", False),
            "require_lowercase": p.get("RequireLowercaseCharacters", False),
            "max_age_days": p.get("MaxPasswordAge"),
            "reuse_prevention": p.get("PasswordReusePrevention"),
        }

    _read(config, "password_policy", password_policy)

    def s3_block():
        # s3control has no global endpoint: without a region boto3 raises NoRegionError.
        control = session.client("s3control", region_name="us-east-1")
        b = control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        return {
            "block_public_acls": b.get("BlockPublicAcls", False),
            "ignore_public_acls": b.get("IgnorePublicAcls", False),
            "block_public_policy": b.get("BlockPublicPolicy", False),
            "restrict_public_buckets": b.get("RestrictPublicBuckets", False),
        }

    _read(config, "s3_public_access_block", s3_block)
    return [_resource("aws_account", f"arn:aws:iam::{account_id}:root", f"AWS account {account_id}", "global", account_id, config)]


def discover_route53_zones(session, account_id: str) -> list[DiscoveredResource]:
    """Hosted zones with the records that point at other services."""
    r53 = session.client("route53")
    out = []
    try:
        zones = _pages(r53, "list_hosted_zones", "HostedZones")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Route 53 discovery failed: %s", _error_code(exc))
        return out
    for zone in zones:
        zone_id = zone["Id"].split("/")[-1]
        config: dict[str, Any] = {
            "name": zone["Name"].rstrip("."),
            "private": bool(zone.get("Config", {}).get("PrivateZone")),
            "record_count": zone.get("ResourceRecordSetCount", 0),
        }

        def pointers(zid=zone_id):
            records = []
            for rr in _pages(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zid):
                alias = (rr.get("AliasTarget") or {}).get("DNSName")
                if rr.get("Type") == "CNAME" or alias:
                    target = alias or (rr.get("ResourceRecords") or [{}])[0].get("Value", "")
                    records.append({"name": rr["Name"].rstrip("."), "type": rr["Type"], "target": target.rstrip(".").lower()})
            return records[:2000]

        _read(config, "pointer_records", pointers)
        out.append(_resource(
            "aws_route53_zone", f"arn:aws:route53:::hostedzone/{zone_id}", config["name"], "global", account_id, config,
        ))
    return out


# ── per region ──────────────────────────────────────────────────────

def discover_region_settings(session, account_id: str, region: str) -> list[DiscoveredResource]:
    """Region-wide security services: EBS default encryption, GuardDuty, AWS Config."""
    config: dict[str, Any] = {"region": region}
    ec2 = session.client("ec2", region_name=region)
    _read(config, "ebs_encryption_by_default", lambda: bool(ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]))

    def guardduty():
        gd = session.client("guardduty", region_name=region)
        ids = gd.list_detectors().get("DetectorIds", [])
        return any(gd.get_detector(DetectorId=i).get("Status") == "ENABLED" for i in ids)

    _read(config, "guardduty_enabled", guardduty, absent=False)

    def recorder():
        cfg = session.client("config", region_name=region)
        return any(s.get("recording") for s in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", []))

    _read(config, "config_recorder_enabled", recorder, absent=False)
    return [_resource(
        "aws_region_settings", f"arn:aws:ec2:{region}:{account_id}:region-settings", f"{region} security settings",
        region, account_id, config,
    )]


def discover_cloudtrail(session, account_id: str, region: str) -> list[DiscoveredResource]:
    ct = session.client("cloudtrail", region_name=region)
    out = []
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("CloudTrail discovery failed in %s: %s", region, _error_code(exc))
        return out
    for t in trails:
        config: dict[str, Any] = {
            "multi_region": bool(t.get("IsMultiRegionTrail")),
            "log_file_validation": bool(t.get("LogFileValidationEnabled")),
            "kms_key_id": t.get("KmsKeyId"),
            "s3_bucket": t.get("S3BucketName"),
            "cloudwatch_logs": bool(t.get("CloudWatchLogsLogGroupArn")),
            "home_region": t.get("HomeRegion", region),
        }
        _read(config, "is_logging", lambda arn=t["TrailARN"]: bool(ct.get_trail_status(Name=arn).get("IsLogging")))
        out.append(_resource("aws_cloudtrail_trail", t["TrailARN"], t.get("Name", ""), config["home_region"], account_id, config))
    return out


def discover_kms_keys(session, account_id: str, region: str) -> list[DiscoveredResource]:
    """Customer-managed symmetric keys (AWS-managed keys rotate on their own)."""
    kms = session.client("kms", region_name=region)
    out = []
    try:
        keys = _pages(kms, "list_keys", "Keys")
    except Exception as exc:  # noqa: BLE001
        logger.warning("KMS discovery failed in %s: %s", region, _error_code(exc))
        return out
    for key in keys:
        try:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
        except Exception:  # noqa: BLE001
            continue
        if meta.get("KeyManager") != "CUSTOMER":
            continue
        config: dict[str, Any] = {
            "state": meta.get("KeyState"), "spec": meta.get("KeySpec"), "origin": meta.get("Origin"),
            "description": meta.get("Description", ""),
        }
        if meta.get("KeyState") == "Enabled" and meta.get("KeySpec") == "SYMMETRIC_DEFAULT":
            _read(config, "rotation_enabled", lambda k=key["KeyId"]: bool(kms.get_key_rotation_status(KeyId=k)["KeyRotationEnabled"]))
        out.append(_resource("aws_kms_key", meta["Arn"], key["KeyId"], region, account_id, config))
    return out


def discover_vpcs(session, account_id: str, region: str) -> list[DiscoveredResource]:
    ec2 = session.client("ec2", region_name=region)
    out = []
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("VPC discovery failed in %s: %s", region, _error_code(exc))
        return out
    logged: set[str] | None
    try:
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        logged = {f["ResourceId"] for f in flow_logs if f.get("FlowLogStatus") == "ACTIVE"}
    except Exception:  # noqa: BLE001
        logged = None
    for vpc in vpcs:
        tags = _tags(vpc.get("Tags"))
        config: dict[str, Any] = {"cidr": vpc.get("CidrBlock"), "is_default": bool(vpc.get("IsDefault"))}
        if logged is None:
            config["_unreadable"] = ["flow_logs_enabled"]
        else:
            config["flow_logs_enabled"] = vpc["VpcId"] in logged
        out.append(_resource(
            "aws_vpc", f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc['VpcId']}", tags.get("Name") or vpc["VpcId"],
            region, account_id, config, tags,
        ))
    return out


def discover_load_balancers(session, account_id: str, region: str) -> list[DiscoveredResource]:
    elb = session.client("elbv2", region_name=region)
    out = []
    try:
        lbs = _pages(elb, "describe_load_balancers", "LoadBalancers")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Load balancer discovery failed in %s: %s", region, _error_code(exc))
        return out
    for lb in lbs:
        arn = lb["LoadBalancerArn"]
        config: dict[str, Any] = {
            "type": lb.get("Type"), "scheme": lb.get("Scheme"), "dns_name": (lb.get("DNSName") or "").lower(),
            "internet_facing": lb.get("Scheme") == "internet-facing",
        }

        def listeners(a=arn):
            return [
                {
                    "port": li.get("Port"), "protocol": li.get("Protocol"), "ssl_policy": li.get("SslPolicy"),
                    "redirects_to_https": any(
                        (act.get("RedirectConfig") or {}).get("Protocol") == "HTTPS" for act in li.get("DefaultActions", [])
                    ),
                }
                for li in _pages(elb, "describe_listeners", "Listeners", LoadBalancerArn=a)
            ]

        _read(config, "listeners", listeners)

        def attributes(a=arn):
            attrs = {x["Key"]: x.get("Value") for x in elb.describe_load_balancer_attributes(LoadBalancerArn=a)["Attributes"]}
            return {
                "access_logs_enabled": attrs.get("access_logs.s3.enabled") == "true",
                "deletion_protection": attrs.get("deletion_protection.enabled") == "true",
                "drop_invalid_headers": attrs.get("routing.http.drop_invalid_header_fields.enabled") == "true",
            }

        _read(config, "attributes", attributes)
        if lb.get("Type") == "application":
            def waf(a=arn):
                acl = session.client("wafv2", region_name=region).get_web_acl_for_resource(ResourceArn=a).get("WebACL")
                return acl.get("Name") if acl else None

            _read(config, "waf_web_acl", waf)
        out.append(_resource("aws_lb", arn, lb.get("LoadBalancerName", ""), region, account_id, config))
    return out


def discover_acm_certificates(session, account_id: str, region: str) -> list[DiscoveredResource]:
    acm = session.client("acm", region_name=region)
    out = []
    try:
        certs = _pages(acm, "list_certificates", "CertificateSummaryList")
    except Exception as exc:  # noqa: BLE001
        logger.warning("ACM discovery failed in %s: %s", region, _error_code(exc))
        return out
    for summary in certs:
        try:
            c = acm.describe_certificate(CertificateArn=summary["CertificateArn"])["Certificate"]
        except Exception:  # noqa: BLE001
            continue
        out.append(_resource("aws_acm_certificate", c["CertificateArn"], c.get("DomainName", ""), region, account_id, {
            "domain": c.get("DomainName"), "status": c.get("Status"), "type": c.get("Type"),
            "not_after": _iso(c.get("NotAfter")), "in_use": bool(c.get("InUseBy")),
            "key_algorithm": c.get("KeyAlgorithm"), "renewal_eligibility": c.get("RenewalEligibility"),
        }))
    return out


def discover_eks_clusters(session, account_id: str, region: str) -> list[DiscoveredResource]:
    eks = session.client("eks", region_name=region)
    out = []
    try:
        names = _pages(eks, "list_clusters", "clusters")
    except Exception as exc:  # noqa: BLE001
        logger.warning("EKS discovery failed in %s: %s", region, _error_code(exc))
        return out
    for name in names:
        try:
            c = eks.describe_cluster(name=name)["cluster"]
        except Exception:  # noqa: BLE001
            continue
        vpc = c.get("resourcesVpcConfig", {})
        enabled_logs = sorted({
            t for entry in c.get("logging", {}).get("clusterLogging", []) if entry.get("enabled") for t in entry.get("types", [])
        })
        out.append(_resource("aws_eks_cluster", c["arn"], name, region, account_id, {
            "version": c.get("version"),
            "endpoint_public_access": bool(vpc.get("endpointPublicAccess")),
            "endpoint_private_access": bool(vpc.get("endpointPrivateAccess")),
            "public_access_cidrs": vpc.get("publicAccessCidrs", []),
            "enabled_log_types": enabled_logs,
            "secrets_encrypted": any("secrets" in e.get("resources", []) for e in c.get("encryptionConfig", [])),
        }, c.get("tags") or {}))
    return out


def discover_ecr_repositories(session, account_id: str, region: str) -> list[DiscoveredResource]:
    ecr = session.client("ecr", region_name=region)
    out = []
    try:
        repos = _pages(ecr, "describe_repositories", "repositories")
    except Exception as exc:  # noqa: BLE001
        logger.warning("ECR discovery failed in %s: %s", region, _error_code(exc))
        return out
    for r in repos:
        out.append(_resource("aws_ecr_repository", r["repositoryArn"], r["repositoryName"], region, account_id, {
            "scan_on_push": bool(r.get("imageScanningConfiguration", {}).get("scanOnPush")),
            "tag_mutability": r.get("imageTagMutability"),
            "encryption_type": r.get("encryptionConfiguration", {}).get("encryptionType"),
        }))
    return out


def discover_secrets(session, account_id: str, region: str) -> list[DiscoveredResource]:
    """Secrets Manager metadata only. Secret values are never read."""
    sm = session.client("secretsmanager", region_name=region)
    out = []
    try:
        secrets = _pages(sm, "list_secrets", "SecretList")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Secrets Manager discovery failed in %s: %s", region, _error_code(exc))
        return out
    for s in secrets:
        out.append(_resource("aws_secretsmanager_secret", s["ARN"], s.get("Name", ""), region, account_id, {
            "rotation_enabled": bool(s.get("RotationEnabled")),
            "last_rotated": _iso(s.get("LastRotatedDate")), "last_accessed": _iso(s.get("LastAccessedDate")),
            "customer_kms_key": bool(s.get("KmsKeyId")),
        }, _tags(s.get("Tags"))))
    return out


GLOBAL_COLLECTORS: dict[str, Callable] = {
    "aws_account": discover_account,
    "aws_route53_zone": discover_route53_zones,
}

REGIONAL_COLLECTORS: dict[str, Callable] = {
    "aws_region_settings": discover_region_settings,
    "aws_cloudtrail_trail": discover_cloudtrail,
    "aws_kms_key": discover_kms_keys,
    "aws_vpc": discover_vpcs,
    "aws_lb": discover_load_balancers,
    "aws_acm_certificate": discover_acm_certificates,
    "aws_eks_cluster": discover_eks_clusters,
    "aws_ecr_repository": discover_ecr_repositories,
    "aws_secretsmanager_secret": discover_secrets,
}

EXTRA_RESOURCE_TYPES = [*GLOBAL_COLLECTORS, *REGIONAL_COLLECTORS]

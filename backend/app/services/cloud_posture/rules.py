"""Posture rules for AWS resources.

A rule looks at one synced resource and returns the reason it fails, or
``None`` when it passes. A rule raises :class:`Unknown` when the setting it
needs could not be read from the cloud, so that a missing read permission is
reported as "not checked" and never as a finding.

CIS numbers refer to the CIS AWS Foundations Benchmark v1.4.0 and were checked
against the control mapping AWS publishes for Security Hub
(docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html).
A number is given only where the rule tests the same thing as the CIS
requirement; the rules are not a certified implementation of the benchmark.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 1433: "SQL Server", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
WORLD = {"0.0.0.0/0", "::/0"}
OLD_TLS_POLICIES = {"ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-TLS-1-1-2017-01"}
RETIRED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x",
    "nodejs12.x", "nodejs14.x", "ruby2.5", "ruby2.7", "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1",
    "dotnetcore3.1", "java8",
}


class Unknown(Exception):
    """The setting this rule needs could not be read."""


@dataclass
class Inventory:
    """Every active resource of one cloud account, for rules that compare resources."""

    by_type: dict[str, list[dict]] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def configs(self, resource_type: str) -> list[dict]:
        return [r["config"] for r in self.by_type.get(resource_type, [])]

    def has(self, resource_type: str) -> bool:
        return resource_type in self.by_type


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    resource_type: str
    check: Callable[[dict, Inventory], Optional[str]]
    remediation: str
    cis: str = ""


def need(config: dict, key: str):
    """Value of a setting, or :class:`Unknown` if it could not be read."""
    if key in (config.get("_unreadable") or []) or key not in config:
        raise Unknown(key)
    return config[key]


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        value = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _all_on(block: Optional[dict]) -> bool:
    return bool(block) and all(
        block.get(k) for k in ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")
    )


def _world_ports(config: dict) -> list[tuple[Optional[int], Optional[int], str]]:
    """(from_port, to_port, protocol) of ingress rules open to the whole internet."""
    return [
        (r.get("from_port"), r.get("to_port"), str(r.get("protocol", "-1")))
        for r in config.get("ingress_rules") or [] if r.get("cidr") in WORLD
    ]


def _covers(rule: tuple, port: int) -> bool:
    low, high, proto = rule
    if proto == "-1":
        return True
    if proto not in ("tcp", "6"):
        return False
    return low is not None and high is not None and low <= port <= high


# ── S3 ──────────────────────────────────────────────────────────────

def s3_public_access(c: dict, inv: Inventory) -> Optional[str]:
    if _all_on(c.get("public_access_block")):
        return None
    for account in inv.configs("aws_account"):
        if _all_on(account.get("s3_public_access_block")):
            return None
    return (
        "Public access is not fully blocked for this bucket: all four Block Public Access settings are not on "
        "at the bucket level (or could not be read) and the account-level block does not cover it."
    )


def s3_versioning(c: dict, inv: Inventory) -> Optional[str]:
    return None if (c.get("versioning") or {}).get("status") == "Enabled" else "Versioning is not enabled."


def s3_logging(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("logging_enabled") else "Server access logging is not enabled."


# ── account ─────────────────────────────────────────────────────────

def root_mfa(c: dict, inv: Inventory) -> Optional[str]:
    return None if need(c, "summary")["root_mfa_enabled"] else "The root user has no MFA device."


def root_keys(c: dict, inv: Inventory) -> Optional[str]:
    return "The root user has access keys." if need(c, "summary")["root_access_keys_present"] else None


def password_length(c: dict, inv: Inventory) -> Optional[str]:
    policy = need(c, "password_policy")
    if policy is None:
        return "No IAM password policy is set, so the AWS default (8 characters) applies."
    length = policy.get("minimum_length") or 0
    return None if length >= 14 else f"The IAM password policy allows passwords of {length} characters; 14 is the minimum recommended."


def password_reuse(c: dict, inv: Inventory) -> Optional[str]:
    policy = need(c, "password_policy")
    kept = (policy or {}).get("reuse_prevention") or 0
    return None if kept >= 24 else f"Password reuse prevention remembers {kept} passwords; 24 is recommended."


def account_s3_block(c: dict, inv: Inventory) -> Optional[str]:
    block = need(c, "s3_public_access_block")
    return None if _all_on(block) else "The account-level S3 Block Public Access settings are not all on."


def no_trail(c: dict, inv: Inventory) -> Optional[str]:
    if not inv.has("aws_cloudtrail_trail") and not inv.has("aws_region_settings"):
        raise Unknown("cloudtrail")           # trails were not part of this sync
    for trail in inv.configs("aws_cloudtrail_trail"):
        if trail.get("multi_region") and trail.get("is_logging"):
            return None
    return "No CloudTrail trail is both multi-region and currently logging in the synced regions."


# ── IAM ─────────────────────────────────────────────────────────────

def user_mfa(c: dict, inv: Inventory) -> Optional[str]:
    if c.get("has_console_access") and not c.get("mfa_enabled"):
        return "This user can sign in to the console but has no MFA device."
    return None


def old_access_keys(c: dict, inv: Inventory) -> Optional[str]:
    old = []
    for key in c.get("access_keys") or []:
        created = _parse(key.get("created"))
        if key.get("status") == "Active" and created and inv.now - created > timedelta(days=90):
            old.append(f"{str(key.get('access_key_id', ''))[:8]}… ({(inv.now - created).days} days)")
    return f"Active access keys older than 90 days: {', '.join(old)}." if old else None


def user_admin(c: dict, inv: Inventory) -> Optional[str]:
    return "AdministratorAccess is attached directly to this user." if c.get("has_admin_access") else None


def role_cross_account_admin(c: dict, inv: Inventory) -> Optional[str]:
    if c.get("allows_cross_account") and c.get("has_admin_access"):
        return "This role has AdministratorAccess and can be assumed from another AWS account."
    return None


# ── network ─────────────────────────────────────────────────────────

def _admin_port(port: int):
    def check(c: dict, inv: Inventory) -> Optional[str]:
        if any(_covers(r, port) for r in _world_ports(c)):
            return f"{ADMIN_PORTS[port]} (port {port}) is open to the whole internet."
        return None
    return check


def sg_sensitive_ports(c: dict, inv: Inventory) -> Optional[str]:
    rules = _world_ports(c)
    if any(r[2] == "-1" for r in rules):
        return "All ports and protocols are open to the whole internet."
    hit = sorted({f"{name} ({port})" for port, name in SENSITIVE_PORTS.items() if any(_covers(r, port) for r in rules)})
    return f"Open to the whole internet: {', '.join(hit)}." if hit else None


def default_sg(c: dict, inv: Inventory) -> Optional[str]:
    if c.get("group_name") == "default" and (c.get("ingress_rules") or c.get("egress_rules")):
        return "The VPC's default security group allows traffic; it should have no rules so nothing uses it by accident."
    return None


def vpc_flow_logs(c: dict, inv: Inventory) -> Optional[str]:
    return None if need(c, "flow_logs_enabled") else "VPC flow logs are not enabled."


# ── data stores and compute ─────────────────────────────────────────

def rds_public(c: dict, inv: Inventory) -> Optional[str]:
    return "The database instance is publicly accessible." if c.get("publicly_accessible") else None


def rds_encryption(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("storage_encrypted") else "Storage is not encrypted."


def rds_backups(c: dict, inv: Inventory) -> Optional[str]:
    days = c.get("backup_retention_period") or 0
    if days == 0:
        return "Automated backups are turned off."
    return None if days >= 7 else f"Automated backups are kept for {days} days; 7 is the minimum recommended."


def rds_deletion_protection(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("deletion_protection") else "Deletion protection is off."


def ebs_encryption(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("encrypted") else "The volume is not encrypted."


def ebs_default_encryption(c: dict, inv: Inventory) -> Optional[str]:
    return None if need(c, "ebs_encryption_by_default") else "EBS encryption by default is off in this region."


def guardduty(c: dict, inv: Inventory) -> Optional[str]:
    return None if need(c, "guardduty_enabled") else "GuardDuty is not enabled in this region."


def config_recorder(c: dict, inv: Inventory) -> Optional[str]:
    return None if need(c, "config_recorder_enabled") else "AWS Config is not recording in this region."


def ec2_imdsv2(c: dict, inv: Inventory) -> Optional[str]:
    if c.get("state") != "running":
        return None
    options = c.get("metadata_options") or {}
    if options.get("http_endpoint") == "enabled" and options.get("http_tokens") != "required":
        return "The instance accepts IMDSv1 requests, which lets a server-side request forgery steal its role credentials."
    return None


def lambda_env_secrets(c: dict, inv: Inventory) -> Optional[str]:
    return "Environment variable names suggest secrets are stored in plain function configuration." if c.get("has_env_secrets") else None


def lambda_runtime(c: dict, inv: Inventory) -> Optional[str]:
    runtime = c.get("runtime")
    return f"Runtime {runtime} is retired and no longer receives security patches." if runtime in RETIRED_LAMBDA_RUNTIMES else None


# ── logging and keys ────────────────────────────────────────────────

def trail_validation(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("log_file_validation") else "Log file validation is off, so tampering with logs would go unnoticed."


def trail_kms(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("kms_key_id") else "Trail logs are not encrypted with a KMS key."


def kms_rotation(c: dict, inv: Inventory) -> Optional[str]:
    if c.get("state") != "Enabled" or c.get("spec") != "SYMMETRIC_DEFAULT" or c.get("origin") == "EXTERNAL":
        return None
    return None if need(c, "rotation_enabled") else "Automatic key rotation is off."


# ── edge ────────────────────────────────────────────────────────────

def lb_plain_http(c: dict, inv: Inventory) -> Optional[str]:
    if not c.get("internet_facing"):
        return None
    ports = [str(li.get("port")) for li in need(c, "listeners") if li.get("protocol") == "HTTP" and not li.get("redirects_to_https")]
    return f"Internet-facing listener on port {', '.join(ports)} serves plain HTTP without redirecting to HTTPS." if ports else None


def lb_old_tls(c: dict, inv: Inventory) -> Optional[str]:
    old = sorted({li["ssl_policy"] for li in need(c, "listeners") if li.get("ssl_policy") in OLD_TLS_POLICIES})
    return f"Listener uses TLS policy {', '.join(old)}, which still allows TLS 1.0/1.1." if old else None


def lb_waf(c: dict, inv: Inventory) -> Optional[str]:
    if not c.get("internet_facing") or c.get("type") != "application":
        return None
    return None if need(c, "waf_web_acl") else "This internet-facing application load balancer has no WAF web ACL."


def lb_access_logs(c: dict, inv: Inventory) -> Optional[str]:
    return None if need(c, "attributes").get("access_logs_enabled") else "Access logging is off."


def cert_expiry(c: dict, inv: Inventory) -> Optional[str]:
    expires = _parse(c.get("not_after"))
    if not c.get("in_use") or expires is None:
        return None
    days = (expires - inv.now).days
    if days < 0:
        return f"The certificate expired {-days} days ago and is still attached to a resource."
    return f"The certificate expires in {days} days and is in use." if days <= 30 else None


def eks_public_endpoint(c: dict, inv: Inventory) -> Optional[str]:
    if c.get("endpoint_public_access") and set(c.get("public_access_cidrs") or []) & WORLD:
        return "The Kubernetes API endpoint is reachable from the whole internet."
    return None


def eks_secrets(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("secrets_encrypted") else "Kubernetes secrets are not envelope-encrypted with a KMS key."


def eks_audit_logs(c: dict, inv: Inventory) -> Optional[str]:
    return None if "audit" in (c.get("enabled_log_types") or []) else "Control plane audit logging is off."


def ecr_scan(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("scan_on_push") else "Images are not scanned when pushed."


def ecr_mutable(c: dict, inv: Inventory) -> Optional[str]:
    return "Image tags are mutable, so a tag can be silently repointed to a different image." if c.get("tag_mutability") == "MUTABLE" else None


def secret_rotation(c: dict, inv: Inventory) -> Optional[str]:
    return None if c.get("rotation_enabled") else "Automatic rotation is not configured for this secret."


def dangling_dns(c: dict, inv: Inventory) -> Optional[str]:
    """Records pointing at an S3 website or load balancer that no longer exists in this account."""
    if c.get("private"):
        return None
    records = need(c, "pointer_records")
    buckets = {b.get("bucket_name", "").lower() for b in inv.configs("aws_s3_bucket")}
    balancers = {lb.get("dns_name", "").lower() for lb in inv.configs("aws_lb")}
    dangling = []
    for record in records:
        target = record.get("target", "")
        if ".s3-website" in target and inv.has("aws_s3_bucket"):
            # A website endpoint only serves the bucket named exactly like the record.
            if record["name"].lower() not in buckets:
                dangling.append(f"{record['name']} -> {target}")
        elif target.endswith(".elb.amazonaws.com") and inv.has("aws_lb"):
            if target.removeprefix("dualstack.") not in balancers:
                dangling.append(f"{record['name']} -> {target}")
    if not dangling:
        return None
    return (
        "Records point at resources that were not found in the synced regions of this account and may be claimable "
        f"by someone else (subdomain takeover): {'; '.join(dangling[:10])}"
        + (f" and {len(dangling) - 10} more." if len(dangling) > 10 else ".")
    )


RULES: list[Rule] = [
    Rule("GN-AWS-S3-001", "S3 bucket does not block public access", "CRITICAL", "storage", "aws_s3_bucket", s3_public_access,
         "Turn on all four Block Public Access settings for the bucket, or for the whole account.", "2.1.5"),
    Rule("GN-AWS-S3-002", "S3 bucket versioning is off", "MEDIUM", "storage", "aws_s3_bucket", s3_versioning,
         "Enable versioning so overwritten or deleted objects can be recovered."),
    Rule("GN-AWS-S3-003", "S3 bucket access logging is off", "LOW", "logging", "aws_s3_bucket", s3_logging,
         "Enable server access logging to a separate log bucket."),
    Rule("GN-AWS-ACCT-001", "Root user has no MFA", "CRITICAL", "iam", "aws_account", root_mfa,
         "Add an MFA device to the root user.", "1.5"),
    Rule("GN-AWS-ACCT-002", "Root user has access keys", "CRITICAL", "iam", "aws_account", root_keys,
         "Delete the root user's access keys and use IAM roles instead.", "1.4"),
    Rule("GN-AWS-ACCT-003", "IAM password policy is too weak", "MEDIUM", "iam", "aws_account", password_length,
         "Set the IAM password policy to a minimum length of 14.", "1.8"),
    Rule("GN-AWS-ACCT-004", "IAM password reuse is not prevented", "LOW", "iam", "aws_account", password_reuse,
         "Set password reuse prevention to 24.", "1.9"),
    Rule("GN-AWS-ACCT-005", "Account-level S3 public access block is not fully on", "HIGH", "storage", "aws_account", account_s3_block,
         "Turn on all four S3 Block Public Access settings at the account level.", "2.1.5"),
    Rule("GN-AWS-ACCT-006", "No multi-region CloudTrail trail is logging", "HIGH", "logging", "aws_account", no_trail,
         "Create a multi-region trail and make sure it is logging.", "3.1"),
    Rule("GN-AWS-IAM-001", "Console user without MFA", "HIGH", "iam", "aws_iam_user", user_mfa,
         "Require an MFA device for every user with a console password.", "1.10"),
    Rule("GN-AWS-IAM-002", "Access key older than 90 days", "MEDIUM", "iam", "aws_iam_user", old_access_keys,
         "Rotate the key, or replace long-lived keys with roles.", "1.14"),
    Rule("GN-AWS-IAM-003", "Administrator access attached directly to a user", "HIGH", "iam", "aws_iam_user", user_admin,
         "Grant administrator access through a role that is assumed when needed, not on the user."),
    Rule("GN-AWS-IAM-004", "Admin role can be assumed from another account", "HIGH", "iam", "aws_iam_role", role_cross_account_admin,
         "Confirm the external account is trusted, add an external ID or condition, and reduce the role's permissions."),
    Rule("GN-AWS-SG-001", "SSH open to the internet", "CRITICAL", "network", "aws_security_group", _admin_port(22),
         "Restrict port 22 to known addresses or use Session Manager.", "5.2"),
    Rule("GN-AWS-SG-002", "RDP open to the internet", "CRITICAL", "network", "aws_security_group", _admin_port(3389),
         "Restrict port 3389 to known addresses or use a bastion.", "5.2"),
    Rule("GN-AWS-SG-003", "Database or admin service port open to the internet", "HIGH", "network", "aws_security_group", sg_sensitive_ports,
         "Restrict these ports to the application's own security groups."),
    Rule("GN-AWS-SG-004", "Default security group allows traffic", "MEDIUM", "network", "aws_security_group", default_sg,
         "Remove all rules from the default security group.", "5.3"),
    Rule("GN-AWS-VPC-001", "VPC flow logs are off", "MEDIUM", "logging", "aws_vpc", vpc_flow_logs,
         "Enable flow logs for the VPC.", "3.9"),
    Rule("GN-AWS-RDS-001", "RDS instance is publicly accessible", "CRITICAL", "database", "aws_rds_instance", rds_public,
         "Turn off public accessibility and reach the database through private networking."),
    Rule("GN-AWS-RDS-002", "RDS storage is not encrypted", "HIGH", "encryption", "aws_rds_instance", rds_encryption,
         "Encryption cannot be added in place: restore an encrypted copy from a snapshot.", "2.3.1"),
    Rule("GN-AWS-RDS-003", "RDS backups are off or kept too briefly", "MEDIUM", "backup", "aws_rds_instance", rds_backups,
         "Set the backup retention period to at least 7 days."),
    Rule("GN-AWS-RDS-004", "RDS deletion protection is off", "LOW", "backup", "aws_rds_instance", rds_deletion_protection,
         "Enable deletion protection."),
    Rule("GN-AWS-EBS-001", "EBS volume is not encrypted", "HIGH", "encryption", "aws_ebs_volume", ebs_encryption,
         "Create an encrypted copy from a snapshot and replace the volume."),
    Rule("GN-AWS-REGION-001", "EBS encryption by default is off", "MEDIUM", "encryption", "aws_region_settings", ebs_default_encryption,
         "Enable EBS encryption by default in the region.", "2.2.1"),
    Rule("GN-AWS-REGION-002", "GuardDuty is not enabled", "MEDIUM", "monitoring", "aws_region_settings", guardduty,
         "Enable GuardDuty in every region in use."),
    Rule("GN-AWS-REGION-003", "AWS Config is not recording", "MEDIUM", "logging", "aws_region_settings", config_recorder,
         "Enable the AWS Config recorder in the region.", "3.5"),
    Rule("GN-AWS-EC2-001", "EC2 instance allows IMDSv1", "HIGH", "compute", "aws_ec2_instance", ec2_imdsv2,
         "Require IMDSv2 (set HttpTokens to required)."),
    Rule("GN-AWS-LAMBDA-001", "Lambda environment appears to hold secrets", "HIGH", "secrets", "aws_lambda_function", lambda_env_secrets,
         "Move the values to Secrets Manager or Parameter Store and read them at run time."),
    Rule("GN-AWS-LAMBDA-002", "Lambda runs on a retired runtime", "MEDIUM", "compute", "aws_lambda_function", lambda_runtime,
         "Move the function to a supported runtime."),
    Rule("GN-AWS-TRAIL-001", "CloudTrail log file validation is off", "MEDIUM", "logging", "aws_cloudtrail_trail", trail_validation,
         "Enable log file validation on the trail.", "3.2"),
    Rule("GN-AWS-TRAIL-002", "CloudTrail logs are not KMS-encrypted", "MEDIUM", "encryption", "aws_cloudtrail_trail", trail_kms,
         "Configure the trail to encrypt logs with a KMS key.", "3.7"),
    Rule("GN-AWS-KMS-001", "KMS key rotation is off", "MEDIUM", "encryption", "aws_kms_key", kms_rotation,
         "Enable automatic rotation for the key.", "3.8"),
    Rule("GN-AWS-LB-001", "Load balancer serves plain HTTP", "HIGH", "encryption", "aws_lb", lb_plain_http,
         "Redirect the HTTP listener to HTTPS."),
    Rule("GN-AWS-LB-002", "Load balancer allows TLS 1.0/1.1", "MEDIUM", "encryption", "aws_lb", lb_old_tls,
         "Use a TLS 1.2+ security policy such as ELBSecurityPolicy-TLS13-1-2-2021-06."),
    Rule("GN-AWS-LB-003", "Internet-facing load balancer has no WAF", "MEDIUM", "network", "aws_lb", lb_waf,
         "Associate a WAF web ACL with the load balancer."),
    Rule("GN-AWS-LB-004", "Load balancer access logging is off", "LOW", "logging", "aws_lb", lb_access_logs,
         "Enable access logs to S3."),
    Rule("GN-AWS-ACM-001", "Certificate in use is expired or about to expire", "HIGH", "encryption", "aws_acm_certificate", cert_expiry,
         "Renew or replace the certificate. Imported certificates do not renew automatically."),
    Rule("GN-AWS-EKS-001", "EKS API endpoint is open to the internet", "HIGH", "network", "aws_eks_cluster", eks_public_endpoint,
         "Restrict the public endpoint to known addresses or use the private endpoint only."),
    Rule("GN-AWS-EKS-002", "EKS secrets are not KMS-encrypted", "MEDIUM", "encryption", "aws_eks_cluster", eks_secrets,
         "Enable envelope encryption of Kubernetes secrets with a KMS key."),
    Rule("GN-AWS-EKS-003", "EKS audit logging is off", "MEDIUM", "logging", "aws_eks_cluster", eks_audit_logs,
         "Enable the audit log type in the cluster's control plane logging."),
    Rule("GN-AWS-ECR-001", "ECR repository does not scan images on push", "LOW", "container", "aws_ecr_repository", ecr_scan,
         "Enable scan on push."),
    Rule("GN-AWS-ECR-002", "ECR repository has mutable tags", "LOW", "container", "aws_ecr_repository", ecr_mutable,
         "Set tag immutability on the repository."),
    Rule("GN-AWS-SM-001", "Secret has no automatic rotation", "LOW", "secrets", "aws_secretsmanager_secret", secret_rotation,
         "Configure a rotation schedule for the secret."),
    Rule("GN-AWS-DNS-001", "DNS record points at a resource that no longer exists", "HIGH", "network", "aws_route53_zone", dangling_dns,
         "Delete the record, or recreate the resource it points to under your control."),
]

RULES_BY_TYPE: dict[str, list[Rule]] = {}
for _rule in RULES:
    RULES_BY_TYPE.setdefault(_rule.resource_type, []).append(_rule)


@dataclass
class Result:
    rule: Rule
    resource: dict           # {"resource_id", "resource_name", "resource_type", "region", "account_id", "config"}
    status: str              # "fail", "pass", "unknown"
    reason: str = ""


def evaluate(resources: list[dict], now: Optional[datetime] = None) -> list[Result]:
    """Run every rule on every resource of one cloud account."""
    inventory = Inventory(now=now or datetime.now(timezone.utc))
    for resource in resources:
        inventory.by_type.setdefault(resource["resource_type"], []).append(resource)
    results: list[Result] = []
    for resource in resources:
        for rule in RULES_BY_TYPE.get(resource["resource_type"], []):
            try:
                reason = rule.check(resource.get("config") or {}, inventory)
            except Unknown as exc:
                results.append(Result(rule, resource, "unknown", f"'{exc}' could not be read from AWS."))
                continue
            results.append(Result(rule, resource, "fail" if reason else "pass", reason or ""))
    return results

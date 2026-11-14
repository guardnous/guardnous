"""
Enterprise Policy Engine — evaluates scan findings against security policies.

Uses a **dual matching strategy**:
1. Structured matching — exact rule_id prefix matching (high confidence, no false positives)
2. Keyword matching — category + keyword checks on title/description (fallback)

Built-in policies cover: S3 public access, encryption requirements, IAM wildcards,
network exposure, logging, key rotation, and more.

Supports custom organizational policies, policy exceptions (waivers) with expiry,
and minimum severity thresholds per policy.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class Policy:
    id: str
    name: str
    description: str
    severity: str
    category: str  # encryption, network, iam, storage, logging, general
    cloud_providers: list[str]  # aws, azure, gcp, all
    # Structured matchers (preferred — exact, no false positives)
    rule_id_prefixes: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    min_severity: str | None = None  # only match findings at or above this severity
    # Legacy regex matchers (fallback for custom policies)
    rule_patterns: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class PolicyException:
    """A waiver/suppression for a specific policy + scope."""
    policy_id: str
    reason: str
    approved_by: str
    scope: str = "global"  # global, repo:<name>, rule:<rule_id>
    expires_at: datetime | None = None


@dataclass
class PolicyResult:
    policy_id: str
    policy_name: str
    status: str  # passed, failed, not_applicable, waived
    severity: str
    category: str
    description: str
    findings_matched: int = 0
    details: str = ""
    match_method: str = ""  # structured, keyword, regex


BUILT_IN_POLICIES: list[dict] = [
    # ── Storage ──
    {
        "id": "POL-S3-001",
        "name": "No Public S3 Buckets",
        "description": "S3 buckets must not allow public access via ACL or bucket policy",
        "severity": "CRITICAL",
        "category": "storage",
        "cloud_providers": ["aws"],
        # Public ACLs and the four public-access-block settings
        "rule_id_prefixes": ["CKV_AWS_20", "CKV_AWS_57", "CKV_AWS_53", "CKV_AWS_54",
                             "CKV_AWS_55", "CKV_AWS_56", "CKV2_AWS_6",
                             "AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0091",
                             "AVD-AWS-0092", "AVD-AWS-0093", "AVD-AWS-0094",
                             "SD-TF-003", "SD-TF-026", "SD-CF-003", "SD-CF-029",
                             "SG-aws-s3-public-acl", "SG-aws-s3-public-read-write"],
        "resource_types": ["aws_s3_bucket", "aws_s3_bucket_acl",
                           "aws_s3_bucket_public_access_block"],
        "categories": [],
    },
    {
        "id": "POL-S3-002",
        "name": "S3 Bucket Encryption Required",
        "description": "All S3 buckets must have server-side encryption enabled",
        "severity": "HIGH",
        "category": "encryption",
        "cloud_providers": ["aws"],
        "rule_id_prefixes": ["CKV_AWS_19", "CKV_AWS_145",
                             "AVD-AWS-0088", "AVD-AWS-0132",
                             "SD-TF-002", "SD-CF-002", "SG-aws-s3-no-encryption"],
        "resource_types": ["aws_s3_bucket", "aws_s3_bucket_server_side_encryption_configuration"],
        "categories": [],
    },
    {
        "id": "POL-S3-003",
        "name": "S3 Versioning Enabled",
        "description": "S3 buckets should have versioning enabled for data protection",
        "severity": "MEDIUM",
        "category": "storage",
        "cloud_providers": ["aws"],
        "rule_id_prefixes": ["CKV_AWS_21", "AVD-AWS-0090",
                             "SD-TF-027", "SD-CF-030", "SG-aws-s3-no-versioning"],
        "resource_types": ["aws_s3_bucket", "aws_s3_bucket_versioning"],
        "categories": [],
    },
    # ── Encryption ──
    {
        "id": "POL-ENC-001",
        "name": "Encryption at Rest Required",
        "description": "All storage and databases must use encryption at rest",
        "severity": "HIGH",
        "category": "encryption",
        "cloud_providers": ["aws", "azure", "gcp"],
        # Databases, volumes, queues and caches (S3 has its own policy)
        "rule_id_prefixes": ["CKV_AWS_3", "CKV_AWS_16", "CKV_AWS_26", "CKV_AWS_27",
                             "CKV_AWS_119", "CKV_AZURE_2",
                             "AVD-AWS-0025", "AVD-AWS-0026", "AVD-AWS-0027",
                             "AVD-AWS-0080", "AVD-AWS-0095", "AVD-AWS-0096", "AVD-AWS-0131",
                             "AVD-AZU-0060", "AVD-AZU-0061", "AVD-GCP-0033", "AVD-GCP-0066",
                             "SD-TF-004", "SD-TF-010", "SD-TF-015", "SD-TF-018",
                             "SD-TF-021", "SD-TF-034", "SD-TF-036",
                             "SD-CF-004", "SD-CF-010", "SD-CF-015", "SD-CF-018",
                             "SD-CF-020", "SD-CF-025",
                             "SD-BI-002", "SD-BI-007", "SD-BI-035",
                             "SG-aws-rds-no-encryption"],
        "resource_types": ["aws_rds_cluster", "aws_ebs_volume", "aws_db_instance",
                           "azurerm_storage_account", "azurerm_managed_disk",
                           "google_compute_disk"],
        "categories": [],
    },
    {
        "id": "POL-ENC-002",
        "name": "Encryption in Transit Required",
        "description": "All network communication must use TLS/SSL encryption",
        "severity": "HIGH",
        "category": "encryption",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_AWS_2", "CKV_AWS_103", "CKV_AZURE_3",
                             "AVD-AZU-0006", "AVD-AZU-0011", "AVD-AZU-0059", "AVD-AZU-0072",
                             "SD-CF-017", "SD-BI-005", "SD-BI-012", "SD-BI-024", "SD-BI-029",
                             "SG-azure-storage-https-only"],
        "categories": [],
    },
    {
        "id": "POL-ENC-003",
        "name": "KMS Key Rotation",
        "description": "KMS/Key Vault keys must have automatic rotation enabled",
        "severity": "MEDIUM",
        "category": "encryption",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_AWS_7", "CKV_GCP_43", "AVD-AWS-0065"],
        "resource_types": ["aws_kms_key", "azurerm_key_vault_key"],
        "categories": [],
    },
    # ── IAM ──
    {
        "id": "POL-IAM-001",
        "name": "No Wildcard IAM Permissions",
        "description": "IAM policies must not use wildcard (*) actions or resources",
        "severity": "CRITICAL",
        "category": "iam",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_AWS_1", "CKV_AWS_62", "CKV_AWS_63", "AVD-AWS-0057",
                             "SD-TF-006", "SD-TF-007", "SD-CF-006", "SD-CF-007"],
        "resource_types": ["aws_iam_policy", "aws_iam_role_policy",
                           "aws_iam_user_policy", "aws_iam_policy_document"],
        "categories": [],
    },
    {
        "id": "POL-IAM-002",
        "name": "MFA Required for IAM Users",
        "description": "All IAM users with console access must have MFA enabled",
        "severity": "HIGH",
        "category": "iam",
        "cloud_providers": ["aws"],
        "rule_id_prefixes": ["AVD-AWS-0123", "AVD-AWS-0145"],
        "categories": [],
    },
    {
        "id": "POL-IAM-003",
        "name": "No Root Account Access Keys",
        "description": "AWS root account should not have access keys",
        "severity": "CRITICAL",
        "category": "iam",
        "cloud_providers": ["aws"],
        # Not visible in IaC; only a scanner that inspects the live account reports it
        "rule_id_prefixes": ["AVD-AWS-0141"],
        "categories": [],
    },
    # ── Network ──
    {
        "id": "POL-NET-001",
        "name": "No Open Security Groups",
        "description": "Security groups must not allow unrestricted inbound access (0.0.0.0/0)",
        "severity": "CRITICAL",
        "category": "network",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_260",
                             "CKV_AZURE_9", "CKV_AZURE_10",
                             "AVD-AWS-0107", "AVD-AZU-0047", "AVD-GCP-0027",
                             "SD-TF-001", "SD-CF-001", "SD-BI-004",
                             "SG-aws-security-group-open-ingress"],
        "resource_types": ["aws_security_group", "aws_security_group_rule",
                           "azurerm_network_security_group", "azurerm_network_security_rule",
                           "google_compute_firewall"],
        "categories": [],
    },
    {
        "id": "POL-NET-002",
        "name": "No SSH from Internet",
        "description": "SSH (port 22) must not be accessible from the public internet",
        "severity": "CRITICAL",
        "category": "network",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_AWS_24", "CKV_AZURE_10",
                             "AVD-AZU-0050", "AVD-GCP-0071",
                             "SD-TF-012", "SD-CF-012"],
        "resource_types": ["aws_security_group", "aws_security_group_rule",
                           "azurerm_network_security_rule",
                           "google_compute_firewall"],
        "categories": [],
    },
    {
        "id": "POL-NET-003",
        "name": "No RDP from Internet",
        "description": "RDP (port 3389) must not be accessible from the public internet",
        "severity": "CRITICAL",
        "category": "network",
        "cloud_providers": ["aws", "azure"],
        "rule_id_prefixes": ["CKV_AWS_25", "CKV_AZURE_9", "AVD-AZU-0048",
                             "SD-TF-013", "SD-CF-013"],
        "resource_types": ["aws_security_group", "aws_security_group_rule",
                           "azurerm_network_security_rule"],
        "categories": [],
    },
    # ── Logging ──
    {
        "id": "POL-LOG-001",
        "name": "CloudTrail / Activity Log Enabled",
        "description": "Cloud audit logging must be enabled in all regions",
        "severity": "HIGH",
        "category": "logging",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_AWS_67", "AVD-AWS-0014",
                             "SD-TF-028", "SD-CF-021"],
        "resource_types": ["aws_cloudtrail", "azurerm_monitor_log_profile"],
        "categories": [],
    },
    {
        "id": "POL-LOG-002",
        "name": "VPC Flow Logs Enabled",
        "description": "VPC/VNet flow logs must be enabled for network monitoring",
        "severity": "MEDIUM",
        "category": "logging",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV2_AWS_11", "CKV_AZURE_12", "CKV_GCP_26",
                             "AVD-AWS-0178", "SD-TF-020"],
        "resource_types": ["aws_vpc", "aws_flow_log",
                           "azurerm_network_watcher_flow_log"],
        "categories": [],
    },
    # ── Azure-specific ──
    {
        "id": "POL-AZ-001",
        "name": "Azure Storage HTTPS Only",
        "description": "Azure Storage accounts must enforce HTTPS-only traffic",
        "severity": "HIGH",
        "category": "encryption",
        "cloud_providers": ["azure"],
        "rule_id_prefixes": ["CKV_AZURE_3", "AVD-AZU-0059", "SG-azure-storage-https-only"],
        "resource_types": ["azurerm_storage_account"],
        "categories": [],
    },
    {
        "id": "POL-AZ-002",
        "name": "Azure Key Vault Soft Delete",
        "description": "Azure Key Vaults must have soft-delete and purge protection enabled",
        "severity": "MEDIUM",
        "category": "storage",
        "cloud_providers": ["azure"],
        "rule_id_prefixes": ["CKV_AZURE_42", "CKV_AZURE_110", "CKV_AZURE_111",
                             "AVD-AZU-0016", "SD-BI-008", "SD-BI-028"],
        "resource_types": ["azurerm_key_vault"],
        "categories": [],
    },
    # ── GCP-specific ──
    {
        "id": "POL-GCP-001",
        "name": "GCP Uniform Bucket-Level Access",
        "description": "GCS buckets should use uniform bucket-level access control",
        "severity": "MEDIUM",
        "category": "storage",
        "cloud_providers": ["gcp"],
        "rule_id_prefixes": ["CKV_GCP_29", "AVD-GCP-0002"],
        "resource_types": ["google_storage_bucket"],
        "categories": [],
    },
    # ── Secrets ──
    {
        "id": "POL-SEC-001",
        "name": "No Hardcoded Secrets",
        "description": "Source code and IaC files must not contain hardcoded credentials",
        "severity": "CRITICAL",
        "category": "secrets",
        "cloud_providers": ["aws", "azure", "gcp"],
        # Topic-wide by design: any finding a scanner classifies as a secret
        "rule_id_prefixes": ["SEC-", "GL-", "TRIVY-SECRET-", "CKV_SECRET_",
                             "SD-TF-009", "SD-CF-009", "SD-BI-010"],
        "categories": ["secrets"],
    },
    # ── Container / Kubernetes ──
    {
        "id": "POL-K8S-001",
        "name": "No Privileged Containers",
        "description": "Kubernetes pods must not run in privileged mode",
        "severity": "HIGH",
        "category": "iam",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_K8S_16", "AVD-KSV-0017",
                             "SG-k8s-privileged-container", "SG-docker-compose-privileged"],
        "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
        "categories": [],
    },
    {
        "id": "POL-DB-001",
        "name": "No Public Database Access",
        "description": "Managed databases (RDS, Azure SQL, Cloud SQL) must not be publicly accessible",
        "severity": "CRITICAL",
        "category": "network",
        "cloud_providers": ["aws", "azure", "gcp"],
        "rule_id_prefixes": ["CKV_AWS_17", "CKV_GCP_11",
                             "AVD-AWS-0082", "AVD-AWS-0180", "AVD-AZU-0022", "AVD-AZU-0029",
                             "AVD-GCP-0017",
                             "SD-TF-005", "SD-CF-005", "SD-BI-006", "SD-BI-030",
                             "SG-aws-rds-publicly-accessible"],
        "resource_types": [
            "aws_db_instance",
            "aws_rds_cluster",
            "azurerm_sql_server",
            "azurerm_postgresql_server",
            "google_sql_database_instance",
        ],
        "categories": [],
    },
    # ── API Security ──
    {
        "id": "POL-API-001",
        "name": "API Security Standards",
        "description": "Enforces secure API development practices including authentication, rate limiting, input validation, and proper error handling",
        "severity": "HIGH",
        "category": "sast",
        "cloud_providers": ["aws", "azure", "gcp"],
        # API Gateway: open access to back ends, access logging, WAF; App Service auth
        "rule_id_prefixes": ["CKV_AWS_59", "CKV_AWS_76", "CKV2_AWS_29", "SD-BI-033"],
        "resource_types": [
            "aws_api_gateway_rest_api",
            "aws_api_gateway_method_settings",
            "aws_apigatewayv2_api",
            "aws_apigatewayv2_stage",
            "azurerm_api_management",
            "azurerm_api_management_api",
            "google_apikeys_key",
        ],
        "categories": [],
    },
]

# Severity ranking for threshold checks
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def builtin_policy_rules(policy: dict) -> list[dict]:
    """The ``rules`` value stored on the SecurityPolicy row of a built-in policy."""
    return [{
        "policy_id": policy["id"],
        "rule_id_prefixes": list(policy.get("rule_id_prefixes", [])),
        "categories": list(policy.get("categories", [])),
        "resource_types": list(policy.get("resource_types", [])),
        "cloud_providers": list(policy.get("cloud_providers", [])),
    }]


# Cloud posture rules (app/services/cloud_posture/rules.py) that each policy also
# covers, so one policy applies to both the code and the running cloud resource.
CLOUD_RULES_BY_POLICY: dict[str, list[str]] = {
    "POL-S3-001": ["GN-AWS-S3-001", "GN-AWS-ACCT-005"],
    "POL-S3-003": ["GN-AWS-S3-002"],
    "POL-ENC-001": ["GN-AWS-RDS-002", "GN-AWS-EBS-001", "GN-AWS-REGION-001", "GN-AWS-EKS-002", "GN-AWS-TRAIL-002"],
    "POL-ENC-002": ["GN-AWS-LB-001", "GN-AWS-LB-002", "GN-AWS-ACM-001"],
    "POL-ENC-003": ["GN-AWS-KMS-001"],
    "POL-IAM-001": ["GN-AWS-IAM-003", "GN-AWS-IAM-004"],
    "POL-IAM-002": ["GN-AWS-IAM-001", "GN-AWS-ACCT-001"],
    "POL-IAM-003": ["GN-AWS-ACCT-002"],
    "POL-NET-001": ["GN-AWS-SG-003", "GN-AWS-SG-004", "GN-AWS-EKS-001"],
    "POL-NET-002": ["GN-AWS-SG-001"],
    "POL-NET-003": ["GN-AWS-SG-002"],
    "POL-LOG-001": ["GN-AWS-ACCT-006", "GN-AWS-TRAIL-001"],
    "POL-LOG-002": ["GN-AWS-VPC-001"],
    "POL-SEC-001": ["GN-AWS-LAMBDA-001"],
    "POL-DB-001": ["GN-AWS-RDS-001"],
}
for _policy in BUILT_IN_POLICIES:
    _policy["rule_id_prefixes"] = [*_policy.get("rule_id_prefixes", []), *CLOUD_RULES_BY_POLICY.get(_policy["id"], [])]

BUILT_IN_BY_ID: dict[str, dict] = {p["id"]: p for p in BUILT_IN_POLICIES}


def severity_for_rule(rule_id: str) -> str | None:
    """Highest severity among the built-in policies that name this exact rule.

    For scanners that report no severity of their own. Family prefixes such as
    ``SEC-`` are ignored: only a policy that lists the rule itself counts.
    """
    from app.services.governance.finding_policies import _canonical

    rid = _canonical(rule_id)
    best = None
    for policy in BUILT_IN_POLICIES:
        if any(_canonical(p) == rid for p in policy.get("rule_id_prefixes", [])):
            sev = policy.get("severity", "MEDIUM").upper()
            if best is None or _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(best, 0):
                best = sev
    return best


class PolicyEngine:
    """Evaluates findings against security policies using structured + keyword matching."""

    def __init__(
        self,
        custom_policies: list[dict] | None = None,
        exceptions: list[dict] | None = None,
    ):
        self.policies: list[Policy] = []
        for pd in BUILT_IN_POLICIES:
            self.policies.append(Policy(**pd))
        if custom_policies:
            for pd in custom_policies:
                try:
                    self.policies.append(Policy(**pd))
                except Exception as e:
                    logger.warning("Invalid custom policy: %s", e)

        self.exceptions: list[PolicyException] = []
        if exceptions:
            for ex in exceptions:
                try:
                    expires = ex.get("expires_at")
                    if isinstance(expires, str):
                        expires = datetime.fromisoformat(expires)
                    self.exceptions.append(PolicyException(
                        policy_id=ex["policy_id"],
                        reason=ex.get("reason", ""),
                        approved_by=ex.get("approved_by", ""),
                        scope=ex.get("scope", "global"),
                        expires_at=expires,
                    ))
                except Exception as e:
                    logger.warning("Invalid policy exception: %s", e)

    def _is_waived(self, policy_id: str) -> PolicyException | None:
        """Check if a policy has an active (non-expired) exception."""
        now = datetime.now(timezone.utc)
        for ex in self.exceptions:
            if ex.policy_id != policy_id:
                continue
            if ex.expires_at and ex.expires_at < now:
                continue
            return ex
        return None

    def _match_structured(self, finding: dict, policy: Policy) -> bool:
        """Match using exact rule_id prefixes, resource types, and categories."""
        rule_id = finding.get("rule_id", "")
        resource_type = finding.get("resource_type", "")
        category = finding.get("category", "")
        severity = finding.get("severity", "INFO")

        # Severity threshold filter
        if policy.min_severity:
            if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(policy.min_severity, 0):
                return False

        # A policy that names specific rules is decided by those rules alone.
        # Falling through to resource type or keywords would make "No Public
        # S3 Buckets" fail on any finding that merely involves an S3 bucket.
        if policy.rule_id_prefixes:
            from app.services.governance.finding_policies import rule_id_matches
            if any(rule_id_matches(prefix, rule_id) for prefix in policy.rule_id_prefixes):
                return True
            if not policy.categories:
                return False

        # Resource type match
        if policy.resource_types and resource_type:
            if resource_type in policy.resource_types:
                return True

        # Category match (only if policy has categories defined)
        if policy.categories and category:
            if category.lower() in [c.lower() for c in policy.categories]:
                # Category alone is too broad — require category + relevant keyword
                title = finding.get("title", "").lower()
                desc = finding.get("description", "").lower()
                combined = f"{title} {desc}"
                policy_keywords = policy.name.lower().split()
                # At least 2 words from policy name must appear in title/description
                match_count = sum(1 for kw in policy_keywords
                                  if len(kw) > 3 and kw in combined)
                if match_count >= 2:
                    return True

        return False

    def _match_regex(self, finding: dict, policy: Policy) -> bool:
        """Legacy regex-based matching (fallback for custom policies)."""
        if not policy.rule_patterns:
            return False
        rule_id = finding.get("rule_id", "")
        title = finding.get("title", "")
        desc = finding.get("description", "")
        check_str = f"{rule_id} {title} {desc}".lower()
        for pattern in policy.rule_patterns:
            if re.search(pattern, check_str, re.IGNORECASE):
                return True
        return False

    def evaluate(
        self,
        findings: list[dict],
        cloud_provider: str | None = None,
    ) -> tuple[list[PolicyResult], dict]:
        """
        Evaluate findings against all enabled policies.
        findings: list of dicts with at least {rule_id, title, severity, category}
        Returns (results, stats)
        """
        results: list[PolicyResult] = []
        passed = 0
        failed = 0
        not_applicable = 0
        waived = 0

        for policy in self.policies:
            if not policy.enabled:
                continue

            # Check cloud provider applicability
            if cloud_provider and "all" not in policy.cloud_providers:
                if cloud_provider.lower() not in policy.cloud_providers:
                    results.append(PolicyResult(
                        policy_id=policy.id, policy_name=policy.name,
                        status="not_applicable", severity=policy.severity,
                        category=policy.category, description=policy.description,
                    ))
                    not_applicable += 1
                    continue

            # Check for active exception/waiver
            exception = self._is_waived(policy.id)
            if exception:
                results.append(PolicyResult(
                    policy_id=policy.id, policy_name=policy.name,
                    status="waived", severity=policy.severity,
                    category=policy.category, description=policy.description,
                    details=f"Waived by {exception.approved_by}: {exception.reason}",
                    match_method="waiver",
                ))
                waived += 1
                continue

            # Match findings — try structured first, fall back to regex
            matched_count = 0
            match_method = "none"
            for f in findings:
                if self._match_structured(f, policy):
                    matched_count += 1
                    match_method = "structured"
                elif self._match_regex(f, policy):
                    matched_count += 1
                    if match_method != "structured":
                        match_method = "regex"

            if matched_count > 0:
                results.append(PolicyResult(
                    policy_id=policy.id, policy_name=policy.name,
                    status="failed", severity=policy.severity,
                    category=policy.category, description=policy.description,
                    findings_matched=matched_count,
                    details=f"{matched_count} finding(s) violate this policy",
                    match_method=match_method,
                ))
                failed += 1
            else:
                results.append(PolicyResult(
                    policy_id=policy.id, policy_name=policy.name,
                    status="passed", severity=policy.severity,
                    category=policy.category, description=policy.description,
                    match_method="structured",
                ))
                passed += 1

        stats = {
            "total_policies": len(results),
            "passed": passed,
            "failed": failed,
            "waived": waived,
            "not_applicable": not_applicable,
            "by_category": {},
            "by_severity": {
                "CRITICAL": sum(1 for r in results if r.status == "failed" and r.severity == "CRITICAL"),
                "HIGH": sum(1 for r in results if r.status == "failed" and r.severity == "HIGH"),
                "MEDIUM": sum(1 for r in results if r.status == "failed" and r.severity == "MEDIUM"),
                "LOW": sum(1 for r in results if r.status == "failed" and r.severity == "LOW"),
            },
        }
        for r in results:
            cat = r.category
            if cat not in stats["by_category"]:
                stats["by_category"][cat] = {"passed": 0, "failed": 0, "not_applicable": 0, "waived": 0}
            stats["by_category"][cat][r.status] += 1

        return results, stats

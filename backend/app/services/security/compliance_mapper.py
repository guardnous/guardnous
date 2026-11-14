"""
Enterprise Compliance Mapper — maps security findings to regulatory
and industry compliance frameworks.

Supported frameworks: CIS Benchmarks, NIST 800-53, SOC 2, PCI-DSS, HIPAA, ISO 27001
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ComplianceMapping:
    framework: str       # CIS, NIST-800-53, SOC2, PCI-DSS, HIPAA, ISO-27001
    control_id: str      # e.g. CIS-1.1, AC-2, CC6.1
    control_name: str
    section: str         # e.g. "Identity and Access Management"
    status: str          # pass, fail, not_evaluated
    finding_count: int = 0
    details: str = ""


# Category-to-framework control mapping
# Each entry: category_keyword -> list of (framework, control_id, control_name, section)
COMPLIANCE_MAP: dict[str, list[tuple[str, str, str, str]]] = {
    # ── Encryption ──
    "encryption": [
        ("CIS", "CIS-2.1", "Ensure encryption at rest is enabled", "Storage"),
        ("NIST-800-53", "SC-28", "Protection of Information at Rest", "System and Communications Protection"),
        ("SOC2", "CC6.1", "Logical and Physical Access Controls", "Common Criteria"),
        ("PCI-DSS", "3.4", "Render PAN unreadable anywhere it is stored", "Protect Stored Cardholder Data"),
        ("HIPAA", "164.312(a)(2)(iv)", "Encryption and Decryption", "Technical Safeguards"),
        ("ISO-27001", "A.10.1.1", "Policy on the use of cryptographic controls", "Cryptography"),
    ],
    "tls": [
        ("CIS", "CIS-4.1", "Ensure TLS 1.2+ is enforced", "Network"),
        ("NIST-800-53", "SC-8", "Transmission Confidentiality and Integrity", "System and Communications Protection"),
        ("PCI-DSS", "4.1", "Use strong cryptography for transmission", "Encrypt Transmission"),
        ("HIPAA", "164.312(e)(1)", "Transmission Security", "Technical Safeguards"),
        ("ISO-27001", "A.13.1.1", "Network controls", "Communications Security"),
    ],
    # ── IAM / Access ──
    "iam": [
        ("CIS", "CIS-1.1", "Avoid use of root account", "Identity and Access Management"),
        ("NIST-800-53", "AC-2", "Account Management", "Access Control"),
        ("SOC2", "CC6.2", "Authorization and Access", "Common Criteria"),
        ("PCI-DSS", "7.1", "Limit access to system components", "Restrict Access"),
        ("HIPAA", "164.312(a)(1)", "Access Control", "Technical Safeguards"),
        ("ISO-27001", "A.9.2.1", "User registration and de-registration", "Access Control"),
    ],
    "wildcard": [
        ("CIS", "CIS-1.16", "Ensure IAM policies are not overly permissive", "IAM"),
        ("NIST-800-53", "AC-6", "Least Privilege", "Access Control"),
        ("SOC2", "CC6.3", "Role-Based Access", "Common Criteria"),
        ("PCI-DSS", "7.1.2", "Restrict access based on need to know", "Restrict Access"),
        ("ISO-27001", "A.9.4.1", "Information access restriction", "Access Control"),
    ],
    "mfa": [
        ("CIS", "CIS-1.2", "Ensure MFA is enabled", "Identity and Access Management"),
        ("NIST-800-53", "IA-2(1)", "Multi-factor Authentication", "Identification and Authentication"),
        ("PCI-DSS", "8.3", "Secure all individual access with MFA", "Identify and Authenticate"),
        ("HIPAA", "164.312(d)", "Person or Entity Authentication", "Technical Safeguards"),
        ("ISO-27001", "A.9.4.2", "Secure log-on procedures", "Access Control"),
    ],
    # ── Network ──
    "network": [
        ("CIS", "CIS-5.1", "Ensure no security groups allow unrestricted ingress", "Networking"),
        ("NIST-800-53", "SC-7", "Boundary Protection", "System and Communications Protection"),
        ("SOC2", "CC6.6", "Logical Access Security Measures", "Common Criteria"),
        ("PCI-DSS", "1.2", "Restrict inbound/outbound traffic", "Install and Maintain Firewall"),
        ("HIPAA", "164.312(e)(1)", "Transmission Security", "Technical Safeguards"),
        ("ISO-27001", "A.13.1.1", "Network controls", "Communications Security"),
    ],
    "ssh": [
        ("CIS", "CIS-5.2", "Ensure SSH is not publicly accessible", "Networking"),
        ("NIST-800-53", "AC-17", "Remote Access", "Access Control"),
        ("PCI-DSS", "2.3", "Encrypt non-console administrative access", "System Configuration"),
        ("ISO-27001", "A.13.1.2", "Security of network services", "Communications Security"),
    ],
    "rdp": [
        ("CIS", "CIS-5.3", "Ensure RDP is not publicly accessible", "Networking"),
        ("NIST-800-53", "AC-17", "Remote Access", "Access Control"),
        ("PCI-DSS", "2.3", "Encrypt non-console administrative access", "System Configuration"),
    ],
    # ── Logging ──
    "logging": [
        ("CIS", "CIS-3.1", "Ensure audit logging is enabled", "Logging and Monitoring"),
        ("NIST-800-53", "AU-2", "Audit Events", "Audit and Accountability"),
        ("SOC2", "CC7.2", "System Monitoring", "Common Criteria"),
        ("PCI-DSS", "10.1", "Implement audit trails", "Track and Monitor Access"),
        ("HIPAA", "164.312(b)", "Audit Controls", "Technical Safeguards"),
        ("ISO-27001", "A.12.4.1", "Event logging", "Operations Security"),
    ],
    # ── Storage ──
    "storage": [
        ("CIS", "CIS-2.3", "Ensure storage access is properly restricted", "Storage"),
        ("NIST-800-53", "SC-28", "Protection of Information at Rest", "System and Communications Protection"),
        ("SOC2", "CC6.1", "Logical and Physical Access Controls", "Common Criteria"),
        ("PCI-DSS", "3.1", "Keep cardholder data storage minimal", "Protect Stored Data"),
        ("ISO-27001", "A.8.2.3", "Handling of assets", "Asset Management"),
    ],
    "public_access": [
        ("CIS", "CIS-2.2", "Ensure buckets are not publicly accessible", "Storage"),
        ("NIST-800-53", "AC-3", "Access Enforcement", "Access Control"),
        ("PCI-DSS", "7.1", "Limit access to system components", "Restrict Access"),
        ("ISO-27001", "A.9.1.2", "Access to networks and network services", "Access Control"),
    ],
    # ── Secrets ──
    "secrets": [
        ("CIS", "CIS-1.20", "Ensure no hardcoded secrets in source code", "IAM"),
        ("NIST-800-53", "IA-5", "Authenticator Management", "Identification and Authentication"),
        ("SOC2", "CC6.1", "Logical and Physical Access Controls", "Common Criteria"),
        ("PCI-DSS", "6.5.3", "Insecure cryptographic storage", "Develop Secure Applications"),
        ("HIPAA", "164.312(a)(2)(iv)", "Encryption and Decryption", "Technical Safeguards"),
        ("ISO-27001", "A.9.2.4", "Management of secret authentication information", "Access Control"),
    ],
}

# Keywords in rule_id/title/description that map to categories above
KEYWORD_CATEGORIES: list[tuple[str, list[str]]] = [
    ("encryption", ["encrypt", "kms", "sse", "server-side"]),
    ("tls", ["tls", "ssl", "https", "transit"]),
    ("iam", ["iam", "role", "policy", "permission", "access key", "user"]),
    ("wildcard", ["wildcard", "star", "overly permissive", "admin access"]),
    ("mfa", ["mfa", "multi-factor", "two-factor", "2fa"]),
    ("network", ["security group", "firewall", "ingress", "egress", "0.0.0.0"]),
    ("ssh", ["ssh", "port 22"]),
    ("rdp", ["rdp", "port 3389"]),
    ("logging", ["cloudtrail", "flow log", "audit log", "monitoring", "activity log"]),
    ("storage", ["bucket", "storage account", "blob", "s3"]),
    ("public_access", ["public access", "public acl", "publicly accessible"]),
    ("secrets", ["secret", "credential", "hardcoded", "api key", "token", "password", "private key"]),
]


class ComplianceMapper:
    """Maps findings to compliance framework controls."""

    SUPPORTED_FRAMEWORKS = ["CIS", "NIST-800-53", "SOC2", "PCI-DSS", "HIPAA", "ISO-27001"]

    def _categorize_finding(self, finding: dict) -> set[str]:
        """Determine which compliance categories a finding maps to."""
        categories = set()
        text = f"{finding.get('rule_id', '')} {finding.get('title', '')} {finding.get('description', '')}".lower()
        for category, keywords in KEYWORD_CATEGORIES:
            if any(kw in text for kw in keywords):
                categories.add(category)
        # Fallback: use the finding's own category
        fc = finding.get("category", "").lower()
        if fc in COMPLIANCE_MAP:
            categories.add(fc)
        return categories

    def map_findings(
        self,
        findings: list[dict],
        frameworks: list[str] | None = None,
    ) -> tuple[list[ComplianceMapping], dict]:
        """
        Map findings to compliance controls.
        findings: list of dicts with {rule_id, title, description, severity, category}
        frameworks: filter to specific frameworks (default: all)
        Returns (mappings, stats)
        """
        target_fw = set(frameworks) if frameworks else set(self.SUPPORTED_FRAMEWORKS)

        # Collect all violated categories
        violated_categories: dict[str, int] = {}
        for f in findings:
            for cat in self._categorize_finding(f):
                violated_categories[cat] = violated_categories.get(cat, 0) + 1

        # Build compliance mappings
        mappings: list[ComplianceMapping] = []
        seen = set()

        # All known categories
        all_categories = set(COMPLIANCE_MAP.keys())

        for category in all_categories:
            controls = COMPLIANCE_MAP[category]
            for fw, control_id, control_name, section in controls:
                if fw not in target_fw:
                    continue
                key = (fw, control_id)
                if key in seen:
                    continue
                seen.add(key)

                count = violated_categories.get(category, 0)
                status = "fail" if count > 0 else "pass"
                mappings.append(ComplianceMapping(
                    framework=fw,
                    control_id=control_id,
                    control_name=control_name,
                    section=section,
                    status=status,
                    finding_count=count,
                    details=f"{count} finding(s) mapped" if count > 0 else "No violations found",
                ))

        # Stats
        stats: dict = {
            "frameworks_evaluated": list(target_fw),
            "total_controls": len(mappings),
            "controls_passed": sum(1 for m in mappings if m.status == "pass"),
            "controls_failed": sum(1 for m in mappings if m.status == "fail"),
            "by_framework": {},
        }
        for m in mappings:
            if m.framework not in stats["by_framework"]:
                stats["by_framework"][m.framework] = {"passed": 0, "failed": 0, "total": 0}
            stats["by_framework"][m.framework]["total"] += 1
            if m.status == "pass":
                stats["by_framework"][m.framework]["passed"] += 1
            else:
                stats["by_framework"][m.framework]["failed"] += 1

        return mappings, stats

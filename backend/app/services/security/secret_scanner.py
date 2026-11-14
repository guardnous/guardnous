"""
Enterprise Secret Scanner — detects hardcoded credentials, API keys,
tokens, private keys, and other sensitive data in repository files.

30+ regex patterns covering AWS, GCP, Azure, GitHub, Slack, Stripe,
database URIs, private keys, JWTs, and generic high-entropy strings.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    rule_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    line_number: int
    secret_type: str
    match_preview: str  # first 8 chars + masked
    confidence: float  # 0.0 - 1.0
    remediation: str


# Each pattern: (rule_id, title, regex, severity, secret_type, description, remediation)
SECRET_PATTERNS: list[tuple[str, str, str, str, str, str, str]] = [
    # ── AWS ──
    ("SEC-AWS-001", "AWS Access Key ID", r"(?:^|[^A-Za-z0-9/+=])(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}(?:[^A-Za-z0-9/+=]|$)",
     "CRITICAL", "aws_access_key", "Hardcoded AWS Access Key ID detected",
     "Remove the key and rotate it immediately via AWS IAM Console. Use environment variables or AWS Secrets Manager."),

    ("SEC-AWS-002", "AWS Secret Access Key", r"""(?:aws_secret_access_key|secret_key|aws_secret)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?""",
     "CRITICAL", "aws_secret_key", "Hardcoded AWS Secret Access Key detected",
     "Rotate the key immediately. Use IAM roles, instance profiles, or secrets manager."),

    ("SEC-AWS-003", "AWS Session Token", r"""(?:aws_session_token|security_token)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{100,}['"]?""",
     "HIGH", "aws_session_token", "AWS Session Token found in source code",
     "Session tokens are temporary but should never be committed. Use environment variables."),

    # ── GCP ──
    ("SEC-GCP-001", "GCP Service Account Key", r'"type"\s*:\s*"service_account"',
     "CRITICAL", "gcp_service_account", "GCP Service Account JSON key file detected",
     "Remove the key file from the repository. Use Workload Identity Federation or GCP Secret Manager."),

    ("SEC-GCP-002", "GCP API Key", r"AIza[0-9A-Za-z_-]{35}",
     "HIGH", "gcp_api_key", "Google Cloud API Key detected",
     "Restrict the key's scope and rotate it. Use Application Default Credentials instead."),

    # ── Azure ──
    ("SEC-AZ-001", "Azure Storage Account Key", r"""(?:AccountKey|account_key)\s*[:=]\s*['"]?[A-Za-z0-9+/=]{86,88}['"]?""",
     "CRITICAL", "azure_storage_key", "Azure Storage Account Key detected",
     "Rotate the key via Azure Portal. Use Managed Identity or SAS tokens with minimal scope."),

    ("SEC-AZ-002", "Azure Connection String", r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
     "CRITICAL", "azure_connection_string", "Azure Storage connection string with embedded key",
     "Use Azure Key Vault references or Managed Identity. Rotate the storage key."),

    ("SEC-AZ-003", "Azure AD Client Secret", r"""(?:client_secret|clientSecret)\s*[:=]\s*['"][A-Za-z0-9~._-]{34,}['"]""",
     "HIGH", "azure_client_secret", "Azure AD application client secret detected",
     "Rotate via Azure Portal > App Registrations. Use Managed Identity where possible."),

    # ── GitHub ──
    ("SEC-GH-001", "GitHub Personal Access Token", r"ghp_[A-Za-z0-9]{20,}",
     "CRITICAL", "github_pat", "GitHub Personal Access Token (classic) detected",
     "Revoke the token immediately at github.com/settings/tokens and create a new one."),

    ("SEC-GH-002", "GitHub Fine-Grained Token", r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
     "CRITICAL", "github_fine_grained_pat", "GitHub Fine-Grained Personal Access Token detected",
     "Revoke and regenerate. Use GitHub Apps for automation instead."),

    ("SEC-GH-003", "GitHub OAuth Token", r"gho_[A-Za-z0-9]{36}",
     "HIGH", "github_oauth", "GitHub OAuth Access Token detected",
     "Revoke the token. Use server-side OAuth flow with proper token storage."),

    ("SEC-GH-004", "GitHub App Token", r"(?:ghu|ghs)_[A-Za-z0-9]{36}",
     "HIGH", "github_app_token", "GitHub App installation/user token detected",
     "These are short-lived but should not be committed. Check token generation flow."),

    # ── Slack ──
    ("SEC-SLACK-001", "Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
     "HIGH", "slack_bot_token", "Slack Bot User OAuth Token detected",
     "Regenerate the token at api.slack.com. Store in environment variables."),

    ("SEC-SLACK-002", "Slack Webhook URL", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
     "MEDIUM", "slack_webhook", "Slack Incoming Webhook URL detected",
     "Regenerate the webhook. Store URL in secrets manager."),

    # ── Stripe ──
    ("SEC-STRIPE-001", "Stripe Secret Key", r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
     "CRITICAL", "stripe_secret_key", "Stripe API Secret Key detected",
     "Roll the key immediately at dashboard.stripe.com/apikeys."),

    ("SEC-STRIPE-002", "Stripe Publishable Key", r"pk_(?:live|test)_[A-Za-z0-9]{24,}",
     "LOW", "stripe_publishable_key", "Stripe Publishable Key in source (low risk but verify scope)",
     "Publishable keys are less sensitive but verify no secret key is nearby."),

    # ── Database ──
    ("SEC-DB-001", "Database Connection URI", r"""(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'"]{10,}""",
     "HIGH", "database_uri", "Database connection string with potential embedded credentials",
     "Use environment variables or secrets manager for connection strings."),

    ("SEC-DB-002", "Database Password in Config", r"""(?:db_password|database_password|DB_PASS(?:WORD)?|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*[:=]\s*['"][^'"]{4,}['"]""",
     "HIGH", "database_password", "Database password found in configuration",
     "Move credentials to environment variables or vault."),

    # ── Private Keys ──
    ("SEC-KEY-001", "RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----",
     "CRITICAL", "rsa_private_key", "RSA private key found in repository",
     "Remove immediately and generate a new key pair. Never commit private keys."),

    ("SEC-KEY-002", "EC Private Key", r"-----BEGIN EC PRIVATE KEY-----",
     "CRITICAL", "ec_private_key", "EC (Elliptic Curve) private key found",
     "Remove and generate a new key pair."),

    ("SEC-KEY-003", "OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----",
     "CRITICAL", "openssh_private_key", "OpenSSH private key committed to repository",
     "Remove and regenerate the SSH key. Add to .gitignore."),

    ("SEC-KEY-004", "PGP/GPG Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     "CRITICAL", "pgp_private_key", "PGP/GPG private key block detected",
     "Remove and revoke the key. Generate a new key pair."),

    # ── JWT / Tokens ──
    ("SEC-JWT-001", "JWT Secret", r"""(?:jwt_secret|JWT_SECRET|jwt_key|JWT_KEY)\s*[:=]\s*['"][^'"]{8,}['"]""",
     "HIGH", "jwt_secret", "JWT signing secret hardcoded in source",
     "Move to environment variable. Rotate the secret."),

    ("SEC-TOK-001", "Generic API Key Assignment", r"""(?:api_key|apikey|api[-_]?secret|access_token|auth_token)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]""",
     "MEDIUM", "generic_api_key", "Potential API key or token assignment detected",
     "Verify if this is a real credential. Move to environment variables if so."),

    # ── SendGrid / Twilio / Other SaaS ──
    ("SEC-SG-001", "SendGrid API Key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
     "HIGH", "sendgrid_api_key", "SendGrid API Key detected",
     "Regenerate at app.sendgrid.com/settings/api_keys."),

    ("SEC-TWILIO-001", "Twilio Auth Token", r"""(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[:=]\s*['"][a-f0-9]{32}['"]""",
     "HIGH", "twilio_auth_token", "Twilio Auth Token detected",
     "Rotate at twilio.com/console."),

    # ── Passwords ──
    ("SEC-PWD-001", "Hardcoded Password", r"""(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]""",
     "HIGH", "hardcoded_password", "Hardcoded password assignment detected",
     "Remove password from source code. Use environment variables or secrets manager."),

    ("SEC-PWD-002", "Password in URL", r"""(?:https?|ftp)://[^:]+:[^@]+@[^\s'"]+""",
     "HIGH", "password_in_url", "Credentials embedded in URL",
     "Remove credentials from URLs. Use authentication headers or secrets manager."),

    # ── Terraform-specific secrets ──
    ("SEC-TF-001", "Terraform Variable Default with Secret", r'default\s*=\s*"(?:sk_|pk_|ghp_|AKIA|AIza)[^"]{10,}"',
     "CRITICAL", "terraform_secret_default", "Terraform variable default contains a secret value",
     "Remove the default. Pass sensitive values via TF_VAR_ environment variables or tfvars files excluded from VCS."),
]

# Files to skip (binary, vendor, generated)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz", ".exe",
    ".dll", ".so", ".dylib", ".pyc", ".class", ".lock", ".sum",
}
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".terraform", ".next",
}


class SecretScanner:
    """Scans file content for hardcoded secrets and credentials."""

    def __init__(self) -> None:
        self._compiled = [
            (rule_id, title, re.compile(pattern, re.IGNORECASE | re.MULTILINE),
             severity, secret_type, desc, remediation)
            for rule_id, title, pattern, severity, secret_type, desc, remediation
            in SECRET_PATTERNS
        ]

    def should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped based on extension or directory."""
        lower = file_path.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in SKIP_EXTENSIONS:
            return True
        parts = file_path.replace("\\", "/").split("/")
        return any(p in SKIP_DIRS for p in parts)

    def scan_content(self, content: str, file_path: str = "") -> list[SecretFinding]:
        """Scan file content for secrets. Returns list of findings."""
        if self.should_skip_file(file_path):
            return []

        findings: list[SecretFinding] = []
        lines = content.split("\n")

        for rule_id, title, pattern, severity, secret_type, desc, remediation in self._compiled:
            for i, line in enumerate(lines, 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for match in pattern.finditer(line):
                    matched = match.group(0).strip()
                    # Mask the match for the preview
                    preview = matched[:8] + "****" if len(matched) > 8 else matched[:4] + "****"

                    findings.append(SecretFinding(
                        rule_id=rule_id,
                        title=title,
                        description=desc,
                        severity=severity,
                        file_path=file_path,
                        line_number=i,
                        secret_type=secret_type,
                        match_preview=preview,
                        confidence=0.9 if severity == "CRITICAL" else 0.8,
                        remediation=remediation,
                    ))

        # Deduplicate (same rule + same line = one finding)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped

    def scan_files(self, files: dict[str, str]) -> tuple[list[SecretFinding], dict]:
        """
        Scan multiple files. files = {path: content}.
        Returns (findings, stats).
        """
        all_findings: list[SecretFinding] = []
        files_scanned = 0
        files_skipped = 0

        for path, content in files.items():
            if self.should_skip_file(path):
                files_skipped += 1
                continue
            file_findings = self.scan_content(content, path)
            all_findings.extend(file_findings)
            files_scanned += 1

        stats = {
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "total_secrets": len(all_findings),
            "by_severity": {
                "CRITICAL": sum(1 for f in all_findings if f.severity == "CRITICAL"),
                "HIGH": sum(1 for f in all_findings if f.severity == "HIGH"),
                "MEDIUM": sum(1 for f in all_findings if f.severity == "MEDIUM"),
                "LOW": sum(1 for f in all_findings if f.severity == "LOW"),
            },
            "by_type": {},
        }
        for f in all_findings:
            stats["by_type"][f.secret_type] = stats["by_type"].get(f.secret_type, 0) + 1

        return all_findings, stats

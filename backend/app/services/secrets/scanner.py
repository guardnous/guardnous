import re
from dataclasses import dataclass
from app.services.scanners.base import ScanResult


@dataclass
class SecretPattern:
    name: str
    pattern: str
    severity: str
    description: str
    case_sensitive: bool = False  # If True, do NOT apply re.IGNORECASE


SECRET_PATTERNS = [
    SecretPattern(
        name="AWS Access Key ID",
        pattern=r"(?:^|[^A-Za-z0-9])((AKIA|ASIA)[A-Z0-9]{16})(?:[^A-Za-z0-9]|$)",
        severity="CRITICAL",
        description="AWS Access Key IDs start with AKIA (long-term) or ASIA (temporary).",
        case_sensitive=True,  # AKIA/ASIA prefixes are uppercase only
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=r"(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity="CRITICAL",
        description="AWS Secret Access Key detected.",
    ),
    SecretPattern(
        name="Google Cloud API Key",
        pattern=r"AIza[0-9A-Za-z_-]{35}",
        severity="CRITICAL",
        description="Google Cloud API key detected.",
    ),
    SecretPattern(
        name="Google Cloud Service Account",
        pattern=r'"type"\s*:\s*"service_account"[^}]*"private_key"\s*:',
        severity="HIGH",
        description="Google Cloud service account JSON key file with private key detected.",
    ),
    SecretPattern(
        name="Azure Storage Account Key",
        pattern=r"(?:AccountKey|account_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{88})['\"]?",
        severity="CRITICAL",
        description="Azure Storage account key detected.",
    ),
    SecretPattern(
        name="Azure Connection String",
        pattern=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
        severity="CRITICAL",
        description="Azure Storage connection string with embedded key.",
    ),
    SecretPattern(
        name="Generic Password",
        pattern=r'(?:password|passwd|pwd)\s*[=:]\s*["\'](?!(?:changeme|password|example|placeholder|your[_-]?password|xxx|P@ssw0rd|CHANGE_ME|TODO|REPLACE_ME|dummy|test1234)["\'])([^"\']{8,})["\']',
        severity="HIGH",
        description="Hardcoded password detected.",
    ),
    SecretPattern(
        name="Generic API Key",
        pattern=r'(?:api_key|apikey|api-key)\s*[=:]\s*["\']([^"\']{16,})["\']',
        severity="HIGH",
        description="Hardcoded API key detected.",
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=r'(?:secret|token|auth_token)\s*[=:]\s*["\']([^"\']{8,})["\']',
        severity="HIGH",
        description="Hardcoded secret or token detected.",
    ),
    SecretPattern(
        name="Private Key",
        pattern=r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        severity="CRITICAL",
        description="Private key file detected. Private keys should never be committed to repositories.",
    ),
    SecretPattern(
        name="GitHub Token",
        pattern=r"gh[pousr]_[A-Za-z0-9_]{36,}",
        severity="CRITICAL",
        description="GitHub personal access token detected.",
    ),
    SecretPattern(
        name="Slack Token",
        pattern=r"xox[bporas]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}",
        severity="HIGH",
        description="Slack API token detected.",
    ),
    SecretPattern(
        name="JWT Token",
        pattern=r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        severity="LOW",
        description="JSON Web Token detected. JWTs in IaC templates may be examples or short-lived tokens. Verify it's not a long-lived credential.",
    ),
    SecretPattern(
        name="Database Connection String",
        pattern=r"(?:mysql|postgres|postgresql|mongodb|redis)://[^:]+:[^@]+@[^/]+",
        severity="HIGH",
        description="Database connection string with embedded credentials.",
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        severity="HIGH",
        description="SendGrid API key detected.",
    ),
    SecretPattern(
        name="Stripe API Key",
        pattern=r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
        severity="CRITICAL",
        description="Stripe API key detected.",
    ),
    SecretPattern(
        name="Twilio Auth Token",
        pattern=r"(?:twilio_auth_token|TWILIO_AUTH)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        severity="HIGH",
        description="Twilio authentication token detected.",
    ),
    SecretPattern(
        name="Mailgun API Key",
        pattern=r"key-[0-9a-zA-Z]{32}",
        severity="HIGH",
        description="Mailgun API key detected.",
    ),
]


class SecretsScanner:
    """Scans content for hardcoded secrets using regex patterns."""

    def scan(self, content: str, file_name: str = "") -> list[ScanResult]:
        results = []
        lines = content.split("\n")

        for secret_pattern in SECRET_PATTERNS:
            flags = re.MULTILINE if secret_pattern.case_sensitive else (re.IGNORECASE | re.MULTILINE)
            for match in re.finditer(secret_pattern.pattern, content, flags):
                line_num = content[:match.start()].count("\n") + 1
                matched_text = match.group(0)
                # Mask the secret for display
                masked = matched_text[:8] + "..." + matched_text[-4:] if len(matched_text) > 16 else "***REDACTED***"

                results.append(ScanResult(
                    rule_id=f"SD-SEC-{SECRET_PATTERNS.index(secret_pattern) + 1:03d}",
                    title=f"Secret detected: {secret_pattern.name}",
                    description=secret_pattern.description,
                    severity=secret_pattern.severity,
                    category="secrets",
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Remove the secret and rotate credentials. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).",
                    metadata={"secret_type": secret_pattern.name, "masked_value": masked},
                ))

        return results

    def scan_config_files(self, content: str, file_name: str = "") -> list[ScanResult]:
        """Scan configuration files (.env, .cfg, .ini, .conf) for secrets."""
        results = []
        lines = content.split("\n")

        config_patterns = [
            (r'^([A-Z_]+(?:KEY|SECRET|PASSWORD|TOKEN|AUTH|CREDENTIAL)[A-Z_]*)\s*=\s*(.+)$', "Configuration secret"),
            (r'^([A-Z_]+(?:DB_PASS|DATABASE_URL|REDIS_URL|MONGO_URI)[A-Z_]*)\s*=\s*(.+)$', "Database credential"),
        ]

        for pat, desc in config_patterns:
            for match in re.finditer(pat, content, re.MULTILINE | re.IGNORECASE):
                key = match.group(1)
                value = match.group(2).strip().strip("'\"")
                if value and not value.startswith("${") and not value.startswith("{{"):
                    line_num = content[:match.start()].count("\n") + 1
                    results.append(ScanResult(
                        rule_id="SD-SEC-CFG",
                        title=f"Secret in config: {key}",
                        description=f"Configuration file contains hardcoded value for {key}.",
                        severity="HIGH",
                        category="secrets",
                        file_path=file_name,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Use environment variables or a secrets manager. Do not commit config files with secrets.",
                    ))

        return results

    def _get_snippet(self, lines: list[str], line_num: int, context: int = 2) -> str:
        if line_num <= 0:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return "\n".join(lines[start:end])

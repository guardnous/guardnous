import pytest
from app.services.secrets.scanner import SecretsScanner


@pytest.fixture
def scanner():
    return SecretsScanner()


class TestSecretsScanner:
    def test_detect_aws_key(self, scanner):
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        results = scanner.scan(content, "test.env")
        aws_keys = [r for r in results if "AWS" in r.title]
        assert len(aws_keys) > 0

    def test_detect_generic_password(self, scanner):
        content = 'password = "SuperSecretPass123"'
        results = scanner.scan(content, "config.py")
        passwords = [r for r in results if "password" in r.title.lower() or "secret" in r.title.lower()]
        assert len(passwords) > 0

    def test_detect_private_key(self, scanner):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ..."
        results = scanner.scan(content, "key.pem")
        keys = [r for r in results if "Private Key" in r.title]
        assert len(keys) > 0

    def test_detect_github_token(self, scanner):
        content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        results = scanner.scan(content, ".env")
        tokens = [r for r in results if "GitHub" in r.title]
        assert len(tokens) > 0

    def test_detect_stripe_key(self, scanner):
        content = 'STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"'
        results = scanner.scan(content, ".env")
        stripe = [r for r in results if "Stripe" in r.title]
        assert len(stripe) > 0

    def test_detect_db_connection_string(self, scanner):
        content = 'DATABASE_URL = "postgresql://user:pass@localhost:5432/db"'
        results = scanner.scan(content, ".env")
        db = [r for r in results if "Database" in r.title]
        assert len(db) > 0

    def test_no_false_positive_on_variable_ref(self, scanner):
        content = 'password = var.db_password'
        results = scanner.scan(content, "main.tf")
        # Variable references should not trigger
        passwords = [r for r in results if "password" in r.title.lower()]
        assert len(passwords) == 0

    def test_config_file_scanning(self, scanner):
        content = """
DB_PASSWORD=mysecretpassword123
API_KEY=abcdefghijklmnop1234
REDIS_URL=redis://default:secret@localhost:6379
"""
        results = scanner.scan_config_files(content, ".env")
        assert len(results) > 0

    def test_masked_values(self, scanner):
        content = 'api_key = "abcdefghijklmnopqrstuvwxyz123456"'
        results = scanner.scan(content, "test.py")
        for r in results:
            if r.metadata.get("masked_value"):
                assert "..." in r.metadata["masked_value"] or "REDACTED" in r.metadata["masked_value"]

    def test_all_findings_have_remediation(self, scanner):
        content = """
AKIAIOSFODNN7EXAMPLE
password = "SuperSecret123!"
-----BEGIN RSA PRIVATE KEY-----
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
"""
        results = scanner.scan(content, "test")
        for r in results:
            assert r.remediation

"""Tests for GitHub VCS service."""
import hashlib
import hmac
import os

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.vcs.github import GitHubService


class TestGitHubWebhookSignature:
    def test_valid_signature(self):
        secret = "test-webhook-secret"
        payload = b'{"action":"push","ref":"refs/heads/main"}'
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        signature = f"sha256={expected}"

        assert GitHubService.verify_webhook_signature(payload, signature, secret) is True

    def test_invalid_signature(self):
        secret = "test-webhook-secret"
        payload = b'{"action":"push"}'
        signature = "sha256=invalid_signature_here"

        assert GitHubService.verify_webhook_signature(payload, signature, secret) is False

    def test_missing_sha256_prefix(self):
        secret = "test-webhook-secret"
        payload = b'{"action":"push"}'
        signature = "invalid_no_prefix"

        assert GitHubService.verify_webhook_signature(payload, signature, secret) is False

    def test_tampered_payload(self):
        secret = "test-webhook-secret"
        original = b'{"action":"push"}'
        tampered = b'{"action":"delete"}'
        expected = hmac.new(secret.encode(), original, hashlib.sha256).hexdigest()
        signature = f"sha256={expected}"

        assert GitHubService.verify_webhook_signature(tampered, signature, secret) is False

    def test_different_secret(self):
        payload = b'{"action":"push"}'
        expected = hmac.new(b"secret-a", payload, hashlib.sha256).hexdigest()
        signature = f"sha256={expected}"

        assert GitHubService.verify_webhook_signature(payload, signature, "secret-b") is False


class TestGitHubTokenEncryption:
    def test_encrypt_decrypt_token(self):
        token = "ghp_abcdef1234567890"
        encrypted = GitHubService.encrypt_access_token(token)
        assert encrypted != token
        decrypted = GitHubService.decrypt_access_token(encrypted)
        assert decrypted == token


class TestGitHubOAuthUrl:
    def test_oauth_url_contains_client_id(self):
        gh = GitHubService()
        url = gh.get_oauth_url(state="test-state")
        assert "github.com/login/oauth/authorize" in url
        assert "state=test-state" in url
        assert "scope=repo" in url

"""Tests for GitLab VCS integration service."""
import os

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.vcs.gitlab import GitLabService


class TestGitLabServiceInit:
    def test_constructor_defaults(self):
        svc = GitLabService(token="glpat-test-token")
        assert svc.token == "glpat-test-token"
        assert "gitlab.com" in svc.base_url

    def test_custom_base_url(self):
        svc = GitLabService(token="tok", base_url="https://gitlab.example.com")
        assert svc.base_url == "https://gitlab.example.com"

    def test_trailing_slash_stripped(self):
        svc = GitLabService(token="tok", base_url="https://gitlab.example.com/")
        assert not svc.base_url.endswith("/")

    def test_headers_contain_token(self):
        svc = GitLabService(token="glpat-abc123")
        headers = svc._headers()
        assert "PRIVATE-TOKEN" in headers or "Authorization" in headers
        token_found = any("glpat-abc123" in v for v in headers.values())
        assert token_found

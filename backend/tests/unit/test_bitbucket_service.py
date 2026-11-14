"""Tests for Bitbucket VCS integration service."""
import os
import httpx

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.vcs.bitbucket import BitbucketService


class TestBitbucketServiceInit:
    def test_constructor(self):
        svc = BitbucketService(username="myuser", app_password="secret123")
        assert svc.username == "myuser"
        assert svc.app_password == "secret123"

    def test_auth_returns_tuple(self):
        svc = BitbucketService(username="u", app_password="p")
        auth = svc._auth()
        assert isinstance(auth, httpx.BasicAuth)
        request = httpx.Request("GET", "https://api.bitbucket.org/2.0/user")
        next(auth.auth_flow(request))
        assert request.headers["Authorization"] == httpx.BasicAuth("u", "p")._auth_header

    def test_base_url(self):
        from app.services.vcs.bitbucket import BITBUCKET_API
        assert "bitbucket.org" in BITBUCKET_API

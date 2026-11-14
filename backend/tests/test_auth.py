"""Tests for authentication endpoints: register, login, MFA, password reset."""
import pytest
from unittest.mock import patch, AsyncMock

from tests.conftest import (
    TEST_EMAIL, TEST_PASSWORD, TEST_NAME, TEST_ORG,
    register_user, get_auth_headers,
)


class TestRegistration:
    @pytest.mark.asyncio
    async def test_register_creates_org_and_user(self, client):
        resp = await client.post("/api/v1/auth/register", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": TEST_NAME,
            "organization_name": TEST_ORG,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == TEST_EMAIL
        assert data["full_name"] == TEST_NAME
        assert data["role"] == "platform_admin"
        assert data["is_active"] is True
        assert "organization_id" in data
        assert data["organization_id"] is not None
        assert "tenant_id" in data

    @pytest.mark.asyncio
    async def test_register_duplicate_email_fails(self, client):
        await register_user(client)
        resp = await client.post("/api/v1/auth/register", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": "Another User",
            "organization_name": "Another Org",
        })
        assert resp.status_code in (400, 409)


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_success(self, client):
        await register_user(client)
        resp = await client.post("/api/v1/auth/login", data={
            "username": TEST_EMAIL,
            "password": TEST_PASSWORD,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "platform_admin"
        assert data["organization_id"] is not None

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client):
        await register_user(client)
        resp = await client.post("/api/v1/auth/login", data={
            "username": TEST_EMAIL,
            "password": "WrongPass999!",
        })
        assert resp.status_code == 401
        assert "Incorrect" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        resp = await client.post("/api/v1/auth/login", data={
            "username": "nobody@example.com",
            "password": TEST_PASSWORD,
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_disabled_user(self, client, db_session):
        """A user with status='deactivated' should get 403."""
        await register_user(client)

        from app.models.user import User
        from sqlalchemy import update as sa_update

        async with db_session as db:
            await db.execute(
                sa_update(User).where(User.email == TEST_EMAIL).values(status="deactivated")
            )
            await db.commit()

        resp = await client.post("/api/v1/auth/login", data={
            "username": TEST_EMAIL,
            "password": TEST_PASSWORD,
        })
        assert resp.status_code == 403
        assert "deactivated" in resp.json()["detail"].lower()


class TestMFA:
    @pytest.mark.asyncio
    async def test_mfa_setup_and_verify(self, client):
        """Setting up 2FA returns a TOTP URI and QR code."""
        headers = await get_auth_headers(client)

        # Setup 2FA
        resp = await client.post("/api/v1/auth/2fa/setup", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "totp_uri" in data
        assert "qr_code" in data
        assert "backup_codes" in data
        assert len(data["backup_codes"]) > 0

        # Extract the TOTP secret from the URI and generate a valid code
        import pyotp
        uri = data["totp_uri"]
        secret = pyotp.parse_uri(uri).secret
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Confirm 2FA with valid code
        resp = await client.post("/api/v1/auth/2fa/confirm", headers=headers, json={
            "code": code,
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestPasswordReset:
    @pytest.mark.asyncio
    @patch("app.core.email.send_password_reset_email", new_callable=AsyncMock)
    async def test_forgot_password_sends_email(self, mock_send, client):
        """Forgot password endpoint returns 200 regardless (no user enumeration)."""
        await register_user(client)
        resp = await client.post("/api/v1/auth/forgot-password", json={
            "email": TEST_EMAIL,
        })
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_reset_password_with_valid_token(self, client):
        """Reset password with a valid token should succeed."""
        user = await register_user(client)

        from app.core.security import create_password_reset_token

        # Generate a real reset token (keyed on the user's id)
        token = create_password_reset_token(user["id"])

        resp = await client.post("/api/v1/auth/reset-password", json={
            "token": token,
            "new_password": "NewSecure456!",
        })
        assert resp.status_code == 200

        # Verify login with new password
        login_resp = await client.post("/api/v1/auth/login", data={
            "username": TEST_EMAIL,
            "password": "NewSecure456!",
        })
        assert login_resp.status_code == 200
        assert "access_token" in login_resp.json()

    @pytest.mark.asyncio
    async def test_reset_password_expired_token(self, client):
        """An expired/invalid reset token should be rejected."""
        await register_user(client)

        resp = await client.post("/api/v1/auth/reset-password", json={
            "token": "invalid-token-value",
            "new_password": "NewSecure456!",
        })
        assert resp.status_code in (400, 401)


class TestMe:
    @pytest.mark.asyncio
    async def test_me_returns_user_info(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == TEST_EMAIL
        assert "permissions" in data

    @pytest.mark.asyncio
    async def test_me_requires_auth(self, client):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code in (401, 403)

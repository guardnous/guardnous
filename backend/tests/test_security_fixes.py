"""Regression tests for authentication, tenant isolation and privilege checks."""
import pytest

from tests.conftest import TEST_PASSWORD, get_auth_headers, register_user


async def _tenant(client, email: str, org: str) -> dict:
    """Register a new tenant admin and return their auth headers."""
    return await get_auth_headers(client, email=email, org_name=org)


class TestTokenTypes:
    @pytest.mark.asyncio
    async def test_password_reset_token_is_not_a_session(self, client):
        from app.core.security import create_password_reset_token

        user = await register_user(client)
        token = create_password_reset_token(user["id"])
        resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_untyped_token_is_rejected(self, client):
        from jose import jwt
        from app.core.config import settings

        user = await register_user(client)
        token = jwt.encode({"sub": str(user["id"])}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_access_token_works(self, client):
        headers = await get_auth_headers(client)
        resp = await client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200


class TestTenantIsolation:
    @pytest.mark.asyncio
    async def test_group_of_another_tenant_is_not_reachable(self, client):
        headers_a = await _tenant(client, "a@corp-a.com", "Corp A")
        headers_b = await _tenant(client, "b@corp-b.com", "Corp B")

        created = await client.post("/api/v1/groups/", headers=headers_a, json={"name": "A team"})
        assert created.status_code == 201, created.text
        group_id = created.json()["id"]

        assert (await client.get(f"/api/v1/groups/{group_id}", headers=headers_a)).status_code == 200
        assert (await client.get(f"/api/v1/groups/{group_id}", headers=headers_b)).status_code == 404
        assert (await client.delete(f"/api/v1/groups/{group_id}", headers=headers_b)).status_code == 404
        renamed = await client.patch(
            f"/api/v1/groups/{group_id}", headers=headers_b, json={"name": "hijacked"}
        )
        assert renamed.status_code == 404

    @pytest.mark.asyncio
    async def test_organization_header_cannot_cross_tenants(self, client, db_session):
        """X-Organization-Id is ignored for users who are not installation superusers."""
        from tests.conftest import create_finding_in_db, create_scan_in_db

        user_a = await register_user(client, email="a@corp-a.com", org_name="Corp A")
        headers_b = await _tenant(client, "b@corp-b.com", "Corp B")
        async with db_session as db:
            scan = await create_scan_in_db(db, user_a["organization_id"])
            await create_finding_in_db(db, scan.id)
            await db.commit()

        resp = await client.get(
            "/api/v1/findings",
            headers={**headers_b, "X-Organization-Id": str(user_a["organization_id"])},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


class TestRoleEscalation:
    @pytest.mark.asyncio
    async def test_cannot_grant_installation_superuser(self, client):
        user = await register_user(client)
        headers = await get_auth_headers(client, email="second@testcorp2.com", org_name="Other")
        resp = await client.put(
            f"/api/v1/users/{user['id']}/role", headers=headers, json={"role": "superadmin"}
        )
        assert resp.status_code in (403, 404)

    @pytest.mark.asyncio
    async def test_cannot_self_promote_to_superuser(self, client):
        user = await register_user(client)
        from tests.conftest import login_user
        token = (await login_user(client))["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.put(
            f"/api/v1/users/{user['id']}/role", headers=headers, json={"role": "superadmin"}
        )
        assert resp.status_code in (400, 403)
        me = await client.get("/api/v1/auth/me", headers=headers)
        assert me.json()["role"] != "superadmin"

    def test_role_grant_rules(self):
        from types import SimpleNamespace
        from fastapi import HTTPException
        from app.core.rbac import ensure_can_grant_role

        tenant_admin = SimpleNamespace(role="platform_admin")
        ensure_can_grant_role(tenant_admin, "security_analyst")  # allowed

        for role, expected in (("god", 400), ("superadmin", 403), ("admin", 403)):
            with pytest.raises(HTTPException) as exc:
                ensure_can_grant_role(tenant_admin, role)
            assert exc.value.status_code == expected

        # A tenant admin cannot demote an installation superuser either
        with pytest.raises(HTTPException) as exc:
            ensure_can_grant_role(tenant_admin, "viewer", target_current_role="superadmin")
        assert exc.value.status_code == 403


class TestSetupGuard:
    @pytest.mark.asyncio
    async def test_setup_cannot_run_once_a_user_exists(self, client):
        await register_user(client)
        resp = await client.post("/api/v1/setup/initialize", json={
            "admin_email": "attacker@evil.com",
            "admin_password": TEST_PASSWORD + "Aa1!",
            "admin_full_name": "Attacker",
            "tenant_name": "Evil",
            "organization_name": "Evil",
        })
        assert resp.status_code in (400, 403, 409)
        check = await client.get("/api/v1/setup/check")
        assert check.status_code == 200

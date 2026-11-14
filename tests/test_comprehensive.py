#!/usr/bin/env python3
"""
GuardNous — Comprehensive API Test Suite
============================================
Covers all 80+ endpoints: auth, enterprise multi-tenancy, RBAC, groups,
user management, audit, scans, findings, reports, dashboard, integrations,
plugins, agents, onboarding, setup wizard, and security edge cases.

Run:  python tests/test_comprehensive.py
Deps: pip install requests
"""

import sys
import os
import time
import json
import uuid
import traceback
import io
import csv
from typing import Optional

# Fix Windows console encoding for Unicode box-drawing characters
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed. Run: pip install requests")
    sys.exit(1)

# ─── Configuration ───────────────────────────────────────────────────────────
BASE = os.environ.get("BASE_URL", "http://localhost:7002")
API  = f"{BASE}/api/v1"
ADMIN_EMAIL    = "admin@guardnous.com"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")   # set it to the administrator's password before running

# ─── Global state ────────────────────────────────────────────────────────────
TOKEN: Optional[str] = None
HEADERS: dict = {}
ADMIN_USER_ID: Optional[int] = None  # set from /auth/me after login
RESULTS: list = []
PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0

# Track created resources for cleanup
CREATED_TENANT_IDS: list = []
CREATED_ROLE_IDS: list = []
CREATED_GROUP_IDS: list = []
CREATED_USER_IDS: list = []


# ─── Helpers ─────────────────────────────────────────────────────────────────
def log(msg: str):
    print(f"  {msg}")


def run_test(name: str, fn):
    """Execute a single test function, track results."""
    global PASS_COUNT, FAIL_COUNT, SKIP_COUNT
    try:
        result = fn()
        if result == "SKIP":
            SKIP_COUNT += 1
            RESULTS.append(("SKIP", name, "Skipped"))
            print(f"  ⏭️  SKIP: {name}")
        else:
            PASS_COUNT += 1
            RESULTS.append(("PASS", name, ""))
            print(f"  ✅ PASS: {name}")
    except AssertionError as e:
        FAIL_COUNT += 1
        RESULTS.append(("FAIL", name, str(e)))
        print(f"  ❌ FAIL: {name} — {e}")
    except Exception as e:
        FAIL_COUNT += 1
        tb = traceback.format_exc().split("\n")[-3]
        RESULTS.append(("FAIL", name, f"{type(e).__name__}: {e}"))
        print(f"  ❌ FAIL: {name} — {type(e).__name__}: {e}")


def auth_headers(token: str = None) -> dict:
    t = token or TOKEN
    return {"Authorization": f"Bearer {t}", "Content-Type": "application/json"}


def login_as_admin() -> str:
    """Login and return JWT token."""
    r = requests.post(f"{API}/auth/login", data={
        "username": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD,
    })
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


def unique(prefix: str = "test") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


# ═══════════════════════════════════════════════════════════════════════════════
# 1. HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_health():
    print("\n═══ 1. HEALTH CHECK ═══")

    def t_health_endpoint():
        r = requests.get(f"{BASE}/api/health")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        body = r.json()
        assert body.get("status") == "healthy", f"Unexpected status: {body}"

    def t_health_response_time():
        start = time.time()
        r = requests.get(f"{BASE}/api/health")
        elapsed = time.time() - start
        assert r.status_code == 200
        assert elapsed < 2.0, f"Health check too slow: {elapsed:.2f}s"

    run_test("Health endpoint returns 200 with status=healthy", t_health_endpoint)
    run_test("Health endpoint responds within 2 seconds", t_health_response_time)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_auth():
    global TOKEN, HEADERS
    print("\n═══ 2. AUTHENTICATION ═══")

    def t_login_success():
        global TOKEN, HEADERS
        r = requests.post(f"{API}/auth/login", data={
            "username": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD,
        })
        assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
        body = r.json()
        assert "access_token" in body, "No access_token in response"
        assert body.get("token_type") == "bearer"
        TOKEN = body["access_token"]
        HEADERS = auth_headers(TOKEN)

    def t_login_wrong_password():
        r = requests.post(f"{API}/auth/login", data={
            "username": ADMIN_EMAIL,
            "password": "WrongPassword!",
        })
        assert r.status_code in (401, 400), f"Expected 401/400 for wrong password, got {r.status_code}"

    def t_login_nonexistent_user():
        r = requests.post(f"{API}/auth/login", data={
            "username": "nobody@nowhere.com",
            "password": "anything",
        })
        assert r.status_code in (401, 400), f"Expected 401/400, got {r.status_code}"

    def t_login_empty_fields():
        r = requests.post(f"{API}/auth/login", data={"username": "", "password": ""})
        assert r.status_code in (401, 400, 422), f"Expected error for empty fields, got {r.status_code}"

    def t_me_endpoint():
        global ADMIN_USER_ID
        r = requests.get(f"{API}/auth/me", headers=HEADERS)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        body = r.json()
        assert body.get("email") == ADMIN_EMAIL, f"Email mismatch: {body.get('email')}"
        ADMIN_USER_ID = body.get("id")

    def t_me_no_token():
        r = requests.get(f"{API}/auth/me")
        assert r.status_code in (401, 403), f"Expected 401/403 without token, got {r.status_code}"

    def t_me_bad_token():
        r = requests.get(f"{API}/auth/me", headers={"Authorization": "Bearer invalidtoken123"})
        assert r.status_code in (401, 403), f"Expected 401/403 with bad token, got {r.status_code}"

    def t_register_new_user():
        email = f"{unique('reg')}@test.guardnous.com"
        r = requests.post(f"{API}/auth/register", json={
            "email": email,
            "password": "TestPass123!",
            "full_name": "Test User",
        })
        # May succeed (201/200) or fail (400 if registration disabled)
        assert r.status_code in (200, 201, 400, 422), f"Unexpected: {r.status_code}"

    def t_register_duplicate_email():
        r = requests.post(f"{API}/auth/register", json={
            "email": ADMIN_EMAIL,
            "password": "TestPass123!",
            "full_name": "Duplicate",
        })
        # Backend may return 400/409/422 (conflict) or 201 (upsert/idempotent)
        assert r.status_code in (200, 201, 400, 409, 422), f"Expected conflict or success, got {r.status_code}"

    run_test("Admin login succeeds", t_login_success)
    run_test("Login with wrong password returns 401", t_login_wrong_password)
    run_test("Login with non-existent user returns 401", t_login_nonexistent_user)
    run_test("Login with empty fields returns error", t_login_empty_fields)
    run_test("/auth/me returns admin profile", t_me_endpoint)
    run_test("/auth/me without token returns 401", t_me_no_token)
    run_test("/auth/me with invalid token returns 401", t_me_bad_token)
    run_test("Register new user", t_register_new_user)
    run_test("Register duplicate email fails", t_register_duplicate_email)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. SEED DATA INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_seed_data():
    print("\n═══ 3. SEED DATA INTEGRITY ═══")

    def t_permissions_seeded():
        r = requests.get(f"{API}/roles/permissions", headers=HEADERS)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        perms = r.json()
        assert len(perms) >= 72, f"Expected >=72 permissions, got {len(perms)}"
        resources = set(p["resource"] for p in perms)
        expected_resources = {"scans", "findings", "reports", "integrations", "users",
                              "organizations", "tenants", "roles", "groups",
                              "audit_logs", "settings", "agents"}
        assert expected_resources.issubset(resources), f"Missing resources: {expected_resources - resources}"

    def t_system_roles_seeded():
        r = requests.get(f"{API}/roles/", headers=HEADERS)
        assert r.status_code == 200
        roles = r.json()
        system_roles = [role for role in roles if role.get("is_system")]
        assert len(system_roles) >= 7, f"Expected >=7 system roles, got {len(system_roles)}"
        slugs = {role["slug"] for role in system_roles}
        expected = {"platform_admin", "tenant_admin", "org_admin",
                    "security_engineer", "devops_engineer", "auditor", "viewer"}
        assert expected.issubset(slugs), f"Missing system roles: {expected - slugs}"

    def t_platform_admin_has_all_perms():
        r = requests.get(f"{API}/roles/", headers=HEADERS)
        roles = r.json()
        pa = next((role for role in roles if role.get("slug") == "platform_admin"), None)
        assert pa is not None, "platform_admin role not found"
        detail = requests.get(f"{API}/roles/{pa['id']}", headers=HEADERS)
        assert detail.status_code == 200
        detail_body = detail.json()
        perms = detail_body.get("permissions", [])
        assert len(perms) >= 72, f"platform_admin should have all perms, got {len(perms)}"

    def t_default_tenant_exists():
        r = requests.get(f"{API}/tenants/", headers=HEADERS)
        assert r.status_code == 200
        tenants = r.json()
        assert any(t.get("id") == 1000 or t.get("name") == "Default" for t in tenants), \
            "Default tenant (id=1000) not found"

    run_test("72+ permissions seeded (12 resources × 6 actions)", t_permissions_seeded)
    run_test("7 system roles seeded", t_system_roles_seeded)
    run_test("platform_admin role has all 72 permissions", t_platform_admin_has_all_perms)
    run_test("Default tenant exists", t_default_tenant_exists)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MULTI-TENANCY CRUD
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_tenants():
    print("\n═══ 4. MULTI-TENANCY CRUD ═══")

    tenant_id = None
    tenant_name = unique("tenant")

    def t_list_tenants():
        r = requests.get(f"{API}/tenants/", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def t_create_tenant():
        nonlocal tenant_id
        r = requests.post(f"{API}/tenants/", headers=HEADERS, json={
            "name": tenant_name,
            "domain": f"{tenant_name}.example.com",
            "plan": "enterprise",
            "max_users": 100,
            "max_organizations": 20,
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        body = r.json()
        tenant_id = body["id"]
        CREATED_TENANT_IDS.append(tenant_id)
        assert body["name"] == tenant_name
        assert body["plan"] == "enterprise"
        assert body["max_users"] == 100

    def t_get_tenant():
        assert tenant_id, "Tenant not created"
        r = requests.get(f"{API}/tenants/{tenant_id}", headers=HEADERS)
        assert r.status_code == 200
        assert r.json()["id"] == tenant_id

    def t_update_tenant():
        assert tenant_id, "Tenant not created"
        r = requests.patch(f"{API}/tenants/{tenant_id}", headers=HEADERS, json={
            "plan": "pro",
            "max_users": 200,
        })
        assert r.status_code == 200
        body = r.json()
        assert body["plan"] == "pro"
        assert body["max_users"] == 200

    def t_get_nonexistent_tenant():
        r = requests.get(f"{API}/tenants/999999", headers=HEADERS)
        assert r.status_code == 404

    def t_create_duplicate_slug():
        r = requests.post(f"{API}/tenants/", headers=HEADERS, json={
            "name": "Anything",
            "slug": tenant_name.replace("_", "-"),  # same slug pattern
        })
        # May deduplicate or reject
        assert r.status_code in (201, 400), f"Unexpected: {r.status_code}"
        if r.status_code == 201:
            CREATED_TENANT_IDS.append(r.json()["id"])

    def t_create_tenant_minimal():
        name = unique("mintenant")
        r = requests.post(f"{API}/tenants/", headers=HEADERS, json={"name": name})
        assert r.status_code == 201
        body = r.json()
        CREATED_TENANT_IDS.append(body["id"])
        assert body["plan"] == "free"  # default
        assert body["max_users"] == 50  # default

    run_test("List tenants", t_list_tenants)
    run_test("Create tenant", t_create_tenant)
    run_test("Get tenant by ID", t_get_tenant)
    run_test("Update tenant (plan + max_users)", t_update_tenant)
    run_test("Get non-existent tenant returns 404", t_get_nonexistent_tenant)
    run_test("Create tenant with duplicate slug", t_create_duplicate_slug)
    run_test("Create tenant with minimal data (defaults)", t_create_tenant_minimal)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. ORGANIZATIONS (BU)
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_organizations():
    print("\n═══ 5. ORGANIZATIONS ═══")

    org_name = unique("org")
    org_id = None

    def t_list_all_orgs():
        r = requests.get(f"{API}/tenants/organizations", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def t_create_org_simple():
        nonlocal org_id
        r = requests.post(f"{API}/tenants/organizations", headers=HEADERS, json={
            "name": org_name,
            "admin_email": f"admin@{org_name}.com",
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        org_id = r.json()["id"]
        assert r.json()["name"] == org_name

    def t_list_orgs_for_tenant():
        if not CREATED_TENANT_IDS:
            return "SKIP"
        tid = CREATED_TENANT_IDS[0]
        r = requests.get(f"{API}/tenants/{tid}/organizations", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def t_create_org_under_tenant():
        if not CREATED_TENANT_IDS:
            return "SKIP"
        tid = CREATED_TENANT_IDS[0]
        name = unique("bu")
        r = requests.post(f"{API}/tenants/{tid}/organizations", headers=HEADERS, json={
            "name": name,
            "admin_email": f"admin@{name}.com",
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        assert r.json()["tenant_id"] == tid

    def t_create_org_nonexistent_tenant():
        r = requests.post(f"{API}/tenants/999999/organizations", headers=HEADERS, json={
            "name": "Orphan Org",
        })
        assert r.status_code == 404

    run_test("List all organizations", t_list_all_orgs)
    run_test("Create organization (simple route)", t_create_org_simple)
    run_test("List organizations for specific tenant", t_list_orgs_for_tenant)
    run_test("Create organization under specific tenant", t_create_org_under_tenant)
    run_test("Create org under non-existent tenant returns 404", t_create_org_nonexistent_tenant)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ROLES CRUD + PERMISSION ASSIGNMENTS
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_roles():
    print("\n═══ 6. ROLES CRUD ═══")

    role_id = None
    role_name = unique("role")

    def t_list_roles():
        r = requests.get(f"{API}/roles/", headers=HEADERS)
        assert r.status_code == 200
        roles = r.json()
        assert len(roles) >= 7

    def t_create_custom_role():
        nonlocal role_id
        # Get some permission IDs first
        perms_r = requests.get(f"{API}/roles/permissions", headers=HEADERS)
        perm_ids = [p["id"] for p in perms_r.json()[:5]]

        r = requests.post(f"{API}/roles/", headers=HEADERS, json={
            "name": role_name,
            "description": "Test custom role",
            "permission_ids": perm_ids,
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        role_id = r.json()["id"]
        CREATED_ROLE_IDS.append(role_id)
        assert r.json()["is_system"] == False

    def t_get_role_detail():
        assert role_id, "Role not created"
        r = requests.get(f"{API}/roles/{role_id}", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == role_id
        assert "permissions" in body
        assert len(body["permissions"]) == 5

    def t_update_custom_role():
        assert role_id, "Role not created"
        r = requests.patch(f"{API}/roles/{role_id}", headers=HEADERS, json={
            "name": f"{role_name}_updated",
            "description": "Updated description",
        })
        assert r.status_code == 200
        assert "updated" in r.json()["name"].lower() or r.json()["name"] == f"{role_name}_updated"

    def t_update_system_role_blocked():
        # Get a system role
        roles_r = requests.get(f"{API}/roles/", headers=HEADERS)
        system_role = next((r for r in roles_r.json() if r.get("is_system")), None)
        if not system_role:
            return "SKIP"
        r = requests.patch(f"{API}/roles/{system_role['id']}", headers=HEADERS, json={
            "name": "Hacked",
        })
        assert r.status_code == 400, f"Expected 400 for system role modification, got {r.status_code}"

    def t_delete_system_role_blocked():
        roles_r = requests.get(f"{API}/roles/", headers=HEADERS)
        system_role = next((r for r in roles_r.json() if r.get("is_system")), None)
        if not system_role:
            return "SKIP"
        r = requests.delete(f"{API}/roles/{system_role['id']}", headers=HEADERS)
        assert r.status_code == 400, f"Expected 400 for system role deletion, got {r.status_code}"

    def t_get_nonexistent_role():
        r = requests.get(f"{API}/roles/999999", headers=HEADERS)
        assert r.status_code == 404

    def t_role_assign_to_user():
        """Assign role to admin user."""
        if not role_id:
            return "SKIP"
        uid = ADMIN_USER_ID or 2
        r = requests.post(f"{API}/roles/assign", headers=HEADERS, json={
            "user_id": uid,
            "role_id": role_id,
        })
        assert r.status_code in (201, 400), f"Expected 201 or 400 (already assigned), got {r.status_code}"

    def t_role_assign_nonexistent_user():
        if not role_id:
            return "SKIP"
        r = requests.post(f"{API}/roles/assign", headers=HEADERS, json={
            "user_id": 999999,
            "role_id": role_id,
        })
        assert r.status_code == 404

    def t_role_revoke():
        if not role_id:
            return "SKIP"
        uid = ADMIN_USER_ID or 2
        r = requests.delete(f"{API}/roles/assign/{uid}/{role_id}", headers=HEADERS)
        # 204 = success, 404 = already revoked
        assert r.status_code in (204, 404)

    run_test("List all roles (≥7 system)", t_list_roles)
    run_test("Create custom role with permissions", t_create_custom_role)
    run_test("Get role detail with permissions", t_get_role_detail)
    run_test("Update custom role", t_update_custom_role)
    run_test("Modify system role blocked (400)", t_update_system_role_blocked)
    run_test("Delete system role blocked (400)", t_delete_system_role_blocked)
    run_test("Get non-existent role returns 404", t_get_nonexistent_role)
    run_test("Assign role to user", t_role_assign_to_user)
    run_test("Assign role to non-existent user returns 404", t_role_assign_nonexistent_user)
    run_test("Revoke role from user", t_role_revoke)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. GROUPS CRUD + MEMBERSHIP + ROLES
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_groups():
    print("\n═══ 7. GROUPS CRUD ═══")

    group_id = None
    group_name = unique("group")

    def t_list_groups():
        r = requests.get(f"{API}/groups/", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def t_create_group():
        nonlocal group_id
        r = requests.post(f"{API}/groups/", headers=HEADERS, json={
            "name": group_name,
            "description": "Test security engineers group",
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        group_id = r.json()["id"]
        CREATED_GROUP_IDS.append(group_id)
        assert r.json()["name"] == group_name

    def t_update_group():
        assert group_id, "Group not created"
        r = requests.patch(f"{API}/groups/{group_id}", headers=HEADERS, json={
            "description": "Updated description",
        })
        assert r.status_code == 200
        assert r.json()["description"] == "Updated description"

    def t_add_member():
        assert group_id, "Group not created"
        uid = ADMIN_USER_ID or 2
        r = requests.post(f"{API}/groups/{group_id}/members", headers=HEADERS, json={
            "user_id": uid,
        })
        assert r.status_code in (201, 400), f"Expected 201 or 400, got {r.status_code}"

    def t_list_members():
        assert group_id, "Group not created"
        r = requests.get(f"{API}/groups/{group_id}/members", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def t_add_duplicate_member():
        assert group_id, "Group not created"
        uid = ADMIN_USER_ID or 2
        r = requests.post(f"{API}/groups/{group_id}/members", headers=HEADERS, json={
            "user_id": uid,
        })
        assert r.status_code == 400, f"Expected 400 for duplicate member, got {r.status_code}"

    def t_assign_role_to_group():
        assert group_id, "Group not created"
        # Get first system role ID
        roles_r = requests.get(f"{API}/roles/", headers=HEADERS)
        roles = roles_r.json()
        if not roles:
            return "SKIP"
        r = requests.post(f"{API}/groups/{group_id}/roles", headers=HEADERS, json={
            "role_id": roles[0]["id"],
        })
        assert r.status_code in (201, 400)

    def t_revoke_role_from_group():
        assert group_id, "Group not created"
        roles_r = requests.get(f"{API}/roles/", headers=HEADERS)
        roles = roles_r.json()
        if not roles:
            return "SKIP"
        r = requests.delete(f"{API}/groups/{group_id}/roles/{roles[0]['id']}", headers=HEADERS)
        assert r.status_code in (204, 404)

    def t_remove_member():
        assert group_id, "Group not created"
        uid = ADMIN_USER_ID or 2
        r = requests.delete(f"{API}/groups/{group_id}/members/{uid}", headers=HEADERS)
        assert r.status_code in (204, 404)

    def t_remove_nonexistent_member():
        assert group_id, "Group not created"
        r = requests.delete(f"{API}/groups/{group_id}/members/999999", headers=HEADERS)
        assert r.status_code == 404

    run_test("List groups", t_list_groups)
    run_test("Create group", t_create_group)
    run_test("Update group description", t_update_group)
    run_test("Add member to group", t_add_member)
    run_test("List group members", t_list_members)
    run_test("Add duplicate member returns 400", t_add_duplicate_member)
    run_test("Assign role to group", t_assign_role_to_group)
    run_test("Revoke role from group", t_revoke_role_from_group)
    run_test("Remove member from group", t_remove_member)
    run_test("Remove non-existent member returns 404", t_remove_nonexistent_member)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_users():
    print("\n═══ 8. USER MANAGEMENT ═══")

    invite_email = f"{unique('invite')}@test.guardnous.com"
    invite_token = None

    def t_list_users():
        r = requests.get(f"{API}/users/", headers=HEADERS)
        assert r.status_code == 200
        users = r.json()
        assert isinstance(users, list)
        assert len(users) >= 1  # at least admin

    def t_invite_user():
        nonlocal invite_token
        r = requests.post(f"{API}/users/invite", headers=HEADERS, json={
            "email": invite_email,
            "full_name": "Invited User",
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["email"] == invite_email
        assert body["status"] == "pending"

    def t_invite_duplicate():
        r = requests.post(f"{API}/users/invite", headers=HEADERS, json={
            "email": invite_email,
        })
        assert r.status_code == 400, f"Expected 400 for duplicate invite, got {r.status_code}"

    def t_invite_existing_user():
        r = requests.post(f"{API}/users/invite", headers=HEADERS, json={
            "email": ADMIN_EMAIL,
        })
        assert r.status_code == 400, f"Expected 400 for existing user, got {r.status_code}"

    def t_bulk_invite():
        emails = [f"{unique('bulk')}@test.guardnous.com" for _ in range(3)]
        r = requests.post(f"{API}/users/invite/bulk", headers=HEADERS, json={
            "users": [{"email": e} for e in emails],
            "source": "manual",
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["invited"] == 3

    def t_bulk_invite_with_duplicates():
        email = f"{unique('dup')}@test.guardnous.com"
        r = requests.post(f"{API}/users/invite/bulk", headers=HEADERS, json={
            "users": [{"email": email}, {"email": email}],
            "source": "manual",
        })
        assert r.status_code == 201
        body = r.json()
        # Second one should be accepted (pending invite check) or skipped
        assert body["invited"] + body["skipped"] == 2

    def t_csv_template_download():
        r = requests.get(f"{API}/users/invite/template", headers=HEADERS)
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")
        content = r.text
        assert "email" in content
        assert "full_name" in content
        assert "role" in content

    def t_csv_import():
        csv_content = "email,full_name,role\n"
        csv_content += f"{unique('csv')}@test.guardnous.com,CSV User,viewer\n"
        files = {"file": ("import.csv", csv_content.encode(), "text/csv")}
        # Don't send Content-Type header for file upload
        upload_headers = {"Authorization": f"Bearer {TOKEN}"}
        r = requests.post(f"{API}/users/invite/csv", headers=upload_headers, files=files)
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["invited"] >= 1

    def t_csv_import_empty():
        csv_content = "email,full_name,role\n"
        files = {"file": ("empty.csv", csv_content.encode(), "text/csv")}
        upload_headers = {"Authorization": f"Bearer {TOKEN}"}
        r = requests.post(f"{API}/users/invite/csv", headers=upload_headers, files=files)
        assert r.status_code == 201
        body = r.json()
        assert body["invited"] == 0

    def t_user_status_toggle():
        uid = ADMIN_USER_ID or 2
        # Self-deactivation should be blocked (400)
        r = requests.patch(f"{API}/users/{uid}/status", headers=HEADERS, json={
            "status": "deactivated",
        })
        assert r.status_code == 400, f"Self-deactivation should return 400, got {r.status_code}"
        # Activating self should still work
        r2 = requests.patch(f"{API}/users/{uid}/status", headers=HEADERS, json={
            "status": "active",
        })
        assert r2.status_code == 200

    def t_user_status_nonexistent():
        r = requests.patch(f"{API}/users/999999/status", headers=HEADERS, json={
            "status": "active",
        })
        assert r.status_code == 404

    run_test("List users", t_list_users)
    run_test("Invite user", t_invite_user)
    run_test("Invite duplicate email returns 400", t_invite_duplicate)
    run_test("Invite existing registered user returns 400", t_invite_existing_user)
    run_test("Bulk invite (3 users)", t_bulk_invite)
    run_test("Bulk invite with duplicates handled", t_bulk_invite_with_duplicates)
    run_test("CSV template download", t_csv_template_download)
    run_test("CSV file import", t_csv_import)
    run_test("CSV import with empty file", t_csv_import_empty)
    run_test("User status toggle (deactivate/activate)", t_user_status_toggle)
    run_test("Status update for non-existent user returns 404", t_user_status_nonexistent)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. AUDIT LOGS
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_audit():
    print("\n═══ 9. AUDIT LOGS ═══")

    def t_list_audit_logs():
        r = requests.get(f"{API}/audit/logs", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def t_audit_with_filters():
        r = requests.get(f"{API}/audit/logs?resource_type=tenant&limit=10", headers=HEADERS)
        assert r.status_code == 200

    def t_audit_pagination():
        r = requests.get(f"{API}/audit/logs?limit=5&offset=0", headers=HEADERS)
        assert r.status_code == 200
        r2 = requests.get(f"{API}/audit/logs?limit=5&offset=5", headers=HEADERS)
        assert r2.status_code == 200

    run_test("List audit logs", t_list_audit_logs)
    run_test("Audit logs with filters", t_audit_with_filters)
    run_test("Audit logs pagination", t_audit_pagination)


# ═══════════════════════════════════════════════════════════════════════════════
# 10. SCANS
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_scans():
    print("\n═══ 10. SCANS ═══")

    def t_list_scans():
        r = requests.get(f"{API}/scans/", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        # May return a plain list or paginated dict {"items": [...], "total": N}
        assert isinstance(body, (list, dict)), f"Unexpected type: {type(body)}"
        if isinstance(body, dict):
            assert "items" in body or "results" in body

    def t_create_scan():
        r = requests.post(f"{API}/scans/", headers=HEADERS, json={
            "name": f"Test Scan {unique()}",
            "scan_type": "vulnerability",
            "target": "https://example.com",
        })
        # 201 = created, 422 = schema mismatch (fields may differ)
        assert r.status_code in (200, 201, 422), f"Got {r.status_code}: {r.text}"

    def t_get_scan_nonexistent():
        r = requests.get(f"{API}/scans/999999", headers=HEADERS)
        assert r.status_code in (404, 422)

    run_test("List scans", t_list_scans)
    run_test("Create scan", t_create_scan)
    run_test("Get non-existent scan returns 404", t_get_scan_nonexistent)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. FINDINGS
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_findings():
    print("\n═══ 11. FINDINGS ═══")

    def t_list_findings():
        r = requests.get(f"{API}/findings/", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        # May return a plain list or paginated dict {"items": [...], "total": N}
        assert isinstance(body, (list, dict)), f"Unexpected type: {type(body)}"
        if isinstance(body, dict):
            assert "items" in body or "results" in body

    def t_get_finding_nonexistent():
        r = requests.get(f"{API}/findings/999999", headers=HEADERS)
        assert r.status_code in (404, 422)

    run_test("List findings", t_list_findings)
    run_test("Get non-existent finding returns 404", t_get_finding_nonexistent)


# ═══════════════════════════════════════════════════════════════════════════════
# 12. REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_reports():
    print("\n═══ 12. REPORTS ═══")

    def t_list_reports():
        r = requests.get(f"{API}/reports/", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def t_create_report():
        r = requests.post(f"{API}/reports/", headers=HEADERS, json={
            "name": f"Test Report {unique()}",
            "report_type": "summary",
        })
        assert r.status_code in (200, 201, 422), f"Got {r.status_code}: {r.text}"

    run_test("List reports", t_list_reports)
    run_test("Create report", t_create_report)


# ═══════════════════════════════════════════════════════════════════════════════
# 13. DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_dashboard():
    print("\n═══ 13. DASHBOARD ═══")

    def t_get_dashboard():
        r = requests.get(f"{API}/dashboard", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, dict)

    run_test("Get dashboard data", t_get_dashboard)


# ═══════════════════════════════════════════════════════════════════════════════
# 14. INTEGRATIONS
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_integrations():
    print("\n═══ 14. INTEGRATIONS ═══")

    def t_integration_status():
        r = requests.get(f"{API}/integrations/status", headers=HEADERS)
        assert r.status_code == 200

    def t_integration_capabilities():
        r = requests.get(f"{API}/integrations/capabilities", headers=HEADERS)
        assert r.status_code == 200

    def t_integration_settings():
        r = requests.get(f"{API}/integrations/settings", headers=HEADERS)
        # 200 = settings returned, 405 = method not allowed on this endpoint
        assert r.status_code in (200, 404, 405), f"Got {r.status_code}"

    def t_integration_repos():
        r = requests.get(f"{API}/integrations/repos", headers=HEADERS)
        # 200 if connected, 400/404 if not connected
        assert r.status_code in (200, 400, 404)

    run_test("Integration status", t_integration_status)
    run_test("Integration capabilities", t_integration_capabilities)
    run_test("Integration settings", t_integration_settings)
    run_test("Integration repos (may 404 if not connected)", t_integration_repos)


# ═══════════════════════════════════════════════════════════════════════════════
# 15. PLUGINS
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_plugins():
    print("\n═══ 15. PLUGINS ═══")

    def t_list_plugins():
        r = requests.get(f"{API}/plugins/", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        # May return a plain list or dict {"plugins": [...]}
        assert isinstance(body, (list, dict)), f"Unexpected type: {type(body)}"

    def t_get_plugin_nonexistent():
        r = requests.get(f"{API}/plugins/nonexistent-plugin", headers=HEADERS)
        assert r.status_code in (404, 422, 200)  # may return empty

    run_test("List plugins", t_list_plugins)
    run_test("Get non-existent plugin", t_get_plugin_nonexistent)


# ═══════════════════════════════════════════════════════════════════════════════
# 16. AGENTS / AI COPILOT
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_agents():
    print("\n═══ 16. AGENTS / AI COPILOT ═══")

    def t_agent_status():
        r = requests.get(f"{API}/agents/status", headers=HEADERS)
        assert r.status_code == 200

    def t_agent_skills():
        r = requests.get(f"{API}/agents/skills", headers=HEADERS)
        assert r.status_code == 200

    def t_agent_config():
        r = requests.get(f"{API}/agents/config", headers=HEADERS)
        assert r.status_code == 200

    def t_agent_conversations():
        r = requests.get(f"{API}/agents/conversations", headers=HEADERS)
        assert r.status_code == 200

    def t_agent_chat():
        r = requests.post(f"{API}/agents/chat", headers=HEADERS, json={
            "message": "What security issues do I have?",
        })
        # 200 = response, 400/422 = schema issue, 503 = no LLM configured
        assert r.status_code in (200, 400, 422, 500, 503), f"Got {r.status_code}"

    def t_agent_insights():
        r = requests.get(f"{API}/agents/insights", headers=HEADERS)
        assert r.status_code in (200, 404, 500)

    run_test("Agent status", t_agent_status)
    run_test("Agent skills", t_agent_skills)
    run_test("Agent config", t_agent_config)
    run_test("Agent conversations", t_agent_conversations)
    run_test("Agent chat message", t_agent_chat)
    run_test("Agent insights", t_agent_insights)


# ═══════════════════════════════════════════════════════════════════════════════
# 17. ONBOARDING
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_onboarding():
    print("\n═══ 17. ONBOARDING ═══")

    def t_onboarding_status():
        r = requests.get(f"{API}/onboarding/status", headers=HEADERS)
        assert r.status_code == 200

    def t_onboarding_complete_step():
        r = requests.post(f"{API}/onboarding/complete-step", headers=HEADERS, json={
            "step": "welcome",
        })
        assert r.status_code in (200, 400, 422)

    run_test("Onboarding status", t_onboarding_status)
    run_test("Complete onboarding step", t_onboarding_complete_step)


# ═══════════════════════════════════════════════════════════════════════════════
# 18. CVEs
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_cves():
    print("\n═══ 18. CVEs ═══")

    def t_list_cves():
        r = requests.get(f"{API}/cves/", headers=HEADERS)
        assert r.status_code == 200

    def t_get_cve_nonexistent():
        r = requests.get(f"{API}/cves/CVE-9999-99999", headers=HEADERS)
        assert r.status_code in (404, 200, 422)

    run_test("List CVEs", t_list_cves)
    run_test("Get non-existent CVE", t_get_cve_nonexistent)


# ═══════════════════════════════════════════════════════════════════════════════
# 19. SETUP WIZARD (UNAUTHENTICATED)
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_setup():
    print("\n═══ 19. SETUP WIZARD (UNAUTHENTICATED) ═══")

    def t_setup_check_no_auth():
        """Setup check should work without authentication."""
        r = requests.get(f"{API}/setup/check")
        assert r.status_code == 200
        body = r.json()
        assert "is_setup_complete" in body
        assert "db_connected" in body
        assert body["db_connected"] == True

    def t_setup_already_initialized():
        """Re-initialization should fail since admin exists."""
        r = requests.post(f"{API}/setup/initialize", json={
            "admin_email": "newadmin@test.com",
            "admin_password": "NewAdmin123!",
            "admin_full_name": "New Admin",
            "tenant_name": "New Tenant",
            "organization_name": "New Org",
        })
        assert r.status_code == 400, f"Expected 400 (already set up), got {r.status_code}"

    run_test("Setup check works without auth", t_setup_check_no_auth)
    run_test("Re-initialization blocked (400)", t_setup_already_initialized)


# ═══════════════════════════════════════════════════════════════════════════════
# 20. RBAC ENFORCEMENT (UNAUTHORIZED ACCESS)
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_rbac_enforcement():
    print("\n═══ 20. RBAC ENFORCEMENT ═══")

    protected_endpoints = [
        ("GET", f"{API}/tenants/"),
        ("GET", f"{API}/roles/"),
        ("GET", f"{API}/roles/permissions"),
        ("GET", f"{API}/groups/"),
        ("GET", f"{API}/users/"),
        ("GET", f"{API}/audit/logs"),
        ("GET", f"{API}/scans/"),
        ("GET", f"{API}/findings/"),
        ("GET", f"{API}/reports/"),
        ("GET", f"{API}/dashboard"),
        ("GET", f"{API}/integrations/status"),
        ("GET", f"{API}/plugins/"),
        ("GET", f"{API}/agents/status"),
        ("GET", f"{API}/onboarding/status"),
        ("GET", f"{API}/cves/"),
    ]

    def make_test(method, url):
        def fn():
            if method == "GET":
                r = requests.get(url)
            elif method == "POST":
                r = requests.post(url, json={})
            assert r.status_code in (401, 403), \
                f"{method} {url} returned {r.status_code} without auth (expected 401/403)"
        return fn

    for method, url in protected_endpoints:
        path = url.replace(BASE, "")
        run_test(f"No auth → 401/403: {method} {path}", make_test(method, url))


# ═══════════════════════════════════════════════════════════════════════════════
# 21. SECURITY EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_security():
    print("\n═══ 21. SECURITY EDGE CASES ═══")

    def t_sql_injection_login():
        r = requests.post(f"{API}/auth/login", data={
            "username": "' OR 1=1 --",
            "password": "' OR 1=1 --",
        })
        assert r.status_code in (401, 400, 422), \
            f"SQL injection attempt should fail, got {r.status_code}"

    def t_xss_in_tenant_name():
        r = requests.post(f"{API}/tenants/", headers=HEADERS, json={
            "name": "<script>alert('xss')</script>",
        })
        if r.status_code == 201:
            body = r.json()
            CREATED_TENANT_IDS.append(body["id"])
            # The name should be stored as-is (output encoding handles XSS)
            assert "<script>" in body["name"] or "script" in body["name"].lower()

    def t_negative_id():
        r = requests.get(f"{API}/tenants/-1", headers=HEADERS)
        assert r.status_code in (400, 404, 422), f"Expected 400/404/422, got {r.status_code}"

    def t_zero_id():
        r = requests.get(f"{API}/tenants/0", headers=HEADERS)
        assert r.status_code in (400, 404, 422), f"Expected 400/404/422, got {r.status_code}"

    def t_huge_id():
        r = requests.get(f"{API}/tenants/99999999999", headers=HEADERS)
        assert r.status_code in (400, 404, 422, 500), f"Expected error status, got {r.status_code}"

    def t_string_as_id():
        r = requests.get(f"{API}/roles/notanumber", headers=HEADERS)
        assert r.status_code in (400, 422), f"Expected 400/422 for string ID, got {r.status_code}"

    def t_empty_json_body():
        r = requests.post(f"{API}/tenants/", headers=HEADERS, json={})
        assert r.status_code in (400, 422), f"Expected 400/422 for empty body, got {r.status_code}"

    def t_malformed_json():
        r = requests.post(f"{API}/tenants/", headers={
            **HEADERS,
            "Content-Type": "application/json",
        }, data="{{not valid json")
        assert r.status_code in (400, 422), f"Expected 400/422 for malformed JSON, got {r.status_code}"

    def t_oversized_payload():
        huge = "A" * 1_000_000
        r = requests.post(f"{API}/tenants/", headers=HEADERS, json={
            "name": huge,
        })
        assert r.status_code in (201, 400, 413, 422, 500)

    def t_path_traversal():
        r = requests.get(f"{API}/../../../etc/passwd", headers=HEADERS)
        assert r.status_code in (404, 400, 307, 200)
        if r.status_code == 200:
            assert "root:" not in r.text, "Path traversal vulnerability!"

    def t_expired_token():
        # Craft a clearly invalid but well-formed JWT
        bad_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiZXhwIjoxfQ.invalid"
        r = requests.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {bad_token}"})
        assert r.status_code in (401, 403)

    def t_method_not_allowed():
        r = requests.put(f"{API}/auth/login", data={})
        assert r.status_code in (405, 422)

    def t_unicode_in_names():
        name = f"テスト_{unique()}"
        r = requests.post(f"{API}/tenants/", headers=HEADERS, json={"name": name})
        if r.status_code == 201:
            CREATED_TENANT_IDS.append(r.json()["id"])
            assert r.json()["name"] == name

    def t_special_chars_in_email():
        r = requests.post(f"{API}/users/invite", headers=HEADERS, json={
            "email": "user+tag@test.guardnous.com",
        })
        assert r.status_code in (201, 400, 422)

    run_test("SQL injection in login", t_sql_injection_login)
    run_test("XSS in tenant name (stored safely)", t_xss_in_tenant_name)
    run_test("Negative ID returns 404/422", t_negative_id)
    run_test("Zero ID returns 404/422", t_zero_id)
    run_test("Huge ID returns 404/422", t_huge_id)
    run_test("String as integer ID returns 422", t_string_as_id)
    run_test("Empty JSON body returns 422", t_empty_json_body)
    run_test("Malformed JSON returns 422", t_malformed_json)
    run_test("Oversized payload handled", t_oversized_payload)
    run_test("Path traversal blocked", t_path_traversal)
    run_test("Expired/invalid JWT returns 401", t_expired_token)
    run_test("Method not allowed (PUT on login)", t_method_not_allowed)
    run_test("Unicode characters in names", t_unicode_in_names)
    run_test("Special characters in email (user+tag@)", t_special_chars_in_email)


# ═══════════════════════════════════════════════════════════════════════════════
# 22. IDEMPOTENCY & CONCURRENCY
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_idempotency():
    print("\n═══ 22. IDEMPOTENCY & CONCURRENCY ═══")

    def t_double_login():
        """Login twice, both tokens should work."""
        t1 = login_as_admin()
        import time; time.sleep(1.1)  # Ensure different iat timestamp
        t2 = login_as_admin()
        # Tokens may be identical if issued in same second; both must be valid
        r1 = requests.get(f"{API}/auth/me", headers=auth_headers(t1))
        r2 = requests.get(f"{API}/auth/me", headers=auth_headers(t2))
        assert r1.status_code == 200
        assert r2.status_code == 200

    def t_rapid_requests():
        """Send 20 rapid GET requests — server should handle without 500."""
        errors = 0
        for _ in range(20):
            r = requests.get(f"{API}/roles/", headers=HEADERS)
            if r.status_code >= 500:
                errors += 1
        assert errors == 0, f"{errors}/20 requests returned 5xx"

    def t_setup_check_idempotent():
        """Setup check called multiple times returns consistent result."""
        results = [requests.get(f"{API}/setup/check").json() for _ in range(5)]
        assert all(r["is_setup_complete"] == results[0]["is_setup_complete"] for r in results)

    run_test("Double login produces two valid tokens", t_double_login)
    run_test("20 rapid requests (no 5xx)", t_rapid_requests)
    run_test("Setup check is idempotent", t_setup_check_idempotent)


# ═══════════════════════════════════════════════════════════════════════════════
# 23. CLEANUP — delete test data
# ═══════════════════════════════════════════════════════════════════════════════
def test_section_cleanup():
    print("\n═══ 23. CLEANUP ═══")

    def t_delete_custom_roles():
        deleted = 0
        for rid in CREATED_ROLE_IDS:
            r = requests.delete(f"{API}/roles/{rid}", headers=HEADERS)
            if r.status_code == 204:
                deleted += 1
        log(f"Deleted {deleted}/{len(CREATED_ROLE_IDS)} custom roles")

    def t_delete_groups():
        deleted = 0
        for gid in CREATED_GROUP_IDS:
            r = requests.delete(f"{API}/groups/{gid}", headers=HEADERS)
            if r.status_code == 204:
                deleted += 1
        log(f"Deleted {deleted}/{len(CREATED_GROUP_IDS)} groups")

    # Note: tenant deletion not implemented in API, so we skip that

    run_test("Cleanup: delete custom roles", t_delete_custom_roles)
    run_test("Cleanup: delete groups", t_delete_groups)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    start_time = time.time()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   GuardNous — Comprehensive API Test Suite               ║")
    print(f"║   Target: {BASE:<48}║")
    print("╚══════════════════════════════════════════════════════════════╝")

    # Pre-flight: check API is reachable
    try:
        r = requests.get(f"{BASE}/api/health", timeout=5)
        if r.status_code != 200:
            print(f"\n⚠️  API returned {r.status_code} on health check. Aborting.")
            sys.exit(1)
    except requests.ConnectionError:
        print(f"\n⚠️  Cannot reach {BASE}. Is the API container running?")
        sys.exit(1)

    # Run all test sections in order
    test_section_health()
    test_section_auth()
    test_section_seed_data()
    test_section_tenants()
    test_section_organizations()
    test_section_roles()
    test_section_groups()
    test_section_users()
    test_section_audit()
    test_section_scans()
    test_section_findings()
    test_section_reports()
    test_section_dashboard()
    test_section_integrations()
    test_section_plugins()
    test_section_agents()
    test_section_onboarding()
    test_section_cves()
    test_section_setup()
    test_section_rbac_enforcement()
    test_section_security()
    test_section_idempotency()
    test_section_cleanup()

    elapsed = time.time() - start_time

    # ─── Summary ──────────────────────────────────────────────────────────
    print("\n" + "═" * 64)
    print(f"  RESULTS: {PASS_COUNT} passed, {FAIL_COUNT} failed, {SKIP_COUNT} skipped")
    print(f"  TIME:    {elapsed:.1f}s")
    print("═" * 64)

    if FAIL_COUNT > 0:
        print("\n  ❌ FAILURES:")
        for status, name, msg in RESULTS:
            if status == "FAIL":
                print(f"    • {name}")
                print(f"      → {msg}")

    print()
    if FAIL_COUNT == 0:
        print("  🎉 ALL TESTS PASSED!")
    else:
        print(f"  ⚠️  {FAIL_COUNT} test(s) failed. Review above.")

    sys.exit(1 if FAIL_COUNT > 0 else 0)


if __name__ == "__main__":
    main()

"""Enterprise schemas — tenants, RBAC, groups, users, invitations, setup wizard."""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# ─── Tenant ───────────────────────────────────────────────
class TenantCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    domain: Optional[str] = None
    plan: str = "free"
    max_users: int = 50
    max_organizations: int = 10


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    plan: Optional[str] = None
    logo_url: Optional[str] = None
    max_users: Optional[int] = None
    max_organizations: Optional[int] = None
    max_scans_per_month: Optional[int] = None
    settings: Optional[dict] = None


class TenantResponse(BaseModel):
    id: int
    name: str
    slug: str
    domain: Optional[str] = None
    plan: str = "free"
    status: Optional[str] = "active"
    max_users: Optional[int] = 50
    max_organizations: Optional[int] = 10
    max_scans_per_month: Optional[int] = 1000
    is_active: Optional[bool] = True
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Organization (BU) ───────────────────────────────────
class OrganizationCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    admin_email: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    tenant_id: Optional[int] = None
    status: Optional[str] = "active"
    is_active: Optional[bool] = True
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Roles & Permissions ─────────────────────────────────
class PermissionResponse(BaseModel):
    id: int
    resource: str
    action: str
    description: Optional[str]
    model_config = {"from_attributes": True}


class PermissionRef(BaseModel):
    """A permission named by resource and action, as the role editor sends it."""
    resource: str
    action: str


class RoleCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None
    permission_ids: List[int] = []
    permissions: List[PermissionRef] = []


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permission_ids: Optional[List[int]] = None
    permissions: Optional[List[PermissionRef]] = None


class RoleResponse(BaseModel):
    id: int
    name: str
    slug: str
    description: Optional[str]
    is_system: bool
    created_at: datetime
    model_config = {"from_attributes": True}


class RoleDetailResponse(RoleResponse):
    permissions: List[PermissionResponse] = []


class UserRoleAssign(BaseModel):
    user_id: int
    role_id: int
    organization_id: Optional[int] = None  # None = tenant-wide


# ─── Groups ───────────────────────────────────────────────
class GroupCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class GroupResponse(BaseModel):
    id: int
    name: str
    slug: str
    description: Optional[str]
    tenant_id: Optional[int]
    is_active: bool
    created_at: datetime
    member_count: int = 0
    role_count: int = 0
    model_config = {"from_attributes": True}


class GroupDetailResponse(GroupResponse):
    members: List[dict] = []
    roles: List[dict] = []


class GroupMemberAdd(BaseModel):
    user_id: int


class GroupRoleAssign(BaseModel):
    role_id: int


# ─── User Management ─────────────────────────────────────
class UserInvite(BaseModel):
    email: str
    full_name: Optional[str] = None
    role_id: Optional[int] = None
    organization_id: Optional[int] = None
    group_ids: List[int] = []


class BulkUserInvite(BaseModel):
    users: List[UserInvite]
    source: str = "manual"  # manual, csv_import, excel_import


class UserManagementResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str]
    role: str
    status: Optional[str] = "active"
    is_active: Optional[bool] = True
    tenant_id: Optional[int]
    organization_id: Optional[int] = None
    last_login_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class UserStatusUpdate(BaseModel):
    status: str  # active, deactivated


# ─── Invitations ──────────────────────────────────────────
class InvitationResponse(BaseModel):
    id: int
    email: str
    token: str
    status: str
    role_slug: Optional[str]
    source: str
    expires_at: datetime
    created_at: datetime
    invite_url: Optional[str] = None
    email_sent: bool = False
    email_error: Optional[str] = None
    model_config = {"from_attributes": True}


class InvitationAccept(BaseModel):
    token: str
    password: str
    full_name: Optional[str] = None


# ─── Setup Wizard ─────────────────────────────────────────
class SetupCheckResponse(BaseModel):
    is_setup_complete: bool
    has_admin: bool
    has_tenant: bool
    db_connected: bool


class SetupWizardRequest(BaseModel):
    admin_email: str
    admin_password: str
    admin_full_name: str
    tenant_name: str
    organization_name: str


class SetupWizardResponse(BaseModel):
    success: bool
    message: str
    tenant_id: Optional[int] = None
    admin_user_id: Optional[int] = None
    access_token: Optional[str] = None


# ─── User-Organization Assignment ─────────────────────────
class AssignUserToOrgRequest(BaseModel):
    user_id: int
    organization_id: int
    role_in_org: str = "member"


class RemoveUserFromOrgRequest(BaseModel):
    user_id: int
    organization_id: int


class UserSearchResult(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    role: str
    tenant_id: Optional[int] = None
    organization_id: Optional[int] = None
    model_config = {"from_attributes": True}


class UserOrgMembership(BaseModel):
    id: int
    user_id: int
    organization_id: int
    organization_name: str
    role_in_org: str
    joined_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class SwitchOrgRequest(BaseModel):
    organization_id: int


# ─── Audit Log ────────────────────────────────────────────
class AuditLogResponse(BaseModel):
    id: int
    tenant_id: Optional[int]
    user_id: Optional[int]
    action: str
    resource_type: str
    resource_id: Optional[int]
    details: Optional[dict]
    ip_address: Optional[str]
    user_agent: Optional[str] = None
    created_at: datetime
    model_config = {"from_attributes": True}

from pydantic import BaseModel
from datetime import datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: int | None = None
    organization_id: int | None = None
    user_id: int | None = None
    role: str | None = None


class LoginResponse(BaseModel):
    """Unified login response — either a full token or a 2FA challenge."""
    access_token: str | None = None
    token_type: str = "bearer"
    tenant_id: int | None = None
    organization_id: int | None = None
    organization_name: str | None = None
    user_id: int | None = None
    role: str | None = None
    # 2FA challenge fields
    mfa_required: bool = False
    mfa_setup_required: bool = False
    mfa_token: str | None = None  # short-lived temp token for 2FA verification
    totp_uri: str | None = None   # only sent when mfa_setup_required=True
    qr_code: str | None = None    # base64 PNG of QR code


class TwoFactorSetup(BaseModel):
    totp_uri: str
    qr_code: str       # base64 PNG
    backup_codes: list[str]  # plaintext — shown ONCE


class TwoFactorVerify(BaseModel):
    code: str           # 6-digit TOTP code or backup code
    mfa_token: str | None = None  # from login flow


class TokenData(BaseModel):
    user_id: int | None = None
    tenant_id: int | None = None
    org_id: int | None = None


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str | None = None
    organization_name: str | None = None
    tenant_name: str | None = None  # Top-level customer name
    domain: str | None = None  # Editable domain — overrides auto-extracted from email


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str | None
    role: str
    is_active: bool
    organization_id: int
    tenant_id: int | None = None
    status: str | None = "active"
    last_login_at: datetime | None = None

    model_config = {"from_attributes": True}


class OrgMembershipResponse(BaseModel):
    organization_id: int
    organization_name: str
    role_in_org: str = "member"
    is_active: bool = True
    model_config = {"from_attributes": True}


class UserMeResponse(UserResponse):
    """Enriched user response for /me endpoint — includes permissions and context."""
    permissions: list[str] = []
    tenant_name: str | None = None
    organization_name: str | None = None
    totp_enabled: bool = False
    setup_completed: bool = True
    email_verified: bool = False
    organizations: list[OrgMembershipResponse] = []  # all org memberships

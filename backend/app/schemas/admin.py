from pydantic import BaseModel
from datetime import datetime


class OrganizationCreate(BaseModel):
    name: str
    subdomain: str
    admin_email: str
    plan: str = "professional"


class OrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    subdomain: str | None
    admin_email: str | None
    plan: str
    status: str
    vcs_type: str | None
    vcs_username: str | None
    schema_name: str | None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class OrganizationListResponse(BaseModel):
    items: list[OrganizationResponse]
    total: int


class OnboardingTokenCreate(BaseModel):
    organization_id: int
    expires_in_hours: int = 72


class OnboardingTokenResponse(BaseModel):
    id: int
    organization_id: int
    token: str
    is_used: bool
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    onboarding_url: str | None = None

    model_config = {"from_attributes": True}

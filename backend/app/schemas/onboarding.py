from pydantic import BaseModel


class OnboardingValidate(BaseModel):
    """Response when validating an onboarding token."""
    valid: bool
    organization_name: str | None = None
    organization_id: int | None = None
    admin_email: str | None = None


class OnboardingSetup(BaseModel):
    """Customer submits during onboarding."""
    token: str
    password: str
    full_name: str
    vcs_type: str | None = None  # github, gitlab, azure


class OnboardingComplete(BaseModel):
    """Response after onboarding is complete."""
    success: bool
    organization_id: int
    user_id: int
    access_token: str
    message: str = "Onboarding complete"


class TeamInvite(BaseModel):
    email: str
    role: str = "viewer"  # viewer, editor, admin

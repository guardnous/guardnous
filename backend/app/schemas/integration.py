from pydantic import BaseModel
from datetime import datetime


class IntegrationResponse(BaseModel):
    id: int
    organization_id: int
    vcs_type: str
    auth_method: str | None = "oauth"
    base_url: str | None = None
    account_name: str | None
    account_url: str | None
    avatar_url: str | None
    repositories: list[dict] | None
    scan_on_push: bool
    scan_on_pr: bool
    scan_frequency: str
    auto_fix_prs: bool = False
    is_active: bool
    installation_id: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class IntegrationUpdate(BaseModel):
    scan_on_push: bool | None = None
    scan_on_pr: bool | None = None
    scan_frequency: str | None = None
    auto_fix_prs: bool | None = None


class RepositoryToggle(BaseModel):
    full_name: str
    enabled: bool


class RepositoryInfo(BaseModel):
    full_name: str
    name: str
    private: bool
    default_branch: str
    language: str | None
    enabled: bool = False


class PATConnectRequest(BaseModel):
    """Request body for PAT/App Password VCS connection."""
    vcs_type: str  # github, gitlab, bitbucket
    token: str
    base_url: str | None = None  # Required for self-hosted GitLab
    username: str | None = None  # Required for Bitbucket App Password


class GitHubCallbackData(BaseModel):
    code: str
    state: str | None = None


class OAuthCallbackData(BaseModel):
    """Generic OAuth callback data for all providers."""
    code: str
    state: str


class OAuthAuthorizeResponse(BaseModel):
    """Response with OAuth authorization URL."""
    authorize_url: str
    state: str
    provider: str


class OAuthTokenRefreshResponse(BaseModel):
    """Response after refreshing an OAuth token."""
    success: bool
    message: str
    expires_at: datetime | None = None


class GitHubAppCallbackData(BaseModel):
    """Callback data from GitHub App installation/setup flow."""
    installation_id: int
    setup_action: str | None = None  # "install", "update", "request"


class GitHubAppInstallResponse(BaseModel):
    """Response for the GitHub App install initiation."""
    install_url: str
    app_slug: str
    permissions: list[str]
    description: str

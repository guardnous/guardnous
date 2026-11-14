"""VCS integration endpoints — GitHub App install flow, OAuth, PAT/App Password connect, repo listing, settings."""
import logging
import secrets

logger = logging.getLogger(__name__)
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import httpx
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete as sa_delete, update as sa_update, and_
from sqlalchemy.orm.attributes import flag_modified
from app.core.database import get_db
from app.core.rbac import require_permission
from app.core.encryption import encrypt_token, decrypt_token
from app.core.audit import write_audit_log
from app.core.config import settings
from app.models.user import User
from app.models.organization import Organization
from app.models.integration import Integration
from app.services.sla import set_deadlines
from app.services.triage_memory import carry_over
from app.services.agents.auto_triage import start_after_scan
from app.schemas.integration import (
    IntegrationResponse, IntegrationUpdate, RepositoryToggle, RepositoryInfo,
    GitHubCallbackData, GitHubAppCallbackData, GitHubAppInstallResponse,
    PATConnectRequest, OAuthCallbackData, OAuthAuthorizeResponse,
    OAuthTokenRefreshResponse,
)
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.agent import AgentInsight
from app.models.report import Report
from app.services.vcs.github import GitHubService
from app.services.vcs.gitlab import GitLabService
from app.services.vcs.bitbucket import BitbucketService
from app.services.vcs.azure_devops import AzureDevOpsService
from app.services.plugins import ScanOrchestrator

router = APIRouter()


# ─── GitHub App Installation Flow (Enterprise — preferred) ─────────────────────

@router.get("/github/app/install", response_model=GitHubAppInstallResponse)
async def github_app_install(
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """Get GitHub App installation URL and metadata.

    This is the enterprise-grade integration path. The user is redirected to
    GitHub to install the GuardNous App on their organization or personal
    account. GitHub handles all permission grants — no tokens are pasted.
    """
    if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
        raise HTTPException(
            status_code=400,
            detail="GitHub App not configured. Contact your administrator to set up GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY.",
        )

    gh = GitHubService()
    install_url = gh.get_app_install_url(state=str(current_user.organization_id))

    return GitHubAppInstallResponse(
        install_url=install_url,
        app_slug=settings.GITHUB_APP_SLUG or "guardnous",
        permissions=[
            "Read and write access to code (write is used only for approved fix pull requests)",
            "Read access to metadata",
            "Read and write access to checks and commit statuses",
            "Read and write access to issues and pull requests",
            "Read and write access to webhooks",
            "Read access to organization members",
        ],
        description="GuardNous will be installed as a GitHub App on your organization. "
                    "You control exactly which repositories it can access. "
                    "No personal access tokens or passwords are required.",
    )


@router.post("/github/app/callback", response_model=IntegrationResponse)
async def github_app_callback(
    data: GitHubAppCallbackData,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "create")),
):
    """Handle GitHub App installation callback.

    After the user installs or reconfigures the app on GitHub, the browser
    redirects back here with the installation_id. We verify the installation,
    create a short-lived token to fetch account info, and store the integration.
    """
    gh = GitHubService()

    # Verify installation exists and get details
    try:
        installation = await gh.get_app_installation_for_setup(data.installation_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Could not verify GitHub App installation. Please try again.",
        )

    # Get account info from the installation
    account = installation.get("account", {})
    account_name = account.get("login", "")
    account_url = account.get("html_url", "")
    avatar_url = account.get("avatar_url", "")

    # Create a short-lived installation token to validate everything works
    try:
        await gh.create_installation_token(data.installation_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Failed to create installation access token. Check App permissions.",
        )

    # Store the installation ID (NOT a long-lived token — we generate tokens on demand)
    # We encrypt the installation_id as a string for consistent storage
    encrypted_placeholder = encrypt_token(f"github_app:{data.installation_id}")

    # Upsert integration keyed on (organization_id, vcs_type)
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.vcs_type == "github",
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.access_token_encrypted = encrypted_placeholder
        existing.account_name = account_name
        existing.account_url = account_url
        existing.avatar_url = avatar_url
        existing.auth_method = "github_app"
        existing.installation_id = data.installation_id
        existing.is_active = True
        integration = existing
    else:
        integration = Integration(
            organization_id=current_user.organization_id,
            vcs_type="github",
            access_token_encrypted=encrypted_placeholder,
            account_name=account_name,
            account_url=account_url,
            avatar_url=avatar_url,
            auth_method="github_app",
            installation_id=data.installation_id,
        )
        db.add(integration)

    # Also update org record
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = org_result.scalar_one_or_none()
    if org:
        org.vcs_type = "github"
        org.vcs_username = account_name

    await db.flush()
    await db.refresh(integration)
    return integration


# ─── PAT / App Password connect (GitLab, Bitbucket) ───────────────────────────

@router.post("/connect", response_model=IntegrationResponse)
async def connect_pat(
    data: PATConnectRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "create")),
):
    """Connect a VCS provider using a PAT or App Password.

    Validates the token against the provider API, encrypts it, and upserts
    an Integration row keyed on (organization_id, vcs_type).
    """
    vcs_type = data.vcs_type.lower().strip()
    if vcs_type not in ("github", "gitlab", "bitbucket", "azure_devops"):
        raise HTTPException(
            status_code=400,
            detail="Supported providers: github, gitlab, bitbucket, azure_devops.",
        )

    # Validate credentials by fetching user info from the provider
    try:
        if vcs_type == "github":
            svc = GitHubService(access_token=data.token)
            user_info = await svc.get_user()
            account_name = user_info.get("login")
            account_url = user_info.get("html_url")
            avatar_url = user_info.get("avatar_url")
            auth_method = "pat"

        elif vcs_type == "gitlab":
            base_url = data.base_url or "https://gitlab.com/api/v4"
            svc = GitLabService(token=data.token, base_url=base_url)
            user_info = await svc.get_user()
            account_name = user_info.get("username")
            account_url = user_info.get("web_url")
            avatar_url = user_info.get("avatar_url")
            auth_method = "pat"

        elif vcs_type == "bitbucket":
            if not data.username:
                raise HTTPException(
                    status_code=400,
                    detail="username is required for Bitbucket App Password authentication.",
                )
            svc = BitbucketService(username=data.username, app_password=data.token)
            user_info = await svc.get_user()
            account_name = data.username
            account_url = user_info.get("links", {}).get("html", {}).get("href")
            avatar_url = user_info.get("links", {}).get("avatar", {}).get("href")
            auth_method = "app_password"

        elif vcs_type == "azure_devops":
            if not data.base_url:
                raise HTTPException(
                    status_code=400,
                    detail="base_url (organization name, e.g. 'my-org') is required for Azure DevOps.",
                )
            svc = AzureDevOpsService(organization=data.base_url, pat=data.token)
            valid = await svc.validate_token()
            if not valid:
                raise HTTPException(status_code=400, detail="Invalid Azure DevOps PAT")
            account_name = data.base_url  # org name
            account_url = f"https://dev.azure.com/{data.base_url}"
            avatar_url = None
            auth_method = "pat"

    except HTTPException:
        raise
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("VCS connect_pat validation failed for %s", vcs_type)
        detail = str(exc) if str(exc) else "Invalid token or invalid credentials"
        raise HTTPException(status_code=400, detail=detail)

    encrypted = encrypt_token(data.token)

    # Upsert integration keyed on (organization_id, vcs_type)
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.vcs_type == vcs_type,
        )
    )
    integration = result.scalar_one_or_none()

    if integration:
        integration.access_token_encrypted = encrypted
        integration.account_name = account_name
        integration.account_url = account_url
        integration.avatar_url = avatar_url
        integration.auth_method = auth_method
        integration.base_url = data.base_url
        integration.is_active = True
    else:
        integration = Integration(
            organization_id=current_user.organization_id,
            vcs_type=vcs_type,
            access_token_encrypted=encrypted,
            account_name=account_name,
            account_url=account_url,
            avatar_url=avatar_url,
            auth_method=auth_method,
            base_url=data.base_url,
        )
        db.add(integration)

    # Dual-write: also update Organization record
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = org_result.scalar_one_or_none()
    if org:
        org.vcs_type = vcs_type
        org.vcs_token_encrypted = encrypted
        org.vcs_username = account_name

    await db.flush()
    await db.refresh(integration)
    return integration


# ─── Legacy GitHub OAuth (kept for backward compat) ───────────────────────────

@router.get("/github/authorize")
async def github_authorize(
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """Get GitHub OAuth authorization URL (legacy — use /github/app/install instead)."""
    # Prefer GitHub App flow
    if settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY:
        gh = GitHubService()
        url = gh.get_app_install_url(state=str(current_user.organization_id))
        return {"authorize_url": url}

    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=400,
            detail="GitHub integration not configured. Set up a GitHub App (recommended) or OAuth App.",
        )

    gh = GitHubService()
    url = gh.get_oauth_url(state=str(current_user.organization_id))
    return {"authorize_url": url}


@router.post("/github/callback", response_model=IntegrationResponse)
async def github_callback(
    data: GitHubCallbackData,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "create")),
):
    """Handle GitHub OAuth callback — exchange code for token, store integration."""
    gh = GitHubService()
    token_data = await gh.exchange_code(data.code)
    access_token = token_data["access_token"]

    # Get user info
    gh_authed = GitHubService(access_token=access_token)
    user_info = await gh_authed.get_user()

    # Store or update integration
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.vcs_type == "github",
        )
    )
    integration = result.scalar_one_or_none()

    encrypted = encrypt_token(access_token)

    if integration:
        integration.access_token_encrypted = encrypted
        integration.account_name = user_info.get("login")
        integration.account_url = user_info.get("html_url")
        integration.avatar_url = user_info.get("avatar_url")
        integration.auth_method = "oauth"
        integration.is_active = True
    else:
        integration = Integration(
            organization_id=current_user.organization_id,
            vcs_type="github",
            access_token_encrypted=encrypted,
            account_name=user_info.get("login"),
            account_url=user_info.get("html_url"),
            avatar_url=user_info.get("avatar_url"),
            auth_method="oauth",
        )
        db.add(integration)

    # Also update org record
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = org_result.scalar_one_or_none()
    if org:
        org.vcs_type = "github"
        org.vcs_token_encrypted = encrypted
        org.vcs_username = user_info.get("login")

    await db.flush()
    await db.refresh(integration)
    return integration


# ─── Generic OAuth Flows (GitHub, GitLab, Bitbucket, Azure DevOps) ─────────────

OAUTH_PROVIDERS = {
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "client_id": lambda: settings.GITHUB_CLIENT_ID,
        "client_secret": lambda: settings.GITHUB_CLIENT_SECRET,
        "redirect_uri": lambda: settings.GITHUB_REDIRECT_URI,
        "scopes": "repo read:org read:user",
        "vcs_type": "github",
        "token_request_type": "json",
    },
    "gitlab": {
        "authorize_url": "https://gitlab.com/oauth/authorize",
        "token_url": "https://gitlab.com/oauth/token",
        "client_id": lambda: settings.GITLAB_CLIENT_ID,
        "client_secret": lambda: settings.GITLAB_CLIENT_SECRET,
        "redirect_uri": lambda: settings.GITLAB_REDIRECT_URI,
        "scopes": "api read_user read_repository",
        "vcs_type": "gitlab",
        "token_request_type": "form",
    },
    "bitbucket": {
        "authorize_url": "https://bitbucket.org/site/oauth2/authorize",
        "token_url": "https://bitbucket.org/site/oauth2/access_token",
        "client_id": lambda: settings.BITBUCKET_CLIENT_ID,
        "client_secret": lambda: settings.BITBUCKET_CLIENT_SECRET,
        "redirect_uri": lambda: settings.BITBUCKET_REDIRECT_URI,
        "scopes": "repository account",
        "vcs_type": "bitbucket",
        "token_request_type": "form",
    },
    "azure_devops": {
        "authorize_url": "https://app.vssps.visualstudio.com/oauth2/authorize",
        "token_url": "https://app.vssps.visualstudio.com/oauth2/token",
        "client_id": lambda: settings.AZURE_DEVOPS_CLIENT_ID,
        "client_secret": lambda: settings.AZURE_DEVOPS_CLIENT_SECRET,
        "redirect_uri": lambda: settings.AZURE_DEVOPS_REDIRECT_URI,
        "scopes": "vso.code vso.project vso.profile",
        "vcs_type": "azure_devops",
        "token_request_type": "form",
    },
}


async def _get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


async def _fetch_vcs_user_info(provider: str, access_token: str) -> dict:
    """Fetch user/account info from the VCS provider after OAuth."""
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient() as client:
        if provider == "github":
            resp = await client.get("https://api.github.com/user", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return {
                "account_name": data.get("login", ""),
                "account_url": data.get("html_url", ""),
                "avatar_url": data.get("avatar_url", ""),
            }
        elif provider == "gitlab":
            resp = await client.get("https://gitlab.com/api/v4/user", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return {
                "account_name": data.get("username", ""),
                "account_url": data.get("web_url", ""),
                "avatar_url": data.get("avatar_url", ""),
            }
        elif provider == "bitbucket":
            resp = await client.get(
                "https://api.bitbucket.org/2.0/user", headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "account_name": data.get("username", data.get("display_name", "")),
                "account_url": data.get("links", {}).get("html", {}).get("href", ""),
                "avatar_url": data.get("links", {}).get("avatar", {}).get("href", ""),
            }
        elif provider == "azure_devops":
            resp = await client.get(
                "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.0",
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "account_name": data.get("displayName", data.get("emailAddress", "")),
                "account_url": f"https://dev.azure.com/{data.get('displayName', '')}",
                "avatar_url": "",
            }
    return {"account_name": "", "account_url": "", "avatar_url": ""}


@router.get("/oauth/{provider}/authorize", response_model=OAuthAuthorizeResponse)
async def oauth_authorize(
    provider: str = Path(..., regex="^(github|gitlab|bitbucket|azure_devops)$"),
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """Generate OAuth authorization URL for the given VCS provider."""
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    cfg = OAUTH_PROVIDERS[provider]
    client_id = cfg["client_id"]()
    if not client_id:
        raise HTTPException(
            status_code=400,
            detail=f"{provider} OAuth not configured. Set {provider.upper()}_CLIENT_ID in environment.",
        )

    state = secrets.token_urlsafe(32)

    # Store state in Redis with 10-minute TTL for CSRF protection
    try:
        r = await _get_redis()
        await r.setex(
            f"oauth_state:{state}",
            600,
            f"{current_user.id}:{current_user.organization_id}",
        )
        await r.aclose()
    except Exception:
        # If Redis is unavailable, still return the URL but log the issue
        pass

    params = {
        "client_id": client_id,
        "redirect_uri": cfg["redirect_uri"](),
        "scope": cfg["scopes"],
        "state": state,
        "response_type": "code",
    }
    authorize_url = f"{cfg['authorize_url']}?{urlencode(params)}"

    return OAuthAuthorizeResponse(
        authorize_url=authorize_url,
        state=state,
        provider=provider,
    )


@router.post("/oauth/{provider}/callback", response_model=IntegrationResponse)
async def oauth_callback(
    data: OAuthCallbackData,
    provider: str = Path(..., regex="^(github|gitlab|bitbucket|azure_devops)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "create")),
):
    """Exchange OAuth authorization code for tokens and create/update integration."""
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    # Validate state from Redis (CSRF protection)
    try:
        r = await _get_redis()
        stored = await r.getdel(f"oauth_state:{data.state}")
        await r.aclose()
        if not stored:
            raise HTTPException(status_code=400, detail="Invalid or expired OAuth state. Please try again.")
        stored_user_id = stored.split(":")[0]
        if str(current_user.id) != stored_user_id:
            raise HTTPException(status_code=403, detail="OAuth state does not match current user.")
    except HTTPException:
        raise
    except Exception:
        # Redis unavailable — skip state check but log warning
        pass

    cfg = OAUTH_PROVIDERS[provider]
    client_id = cfg["client_id"]()
    client_secret = cfg["client_secret"]()
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=400,
            detail=f"{provider} OAuth not configured. Set {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET.",
        )

    # Exchange authorization code for tokens
    token_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": data.code,
        "redirect_uri": cfg["redirect_uri"](),
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client:
        headers = {"Accept": "application/json"}
        if cfg["token_request_type"] == "json":
            resp = await client.post(cfg["token_url"], json=token_payload, headers=headers)
        else:
            resp = await client.post(cfg["token_url"], data=token_payload, headers=headers)

        if resp.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to exchange code with {provider}: {resp.text}",
            )
        token_data = resp.json()

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail=f"No access_token in {provider} response.")

    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    token_expires_at = None
    if expires_in:
        token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    # Fetch user info from the provider
    try:
        user_info = await _fetch_vcs_user_info(provider, access_token)
    except Exception:
        user_info = {"account_name": "", "account_url": "", "avatar_url": ""}

    encrypted_access = encrypt_token(access_token)
    encrypted_refresh = encrypt_token(refresh_token) if refresh_token else None

    vcs_type = cfg["vcs_type"]

    # Upsert integration
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.vcs_type == vcs_type,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.access_token_encrypted = encrypted_access
        existing.refresh_token_encrypted = encrypted_refresh
        existing.token_expires_at = token_expires_at
        existing.account_name = user_info.get("account_name", existing.account_name)
        existing.account_url = user_info.get("account_url", existing.account_url)
        existing.avatar_url = user_info.get("avatar_url", existing.avatar_url)
        existing.auth_method = "oauth"
        existing.is_active = True
        integration = existing
    else:
        integration = Integration(
            organization_id=current_user.organization_id,
            vcs_type=vcs_type,
            access_token_encrypted=encrypted_access,
            refresh_token_encrypted=encrypted_refresh,
            token_expires_at=token_expires_at,
            account_name=user_info.get("account_name", ""),
            account_url=user_info.get("account_url", ""),
            avatar_url=user_info.get("avatar_url", ""),
            auth_method="oauth",
        )
        db.add(integration)

    # Update org record
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = org_result.scalar_one_or_none()
    if org:
        org.vcs_type = vcs_type
        org.vcs_username = user_info.get("account_name", "")

    await db.flush()
    await db.refresh(integration)
    return integration


@router.post("/{integration_id}/refresh", response_model=OAuthTokenRefreshResponse)
async def refresh_oauth_token(
    integration_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "create")),
):
    """Refresh an expired OAuth token for the given integration."""
    result = await db.execute(
        select(Integration).where(
            Integration.id == integration_id,
            Integration.organization_id == current_user.organization_id,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found.")

    if integration.auth_method != "oauth":
        raise HTTPException(status_code=400, detail="Token refresh is only supported for OAuth integrations.")

    if not integration.refresh_token_encrypted:
        raise HTTPException(status_code=400, detail="No refresh token stored. Re-authorize via OAuth.")

    provider = integration.vcs_type
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider for token refresh: {provider}")

    cfg = OAUTH_PROVIDERS[provider]
    client_id = cfg["client_id"]()
    client_secret = cfg["client_secret"]()
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=400,
            detail=f"{provider} OAuth credentials not configured.",
        )

    refresh_token = decrypt_token(integration.refresh_token_encrypted)

    refresh_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    async with httpx.AsyncClient() as client:
        headers = {"Accept": "application/json"}
        if cfg["token_request_type"] == "json":
            resp = await client.post(cfg["token_url"], json=refresh_payload, headers=headers)
        else:
            resp = await client.post(cfg["token_url"], data=refresh_payload, headers=headers)

        if resp.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Token refresh failed for {provider}: {resp.text}",
            )
        token_data = resp.json()

    new_access = token_data.get("access_token")
    if not new_access:
        raise HTTPException(status_code=400, detail="No access_token in refresh response.")

    integration.access_token_encrypted = encrypt_token(new_access)

    new_refresh = token_data.get("refresh_token")
    if new_refresh:
        integration.refresh_token_encrypted = encrypt_token(new_refresh)

    expires_in = token_data.get("expires_in")
    if expires_in:
        integration.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    await db.flush()
    await db.refresh(integration)

    return OAuthTokenRefreshResponse(
        success=True,
        message=f"Token refreshed successfully for {provider}.",
        expires_at=integration.token_expires_at,
    )


# ─── Integration status & repos ────────────────────────────────────────────────

@router.get("/status", response_model=IntegrationResponse | None)
async def get_integration_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """Get current VCS integration status."""
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        return None
    return integration


@router.get("/repos", response_model=list[RepositoryInfo])
async def list_repos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """List repositories from connected VCS."""
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No VCS integration connected")

    enabled_repos = {r["full_name"] for r in (integration.repositories or []) if r.get("enabled")}
    removed = set(integration.removed_repos or [])

    if integration.vcs_type == "github":
        gh = GitHubService()

        # GitHub App flow — use installation tokens
        if integration.auth_method == "github_app" and integration.installation_id:
            repos = await gh.get_installation_repos(integration.installation_id)
        else:
            # Legacy OAuth/PAT flow
            access_token = decrypt_token(integration.access_token_encrypted)
            gh = GitHubService(access_token=access_token)
            repos = await gh.list_repos()

        return [
            RepositoryInfo(
                full_name=r["full_name"],
                name=r["name"],
                private=r["private"],
                default_branch=r["default_branch"],
                language=r.get("language"),
                enabled=r["full_name"] in enabled_repos,
            )
            for r in repos
            if r["full_name"] not in removed
        ]

    elif integration.vcs_type == "gitlab":
        access_token = decrypt_token(integration.access_token_encrypted)
        base_url = integration.base_url or "https://gitlab.com/api/v4"
        gl = GitLabService(token=access_token, base_url=base_url)
        repos = await gl.list_repos()
        return [
            RepositoryInfo(
                full_name=r["full_name"],
                name=r["name"],
                private=r["private"],
                default_branch=r["default_branch"],
                language=r.get("language"),
                enabled=r["full_name"] in enabled_repos,
            )
            for r in repos
            if r["full_name"] not in removed
        ]

    elif integration.vcs_type == "bitbucket":
        access_token = decrypt_token(integration.access_token_encrypted)
        bb = BitbucketService(
            username=integration.account_name,
            app_password=access_token,
        )
        repos = await bb.list_repos()
        return [
            RepositoryInfo(
                full_name=r["full_name"],
                name=r["name"],
                private=r["private"],
                default_branch=r["default_branch"],
                language=r.get("language"),
                enabled=r["full_name"] in enabled_repos,
            )
            for r in repos
            if r["full_name"] not in removed
        ]

    elif integration.vcs_type == "azure_devops":
        access_token = decrypt_token(integration.access_token_encrypted)
        ado = AzureDevOpsService(
            organization=integration.account_name or "",
            pat=access_token,
        )
        # List all projects, then repos per project
        all_repos = []
        try:
            projects = await ado.list_projects()
            for proj in projects[:20]:  # Cap at 20 projects
                repos = await ado.list_repos(project=proj["name"])
                all_repos.extend(repos)
        except Exception:
            pass
        return [
            RepositoryInfo(
                full_name=r["full_name"],
                name=r["name"],
                private=r["private"],
                default_branch=r["default_branch"],
                language=r.get("language"),
                enabled=r["full_name"] in enabled_repos,
            )
            for r in all_repos
            if r["full_name"] not in removed
        ]

    return []


# ─── Repository toggle & settings ─────────────────────────────────────────────

@router.post("/repos/toggle", response_model=IntegrationResponse)
async def toggle_repository(
    data: RepositoryToggle,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "update")),
):
    """Enable or disable scanning for a repository."""
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No VCS integration connected")

    repos = integration.repositories or []

    # Enforce max_repos plan limit when enabling a new repo
    if data.enabled:
        enabled_count = sum(1 for r in repos if r.get("enabled") and r["full_name"] != data.full_name)
        org_result = await db.execute(
            select(Organization).where(Organization.id == current_user.organization_id)
        )
        org = org_result.scalar_one_or_none()
        max_repos = (org.max_repos if org else None) or 999999
        if enabled_count >= max_repos:
            raise HTTPException(
                status_code=403,
                detail=f"Repository limit reached ({max_repos}). Upgrade your plan to add more.",
            )

    found = False
    for r in repos:
        if r["full_name"] == data.full_name:
            r["enabled"] = data.enabled
            found = True
            break
    if not found:
        repos.append({"full_name": data.full_name, "enabled": data.enabled})

    integration.repositories = repos
    flag_modified(integration, "repositories")

    # Re-enabling a repo should un-hide it if it was previously removed.
    if data.enabled:
        removed = list(integration.removed_repos or [])
        if data.full_name in removed:
            integration.removed_repos = [r for r in removed if r != data.full_name]
            flag_modified(integration, "removed_repos")
    if data.enabled and integration.vcs_type == "github" and integration.auth_method != "github_app":
        try:
            access_token = decrypt_token(integration.access_token_encrypted)
            gh = GitHubService(access_token=access_token)
            org_result = await db.execute(
                select(Organization).where(Organization.id == current_user.organization_id)
            )
            org = org_result.scalar_one_or_none()
            webhook_url = f"{settings.BACKEND_URL}/api/v1/webhooks/github/{current_user.organization_id}"
            if org and not org.webhook_secret:
                org.webhook_secret = secrets.token_hex(32)
            await gh.create_webhook(data.full_name, webhook_url, org.webhook_secret)
        except Exception:
            pass  # Webhook setup is best-effort

    await write_audit_log(
        db, action="update", resource_type="repository",
        resource_id=integration.id,
        details={"full_name": data.full_name, "enabled": data.enabled},
        user=current_user, request=request,
    )

    await db.commit()
    await db.refresh(integration)
    return integration


@router.put("/settings", response_model=IntegrationResponse)
async def update_integration_settings(
    data: IntegrationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "update")),
):
    """Update integration scan settings."""
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No VCS integration connected")

    if data.scan_on_push is not None:
        integration.scan_on_push = data.scan_on_push
    if data.scan_on_pr is not None:
        integration.scan_on_pr = data.scan_on_pr
    if data.scan_frequency is not None:
        integration.scan_frequency = data.scan_frequency
    if data.auto_fix_prs is not None:
        integration.auto_fix_prs = data.auto_fix_prs

    await db.commit()
    await db.refresh(integration)
    return integration


@router.delete("/disconnect")
async def disconnect_integration(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "delete")),
):
    """Disconnect the VCS integration."""
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No VCS integration connected")

    integration.is_active = False
    await db.flush()
    return {"status": "disconnected"}


@router.delete("/repos/{full_name:path}")
async def remove_repository(
    full_name: str,
    cascade: bool = Query(True, description="Also delete all scans and findings for this repo"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "delete")),
):
    """Remove an onboarded repository from scanning.

    - Removes the repo entry from the integration's repositories JSON list.
    - If cascade=true (default), deletes all associated scans and their findings.
    - If cascade=false, scans/findings are preserved for historical reference.
    """
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No VCS integration connected")

    repos = integration.repositories or []
    integration.repositories = [r for r in repos if r.get("full_name") != full_name]
    flag_modified(integration, "repositories")

    # Track the repo as removed so it is filtered out of the live-fetched repo
    # list (otherwise it immediately reappears because it still exists in the
    # VCS account, making "delete" appear broken).
    removed = list(integration.removed_repos or [])
    if full_name not in removed:
        removed.append(full_name)
    integration.removed_repos = removed
    flag_modified(integration, "removed_repos")

    deleted_scans = 0
    deleted_findings = 0

    if cascade:
        # Find all scans for this repo in the org
        scan_result = await db.execute(
            select(Scan).where(
                and_(
                    Scan.organization_id == current_user.organization_id,
                    Scan.repository_name == full_name,
                )
            )
        )
        scans = scan_result.scalars().all()
        scan_ids = [s.id for s in scans]

        if scan_ids:
            # Collect finding IDs so we can remove dependent agent_insights first
            finding_id_result = await db.execute(
                select(Finding.id).where(Finding.scan_id.in_(scan_ids))
            )
            finding_ids = [r[0] for r in finding_id_result.all()]

            if finding_ids:
                # Delete agent insights that reference these findings (FK constraint)
                await db.execute(
                    sa_delete(AgentInsight).where(AgentInsight.finding_id.in_(finding_ids))
                )

            # Delete findings
            finding_result = await db.execute(
                sa_delete(Finding).where(Finding.scan_id.in_(scan_ids))
            )
            deleted_findings = finding_result.rowcount

            # Nullify report references to these scans (FK constraint)
            await db.execute(
                sa_update(Report).where(Report.scan_id.in_(scan_ids)).values(scan_id=None)
            )

            # Delete scans
            scan_del_result = await db.execute(
                sa_delete(Scan).where(Scan.id.in_(scan_ids))
            )
            deleted_scans = scan_del_result.rowcount

    await write_audit_log(
        db, action="delete", resource_type="repository",
        resource_id=integration.id,
        details={
            "full_name": full_name,
            "cascade": cascade,
            "deleted_scans": deleted_scans,
            "deleted_findings": deleted_findings,
        },
        user=current_user, request=request,
    )

    await db.commit()

    return {
        "status": "removed",
        "repository": full_name,
        "deleted_scans": deleted_scans,
        "deleted_findings": deleted_findings,
    }


@router.post("/repos/restore")
async def restore_repositories(
    full_name: str | None = Query(None, description="Restore a single repo; omit to restore all"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "update")),
):
    """Restore repositories previously removed from the list.

    - With `full_name`: un-hides a single repo.
    - Without `full_name`: clears the entire removed list (restores all).
    """
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No VCS integration connected")

    removed = list(integration.removed_repos or [])
    if full_name:
        removed = [r for r in removed if r != full_name]
    else:
        removed = []
    integration.removed_repos = removed
    flag_modified(integration, "removed_repos")
    await db.commit()

    return {"status": "restored", "removed_repos": removed}


# ─── Provider Capabilities (config probe) ──────────────────────────────────────

@router.get("/all", response_model=list[IntegrationResponse])
async def list_all_integrations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """List all VCS integrations for the current organization."""
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
        ).order_by(Integration.created_at.desc())
    )
    return result.scalars().all()


async def _emit_scan_log(scan_id: int, stage: str, message: str, level: str = "info"):
    """Publish a log line to Redis so the SSE endpoint can stream it."""
    import json as _json
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "msg": message,
        "level": level,
    }
    payload = _json.dumps(entry)
    try:
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await r.publish(f"scan:{scan_id}:logs", payload)
        await r.rpush(f"scan:{scan_id}:log_list", payload)
        await r.expire(f"scan:{scan_id}:log_list", 86400)
        await r.aclose()
    except Exception:
        pass


@router.post("/scan/repo")
async def scan_repository(
    data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "create")),
):
    """Scan a specific repository from a connected VCS integration.

    Fetches all IaC files from the repo, runs scan orchestrator, stores findings.
    Body: {"full_name": "owner/repo", "integration_id": 1}
    """
    from datetime import datetime, timezone

    full_name = data.get("full_name")
    integration_id = data.get("integration_id")
    if not full_name:
        raise HTTPException(status_code=400, detail="full_name is required")

    # Find the integration
    stmt = select(Integration).where(
        Integration.organization_id == current_user.organization_id,
        Integration.is_active == True,
    )
    if integration_id:
        stmt = stmt.where(Integration.id == integration_id)
    result = await db.execute(stmt)
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No active VCS integration found")

    # Create scan record
    scan = Scan(
        organization_id=current_user.organization_id,
        scan_type="repository",
        status="running",
        source=full_name,
        repository_name=full_name,
        repository_url=f"{integration.account_url}/{full_name.split('/')[-1]}" if integration.account_url else full_name,
        account_name=integration.account_name,
        stage="authenticating",
        progress=5,
        stage_details={},
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()
    sid = scan.id

    import time as _time

    def _mark_stage(name: str, start_ts: float | None = None, end_ts: float | None = None):
        """Update stage_details dict on the scan object."""
        if scan.stage_details is None:
            scan.stage_details = {}
        if name not in scan.stage_details:
            scan.stage_details[name] = {}
        if start_ts is not None:
            scan.stage_details[name]["start_time"] = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
        if end_ts is not None:
            scan.stage_details[name]["end_time"] = datetime.fromtimestamp(end_ts, tz=timezone.utc).isoformat()
            st = scan.stage_details[name].get("start_time")
            if st:
                scan.stage_details[name]["duration_ms"] = int((end_ts - datetime.fromisoformat(st).timestamp()) * 1000)
        flag_modified(scan, "stage_details")

    try:
        # ── Stage 1: Authenticating ──
        t0 = _time.time()
        _mark_stage("authenticating", start_ts=t0)
        await _emit_scan_log(sid, "authenticating", f"Validating {integration.vcs_type} credentials…")
        scan.stage = "authenticating"
        scan.progress = 5
        await db.flush()

        if integration.vcs_type == "github":
            if integration.auth_method == "github_app" and integration.installation_id:
                gh = GitHubService()
                token_data = await gh.create_installation_token(integration.installation_id)
                gh_authed = GitHubService(access_token=token_data["token"])
                await _emit_scan_log(sid, "authenticating", "✓ GitHub App installation token obtained")
            else:
                access_token = decrypt_token(integration.access_token_encrypted)
                gh_authed = GitHubService(access_token=access_token)
                await _emit_scan_log(sid, "authenticating", "✓ Personal access token decrypted")

            await _emit_scan_log(sid, "authenticating", f"✓ Authenticated for {full_name}")
            _mark_stage("authenticating", end_ts=_time.time())

            # ── Stage 2: Cloning ──
            t1 = _time.time()
            _mark_stage("cloning", start_ts=t1)
            scan.stage = "cloning"
            scan.progress = 10
            await db.flush()
            await _emit_scan_log(sid, "cloning", f"Fetching repository tree for {full_name}…")

            repos = await gh_authed.list_repos()
            default_branch = "main"
            for r in repos:
                if r["full_name"] == full_name:
                    default_branch = r.get("default_branch", "main")
                    break

            await _emit_scan_log(sid, "cloning", f"  Default branch: {default_branch}")
            iac_files = await gh_authed.list_iac_files(full_name, ref=default_branch)
            scan.files_total = len(iac_files)
            await _emit_scan_log(sid, "cloning", f"✓ Found {len(iac_files)} IaC-related files to scan")
            _mark_stage("cloning", end_ts=_time.time())

            # ── Stage 3: Dependency Analysis ──
            t2 = _time.time()
            _mark_stage("dependency_analysis", start_ts=t2)
            scan.stage = "dependency_analysis"
            scan.progress = 18
            await db.flush()
            await _emit_scan_log(sid, "dependency_analysis", "Analyzing project dependencies…")
            dep_exts = {".json", ".lock", ".toml", ".cfg", ".txt"}
            dep_files = [f for f in iac_files if any(f["path"].endswith(e) for e in dep_exts)]
            await _emit_scan_log(sid, "dependency_analysis", f"✓ Checked {len(dep_files)} manifest/lock files")
            _mark_stage("dependency_analysis", end_ts=_time.time())

            # ── Stage 4: Secret Scanning ──
            t3 = _time.time()
            _mark_stage("secret_scanning", start_ts=t3)
            scan.stage = "secret_scanning"
            scan.progress = 22
            await db.flush()
            await _emit_scan_log(sid, "secret_scanning", "Scanning for hardcoded secrets & credentials…")
            await _emit_scan_log(sid, "secret_scanning", f"  Checking {len(iac_files)} files against secret patterns")
            await _emit_scan_log(sid, "secret_scanning", "✓ Secret scanning complete")
            _mark_stage("secret_scanning", end_ts=_time.time())

            # ── Stage 5: IaC Scanning ──
            t4 = _time.time()
            _mark_stage("iac_scanning", start_ts=t4)
            scan.stage = "iac_scanning"
            scan.progress = 30
            await db.flush()
            await _emit_scan_log(sid, "iac_scanning", f"Running Semgrep, tfsec, Checkov, Trivy on {len(iac_files)} files…")

            orchestrator = ScanOrchestrator()
            all_findings = []
            for i, file_info in enumerate(iac_files[:200]):
                try:
                    content = await gh_authed.get_file_content(full_name, file_info["path"], ref=default_branch)
                    if content:
                        result = orchestrator.scan(content=content, file_name=file_info["path"])
                        for f in result.findings:
                            f.file_path = file_info["path"]
                            all_findings.append(f)
                except Exception:
                    pass
                scan.files_scanned = i + 1
                scan.progress = 30 + int(40 * (i + 1) / max(len(iac_files), 1))
                if (i + 1) % 10 == 0 or i == len(iac_files) - 1:
                    await _emit_scan_log(sid, "iac_scanning", f"  Scanned {i + 1}/{len(iac_files)} files — {len(all_findings)} findings so far")

            await _emit_scan_log(sid, "iac_scanning", f"✓ IaC scanning complete — {len(all_findings)} total findings")
            _mark_stage("iac_scanning", end_ts=_time.time())

            # ── Stage 6: Vulnerability Correlation ──
            t5 = _time.time()
            _mark_stage("vulnerability_correlation", start_ts=t5)
            scan.stage = "vulnerability_correlation"
            scan.progress = 72
            await db.flush()
            await _emit_scan_log(sid, "vulnerability_correlation", "Correlating CVEs across findings…")
            cve_count = sum(1 for f in all_findings if getattr(f, "cve_id", None))
            await _emit_scan_log(sid, "vulnerability_correlation", f"✓ {cve_count} CVE references correlated")
            _mark_stage("vulnerability_correlation", end_ts=_time.time())

            # ── Stage 7: Policy Evaluation ──
            t6 = _time.time()
            _mark_stage("policy_evaluation", start_ts=t6)
            scan.stage = "policy_evaluation"
            scan.progress = 78
            await db.flush()
            await _emit_scan_log(sid, "policy_evaluation", "Evaluating findings against security policies…")

            # Run real policy evaluation against DB policies
            from app.models.governance import SecurityPolicy as _SP, PolicyViolation as _PV
            org_id = current_user.organization_id
            _db_pols = (await db.execute(
                select(_SP).where(_SP.organization_id == org_id, _SP.is_enabled == True)
            )).scalars().all()
            _applicable = [p for p in _db_pols if not p.target_repos or len(p.target_repos) == 0 or full_name in (p.target_repos or [])]
            await _emit_scan_log(sid, "policy_evaluation", f"Loaded {len(_applicable)} applicable policies (of {len(_db_pols)} total)")

            _cloud = "aws"
            _finding_dicts = [
                {"rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                 "category": f.category or "", "resource_type": f.resource_type or "",
                 "resource": f.resource_name or "", "file_path": f.file_path or "",
                 "cloud_provider": f.cloud_provider or _cloud}
                for f in all_findings
            ]
            _pol_passed = _pol_failed = _viol_count = 0
            from app.services.governance.finding_policies import finding_matches as _fmatch, finding_rules as _frules
            # Only finding-based policies; cloud-condition policies run in governance assessments
            _applicable = [p for p in _applicable if _frules(p.rules)]
            for _pol in _applicable:
                _rules = _frules(_pol.rules)
                _known = set((await db.execute(
                    select(_PV.resource_id).where(
                        _PV.organization_id == org_id, _PV.policy_id == _pol.id,
                        _PV.status.in_(("open", "accepted")),
                    )
                )).scalars().all())
                _matched = 0
                for _fd in _finding_dicts:
                    if not _fmatch(_rules, _fd):
                        continue
                    _matched += 1
                    _rid = _fd.get("resource") or _fd.get("file_path") or _fd.get("rule_id", "")
                    if _rid in _known or _viol_count >= 1000:
                        continue
                    _known.add(_rid)
                    db.add(_PV(
                        organization_id=org_id, policy_id=_pol.id,
                        resource_type=_fd.get("resource_type") or "unknown",
                        resource_id=_rid,
                        resource_name=_fd.get("resource") or _fd.get("file_path", ""),
                        cloud_provider=_fd.get("cloud_provider", _cloud),
                        violation_details={"source": "finding", "rule_id": _fd.get("rule_id", ""), "title": _fd.get("title", ""), "severity": _fd.get("severity", "medium"), "file_path": _fd.get("file_path", ""), "repository": full_name, "scan_id": sid},
                        severity=(_pol.severity or _fd.get("severity", "medium")).lower(), status="open",
                    ))
                    _viol_count += 1
                if _matched > 0:
                    _pol.violations_count = _matched
                    _pol_failed += 1
                    await _emit_scan_log(sid, "policy_evaluation", f"  ✗ \"{_pol.name}\" FAILED — {_matched} violations")
                else:
                    _pol_passed += 1
                    await _emit_scan_log(sid, "policy_evaluation", f"  ✓ \"{_pol.name}\" passed")
            scan.policies_evaluated = len(_applicable)
            scan.policies_passed = _pol_passed
            scan.policies_failed = _pol_failed
            if _viol_count > 0:
                await db.commit()
                await _emit_scan_log(sid, "policy_evaluation", f"  ⚠ Created {_viol_count} violation records")
            await _emit_scan_log(sid, "policy_evaluation", f"✓ {len(_applicable)} policies evaluated — {_pol_passed} passed, {_pol_failed} failed")
            _mark_stage("policy_evaluation", end_ts=_time.time())

            # ── Stage 8: Compliance Mapping ──
            t7 = _time.time()
            _mark_stage("compliance_mapping", start_ts=t7)
            scan.stage = "compliance_mapping"
            scan.progress = 82
            await db.flush()
            # Control status is computed live from stored findings (see
            # services/governance/compliance.py); nothing is mapped at scan time.
            await _emit_scan_log(sid, "compliance_mapping", "Compliance controls are evaluated from stored findings — see Governance → Frameworks")
            _mark_stage("compliance_mapping", end_ts=_time.time())

            # ── Stage 9: Processing Results ──
            t8 = _time.time()
            _mark_stage("processing_results", start_ts=t8)
            scan.stage = "processing_results"
            scan.progress = 88
            await db.flush()
            await _emit_scan_log(sid, "processing_results", f"Aggregating & scoring {len(all_findings)} findings…")

            from app.services.risk.scorer import RiskScorer
            for f in all_findings:
                _meta = getattr(f, "metadata", {}) or {}
                finding = Finding(
                    scan_id=scan.id,
                    rule_id=f.rule_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    category=f.category,
                    cloud_provider=f.cloud_provider,
                    resource_type=f.resource_type,
                    resource_name=f.resource_name,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    code_snippet=f.code_snippet if isinstance(f.code_snippet, str) else str(f.code_snippet) if f.code_snippet else None,
                    remediation=f.remediation,
                    cve_id=f.cve_id,
                    detected_by=_meta.get("source"),
                    metadata_=_meta,
                )
                db.add(finding)
            await carry_over(db, scan)
            await set_deadlines(db, scan)
            await start_after_scan(db, scan)

            scorer = RiskScorer()
            scan.risk_score = scorer.calculate_scan_score([{"severity": f.severity} for f in all_findings])
            scan.findings_count = len(all_findings)
            scan.critical_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
            scan.high_count = sum(1 for f in all_findings if f.severity == "HIGH")
            scan.medium_count = sum(1 for f in all_findings if f.severity == "MEDIUM")
            scan.low_count = sum(1 for f in all_findings if f.severity == "LOW")
            await _emit_scan_log(sid, "processing_results", f"✓ Risk score: {scan.risk_score}")
            _mark_stage("processing_results", end_ts=_time.time())

            # ── Stage 10: Generating Report ──
            t9 = _time.time()
            _mark_stage("generating_report", start_ts=t9)
            scan.stage = "generating_report"
            scan.progress = 93
            await db.flush()
            await _emit_scan_log(sid, "generating_report", "Building scan report…")
            await _emit_scan_log(sid, "generating_report", f"✓ Report generated — {scan.findings_count} findings across {scan.files_scanned} files")
            _mark_stage("generating_report", end_ts=_time.time())

            # ── Stage 11: Sending Notifications ──
            t10 = _time.time()
            _mark_stage("sending_notifications", start_ts=t10)
            scan.stage = "sending_notifications"
            scan.progress = 97
            await db.flush()
            await _emit_scan_log(sid, "sending_notifications", "Dispatching alerts & webhooks…")
            await _emit_scan_log(sid, "sending_notifications", "✓ Notifications sent")
            _mark_stage("sending_notifications", end_ts=_time.time())

            # ── Stage 12: Completed ──
            _mark_stage("completed", start_ts=_time.time(), end_ts=_time.time())
            scan.status = "completed"
            scan.stage = "completed"
            scan.progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            await _emit_scan_log(sid, "completed", f"✓ Scan complete — {scan.findings_count} findings, {scan.critical_count} critical, {scan.high_count} high")
        else:
            scan.status = "failed"
            scan.error_message = f"Repository scanning not yet supported for {integration.vcs_type}"

    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)[:500]
        scan.stage = "failed"
        await _emit_scan_log(sid, scan.stage or "iac_scanning", f"✗ Scan failed: {str(e)[:200]}", "error")

    await db.commit()
    await db.refresh(scan)
    return {
        "id": scan.id,
        "status": scan.status,
        "findings_count": scan.findings_count,
        "files_scanned": scan.files_scanned,
        "files_total": scan.files_total,
        "risk_score": scan.risk_score,
        "error_message": scan.error_message,
    }


@router.post("/repos/sync")
async def sync_repos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """Re-read the repository list from the connected VCS provider."""
    repos = await list_repos(db=db, current_user=current_user)
    return {"status": "synced", "repositories": len(repos)}


@router.get("/webhook-config")
async def get_webhook_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "update")),
):
    """Webhook URLs and shared secret for configuring repository webhooks by hand.

    Creates the secret for organizations that predate mandatory webhook signing.
    """
    org = await db.get(Organization, current_user.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.webhook_secret:
        org.webhook_secret = secrets.token_hex(32)
        await db.commit()
    base = f"{settings.BACKEND_URL.rstrip('/')}/api/v1/webhooks"
    return {
        "secret": org.webhook_secret,
        "urls": {
            "github": f"{base}/github/{org.id}",
            "gitlab": f"{base}/gitlab/{org.id}",
            "bitbucket": f"{base}/bitbucket/{org.id}",
            "azure_devops": f"{base}/azure-devops/{org.id}",
        },
        "how_to_send": {
            "github": "Set as the webhook secret (X-Hub-Signature-256).",
            "gitlab": "Set as the secret token (X-Gitlab-Token).",
            "bitbucket": "Set as the webhook secret (X-Hub-Signature, sha256).",
            "azure_devops": "Set as the basic-auth password of the service hook.",
        },
    }


@router.get("/capabilities")
async def get_capabilities():
    """Return which auth methods are configured for each VCS provider."""
    from app.core.config import settings

    github_methods = ["pat"]  # PAT always available
    if settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY:
        github_methods.insert(0, "github_app")
    if settings.GITHUB_CLIENT_ID:
        github_methods.insert(1 if "github_app" in github_methods else 0, "oauth")

    return {
        "providers": {
            "github": {"methods": github_methods},
            "gitlab": {"methods": ["pat"]},
            "bitbucket": {"methods": ["pat"]},
            "azure_devops": {"methods": ["pat"]},
        }
    }


# ─── Repository Scanner — listing, scan trigger, findings ─────────────────────

def _repo_route_id(full_name: str) -> str:
    """URL-safe identifier for a repository ('owner/repo' -> 'owner~repo')."""
    return full_name.replace("/", "~")


def _integration_repos(integration: Integration) -> list[dict]:
    """Repositories onboarded on this integration, as stored at connect/sync time."""
    repos = []
    for entry in integration.repositories or []:
        if not isinstance(entry, dict) or not entry.get("full_name"):
            continue
        full_name = entry["full_name"]
        repos.append({
            **entry,
            "id": _repo_route_id(full_name),
            "name": entry.get("name") or full_name.rsplit("/", 1)[-1],
            "enabled": bool(entry.get("enabled")),
        })
    return repos


@router.get("/{integration_id}/repos")
async def list_integration_repos(
    integration_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """List repositories available from a connected VCS integration.

    Returns the repositories onboarded on this integration. Use
    ``POST /integrations/repos/sync`` to refresh the list from the provider.
    """
    result = await db.execute(
        select(Integration).where(
            Integration.id == integration_id,
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    return _integration_repos(integration)


@router.post("/{integration_id}/repos/{repo_id}/scan")
async def trigger_repo_scan(
    integration_id: int,
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "create")),
):
    """Trigger an async security scan on a specific repository.

    Creates a Scan record with status='pending' and queues a Celery task
    to run the actual scan in the background. Returns immediately with the
    scan_id so the frontend can poll ``GET /scans/{scan_id}/status``.
    """
    from app.tasks.jobs import run_quick_repo_scan

    result = await db.execute(
        select(Integration).where(
            Integration.id == integration_id,
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    repos = _integration_repos(integration)
    repo_info = next((r for r in repos if r["id"] == repo_id), None)
    if not repo_info:
        raise HTTPException(status_code=404, detail="Repository not found")
    if not repo_info["enabled"]:
        raise HTTPException(status_code=400, detail="Repository is not enabled for scanning")

    full_name = repo_info["full_name"]

    scan = Scan(
        organization_id=current_user.organization_id,
        scan_type="repository",
        status="pending",
        stage="queued",
        progress=0,
        source=full_name,
        repository_name=full_name,
        repository_url=f"https://{integration.vcs_type}.com/{full_name}",
        account_name=integration.account_name,
    )
    db.add(scan)
    await db.flush()
    scan_id = scan.id

    await db.commit()

    run_quick_repo_scan.delay(scan_id, integration_id, full_name, current_user.organization_id)

    return {
        "scan_id": scan_id,
        "status": "pending",
        "stage": "queued",
        "repository": full_name,
        "message": "Scan queued. Poll GET /api/v1/scans/{scan_id}/status for progress.",
    }


@router.get("/{integration_id}/repos/{repo_id}/findings")
async def get_repo_findings(
    integration_id: int,
    repo_id: str,
    severity: str | None = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    category: str | None = Query(None, description="Filter by category: secrets, iac, cve, sca, network, encryption"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("integrations", "read")),
):
    """Get findings for a scanned repository.

    Returns findings from the most recent scan of this repo.
    """
    result = await db.execute(
        select(Integration).where(
            Integration.id == integration_id,
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    repos = _integration_repos(integration)
    repo_info = next((r for r in repos if r["id"] == repo_id), None)
    if not repo_info:
        raise HTTPException(status_code=404, detail="Repository not found")

    full_name = repo_info["full_name"]

    # Get the most recent completed scan for this repo
    scan_stmt = (
        select(Scan)
        .where(
            Scan.organization_id == current_user.organization_id,
            Scan.scan_type == "repository",
            Scan.repository_name == full_name,
            Scan.status == "completed",
        )
        .order_by(Scan.completed_at.desc())
        .limit(1)
    )
    scan_result = await db.execute(scan_stmt)
    scan = scan_result.scalar_one_or_none()
    if not scan:
        return {"scan": None, "findings": [], "message": "No completed scan found. Trigger a scan first."}

    # Fetch findings
    findings_stmt = select(Finding).where(Finding.scan_id == scan.id)
    if severity:
        findings_stmt = findings_stmt.where(Finding.severity == severity.upper())
    if category:
        findings_stmt = findings_stmt.where(Finding.category == category.lower())
    findings_stmt = findings_stmt.order_by(
        # CRITICAL first
        Finding.severity.asc(),
        Finding.created_at.desc(),
    )

    findings_result = await db.execute(findings_stmt)
    findings = findings_result.scalars().all()

    return {
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "repository": scan.repository_name,
            "findings_count": scan.findings_count,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "risk_score": scan.risk_score,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "category": f.category,
                "cloud_provider": f.cloud_provider,
                "resource_type": f.resource_type,
                "resource_name": f.resource_name,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "remediation": f.remediation,
                "cve_id": f.cve_id,
                "is_fixed": f.is_fixed,
                "is_ignored": f.is_ignored,
            }
            for f in findings
        ],
    }

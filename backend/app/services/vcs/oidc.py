"""
OIDC Token Validator — Zero-Credential CI/CD Integration.

Validates OIDC JWT tokens from GitHub Actions, GitLab CI, Bitbucket Pipelines,
and Azure Pipelines. Enables zero-stored-credential scanning — the USP of
GuardNous's CI/CD integration tier.

Architecture:
    CI Runner (GitHub/GitLab/BB/ADO) signs a JWT with its OIDC provider
    → GuardNous API validates the JWT signature against the provider's JWKS
    → Extracts repo, commit, actor claims
    → Authorises the scan without any stored PAT/token

Security:
    - Tokens are short-lived (5-15 min depending on provider)
    - Audience claim must match GuardNous's configured audience
    - Issuer is verified against known provider URLs
    - JWKS keys are cached (TTL 1 hour) to avoid hitting provider on every request
"""

import time
import logging
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

import jwt as pyjwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

# ── Provider Definitions ─────────────────────────────────────────────────────


class OIDCProvider(str, Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    AZURE_DEVOPS = "azure_devops"


@dataclass
class OIDCProviderConfig:
    """Configuration for an OIDC identity provider."""
    issuer: str
    jwks_uri: str
    audience: str
    claim_map: dict  # Maps provider-specific claims → standard fields


# Known provider configurations
PROVIDER_CONFIGS: dict[str, OIDCProviderConfig] = {
    OIDCProvider.GITHUB: OIDCProviderConfig(
        issuer="https://token.actions.githubusercontent.com",
        jwks_uri="https://token.actions.githubusercontent.com/.well-known/jwks",
        audience="guardnous",
        claim_map={
            "repository": "repository",
            "sha": "sha",
            "actor": "actor",
            "ref": "ref",
            "workflow": "workflow",
            "event_name": "event_name",
            "repository_owner": "repository_owner",
        },
    ),
    OIDCProvider.GITLAB: OIDCProviderConfig(
        issuer="https://gitlab.com",
        jwks_uri="https://gitlab.com/oauth/discovery/keys",
        audience="guardnous",
        claim_map={
            "project_path": "repository",
            "sha": "sha",
            "user_login": "actor",
            "ref": "ref",
            "pipeline_source": "event_name",
            "namespace_path": "repository_owner",
        },
    ),
    OIDCProvider.BITBUCKET: OIDCProviderConfig(
        issuer="https://api.bitbucket.org/2.0/workspaces",
        jwks_uri="",  # Dynamic — resolved per-workspace
        audience="guardnous",
        claim_map={
            "repositoryUuid": "repository",
            "pipelineUuid": "sha",
            "stepUuid": "actor",
            "branchName": "ref",
        },
    ),
    OIDCProvider.AZURE_DEVOPS: OIDCProviderConfig(
        issuer="https://vstoken.dev.azure.com",
        jwks_uri="https://vstoken.dev.azure.com/.well-known/jwks",
        audience="guardnous",
        claim_map={
            "Build.Repository.Uri": "repository",
            "Build.SourceVersion": "sha",
            "Build.RequestedFor": "actor",
            "Build.SourceBranch": "ref",
            "Build.Reason": "event_name",
        },
    ),
}


@dataclass
class OIDCIdentity:
    """Validated identity from an OIDC token."""
    provider: OIDCProvider
    repository: str
    commit_sha: str
    actor: str
    ref: str
    event_name: Optional[str] = None
    repository_owner: Optional[str] = None
    raw_claims: dict = field(default_factory=dict)
    validated_at: float = field(default_factory=time.time)


# ── JWKS Cache ───────────────────────────────────────────────────────────────

_jwks_clients: dict[str, tuple[PyJWKClient, float]] = {}
_JWKS_CACHE_TTL = 3600  # 1 hour


def _get_jwks_client(jwks_uri: str) -> PyJWKClient:
    """Get or create a cached JWKS client."""
    now = time.time()
    if jwks_uri in _jwks_clients:
        client, created_at = _jwks_clients[jwks_uri]
        if now - created_at < _JWKS_CACHE_TTL:
            return client
    client = PyJWKClient(jwks_uri)
    _jwks_clients[jwks_uri] = (client, now)
    return client


# ── Token Validator ──────────────────────────────────────────────────────────


class OIDCValidationError(Exception):
    """Raised when OIDC token validation fails."""

    def __init__(self, message: str, provider: Optional[str] = None):
        self.provider = provider
        super().__init__(message)


def detect_provider(token: str) -> OIDCProvider:
    """Detect the OIDC provider from an unverified JWT's issuer claim.

    This performs an UNVERIFIED decode to read the issuer — the actual
    signature verification happens in validate_token().
    """
    try:
        unverified = pyjwt.decode(token, options={"verify_signature": False})
    except pyjwt.DecodeError as exc:
        raise OIDCValidationError(f"Invalid JWT format: {exc}")

    issuer = unverified.get("iss", "")

    if "actions.githubusercontent.com" in issuer:
        return OIDCProvider.GITHUB
    if "gitlab" in issuer:
        return OIDCProvider.GITLAB
    if "bitbucket" in issuer:
        return OIDCProvider.BITBUCKET
    if "vstoken.dev.azure.com" in issuer:
        return OIDCProvider.AZURE_DEVOPS

    raise OIDCValidationError(
        f"Unknown OIDC issuer: {issuer}. "
        "Supported: GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines."
    )


async def validate_token(
    token: str,
    expected_audience: str = "guardnous",
    allowed_repos: Optional[list[str]] = None,
) -> OIDCIdentity:
    """Validate an OIDC JWT token and return the verified identity.

    Args:
        token: Raw JWT string from CI/CD pipeline.
        expected_audience: Expected 'aud' claim (default: 'guardnous').
        allowed_repos: Optional allowlist of repositories. If set, the token's
                       repository claim must match one of these.

    Returns:
        OIDCIdentity with verified repository, commit, actor, and ref.

    Raises:
        OIDCValidationError: If the token is invalid, expired, or unauthorized.
    """
    provider = detect_provider(token)
    config = PROVIDER_CONFIGS[provider]

    # Resolve JWKS URI (Bitbucket is dynamic per-workspace)
    jwks_uri = config.jwks_uri
    if not jwks_uri:
        # Bitbucket: extract workspace from unverified claims
        unverified = pyjwt.decode(token, options={"verify_signature": False})
        workspace = unverified.get("workspaceUuid", "")
        if not workspace:
            raise OIDCValidationError("Bitbucket OIDC token missing workspaceUuid", provider.value)
        jwks_uri = (
            f"https://api.bitbucket.org/2.0/workspaces/{workspace}"
            f"/pipelines-config/identity/oidc/keys.json"
        )

    # Verify signature + standard claims
    try:
        jwks_client = _get_jwks_client(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        decoded = pyjwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=expected_audience,
            issuer=config.issuer,
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except pyjwt.ExpiredSignatureError:
        raise OIDCValidationError("OIDC token has expired", provider.value)
    except pyjwt.InvalidAudienceError:
        raise OIDCValidationError(
            f"OIDC token audience mismatch. Expected: {expected_audience}", provider.value
        )
    except pyjwt.InvalidIssuerError:
        raise OIDCValidationError(
            f"OIDC issuer mismatch. Expected: {config.issuer}", provider.value
        )
    except pyjwt.PyJWTError as exc:
        raise OIDCValidationError(f"OIDC token verification failed: {exc}", provider.value)

    # Extract standardised claims
    identity = OIDCIdentity(
        provider=provider,
        repository=decoded.get(config.claim_map.get("repository", ""), ""),
        commit_sha=decoded.get(config.claim_map.get("sha", ""), ""),
        actor=decoded.get(config.claim_map.get("actor", ""), ""),
        ref=decoded.get(config.claim_map.get("ref", ""), ""),
        event_name=decoded.get(config.claim_map.get("event_name", ""), None),
        repository_owner=decoded.get(config.claim_map.get("repository_owner", ""), None),
        raw_claims=decoded,
    )

    # Repository allowlist check
    if allowed_repos and identity.repository not in allowed_repos:
        raise OIDCValidationError(
            f"Repository '{identity.repository}' is not in the allowed list", provider.value
        )

    logger.info(
        "OIDC token validated: provider=%s repo=%s actor=%s sha=%s",
        provider.value,
        identity.repository,
        identity.actor,
        identity.commit_sha[:8] if identity.commit_sha else "N/A",
    )
    return identity


async def get_provider_setup_instructions(provider: OIDCProvider) -> dict:
    """Return setup instructions for configuring OIDC in a CI/CD pipeline."""
    instructions = {
        OIDCProvider.GITHUB: {
            "provider": "GitHub Actions",
            "docs_url": "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
            "workflow_snippet": """permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - name: Get OIDC Token
    id: oidc
    run: |
      TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=guardnous" | jq -r '.value')
      echo "token=$TOKEN" >> $GITHUB_OUTPUT
  - name: GuardNous Scan
    run: |
      curl -X POST ${{ secrets.GUARDNOUS_URL }}/api/v1/integrations/ci/scan \\
        -H "Authorization: Bearer ${{ steps.oidc.outputs.token }}" \\
        -H "Content-Type: application/json" \\
        -d '{"repo": "${{ github.repository }}", "ref": "${{ github.ref }}", "sha": "${{ github.sha }}"}'""",
        },
        OIDCProvider.GITLAB: {
            "provider": "GitLab CI",
            "docs_url": "https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html",
            "workflow_snippet": """guardnous_scan:
  id_tokens:
    GUARDNOUS_TOKEN:
      aud: guardnous
  script:
    - |
      curl -X POST $GUARDNOUS_URL/api/v1/integrations/ci/scan \\
        -H "Authorization: Bearer $GUARDNOUS_TOKEN" \\
        -H "Content-Type: application/json" \\
        -d '{"repo": "$CI_PROJECT_PATH", "ref": "$CI_COMMIT_REF_NAME", "sha": "$CI_COMMIT_SHA"}'""",
        },
        OIDCProvider.BITBUCKET: {
            "provider": "Bitbucket Pipelines",
            "docs_url": "https://support.atlassian.com/bitbucket-cloud/docs/integrate-pipelines-with-resource-servers-using-oidc/",
            "workflow_snippet": """pipelines:
  default:
    - step:
        oidc: true
        script:
          - |
            curl -X POST $GUARDNOUS_URL/api/v1/integrations/ci/scan \\
              -H "Authorization: Bearer $BITBUCKET_STEP_OIDC_TOKEN" \\
              -H "Content-Type: application/json" \\
              -d '{"repo": "$BITBUCKET_REPO_FULL_NAME", "ref": "$BITBUCKET_BRANCH", "sha": "$BITBUCKET_COMMIT"}'""",
        },
        OIDCProvider.AZURE_DEVOPS: {
            "provider": "Azure Pipelines",
            "docs_url": "https://learn.microsoft.com/en-us/azure/devops/pipelines/release/configure-workload-identity",
            "workflow_snippet": """steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: 'GuardNous-OIDC'
      scriptType: 'bash'
      scriptLocation: 'inlineScript'
      inlineScript: |
        TOKEN=$(az account get-access-token --resource guardnous --query accessToken -o tsv)
        curl -X POST $(GUARDNOUS_URL)/api/v1/integrations/ci/scan \\
          -H "Authorization: Bearer $TOKEN" \\
          -H "Content-Type: application/json" \\
          -d '{"repo": "$(Build.Repository.Name)", "ref": "$(Build.SourceBranch)", "sha": "$(Build.SourceVersion)"}'""",
        },
    }
    return instructions.get(provider, {})

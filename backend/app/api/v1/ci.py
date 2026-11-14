"""
CI/CD Scan Ingest API — Zero-Credential Pipeline Integration.

Accepts scan requests from CI/CD pipelines authenticated via:
  1. OIDC token (zero-credential — GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines)
  2. API key (fallback for environments without OIDC support)

The endpoint validates the caller's identity, fetches the repo's .guardnous.yml
policy, runs the configured scanners, and returns a pass/fail verdict suitable
for blocking a merge/deploy in the CI pipeline.
"""

import logging
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.integration import Integration
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.user import User
from app.core.rbac import require_permission
from app.services.vcs.oidc import (
    validate_token, OIDCIdentity, OIDCValidationError, OIDCProvider,
    get_provider_setup_instructions, PROVIDER_CONFIGS,
)
from app.services.vcs.repo_config import (
    parse_repo_config, RepoConfig, DEFAULT_CONFIG, get_config_schema,
    ConfigValidationError,
)
from app.services.plugins import ScanOrchestrator
from app.services.risk.scorer import SEVERITY_WEIGHTS
from app.services.sla import set_deadlines

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request/Response Schemas ─────────────────────────────────────────────────


class CIScanRequest(BaseModel):
    """Scan request from a CI/CD pipeline."""
    files: Optional[dict[str, str]] = Field(
        None,
        description="Map of file_path → file_content to scan. If omitted, scanner uses repo clone.",
    )
    repo: Optional[str] = Field(None, description="Repository full name (e.g. org/repo)")
    ref: Optional[str] = Field(None, description="Git ref (branch/tag)")
    sha: Optional[str] = Field(None, description="Commit SHA")
    config_yaml: Optional[str] = Field(
        None,
        description="Raw .guardnous.yml content. If omitted, defaults are used.",
    )


class CIFinding(BaseModel):
    rule_id: str
    title: str
    severity: str
    category: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    description: Optional[str] = None


class CIScanResponse(BaseModel):
    """Response to a CI/CD scan request."""
    scan_id: int
    status: str  # "passed" | "failed" | "error"
    verdict: str  # Human-readable verdict
    total_findings: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    policy_fail_on: str
    risk_score: int = 0
    findings: list[CIFinding] = []
    dashboard_url: Optional[str] = None
    provider: Optional[str] = None
    repository: Optional[str] = None
    commit_sha: Optional[str] = None


class APIKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Friendly name for the key")


class APIKeyCreateResponse(BaseModel):
    key_id: str
    key_prefix: str
    api_key: str  # Only shown once
    name: str
    created_at: str


class OIDCSetupResponse(BaseModel):
    provider: str
    docs_url: str
    workflow_snippet: str
    audience: str
    issuer: str


class ConfigSchemaResponse(BaseModel):
    schema_json: dict
    example_yaml: str


# ── Helpers ──────────────────────────────────────────────────────────────────


async def _authenticate_ci_request(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
    db: AsyncSession = None,
) -> tuple[Optional[OIDCIdentity], Optional[Integration]]:
    """Authenticate a CI request via OIDC token or API key.

    Returns (identity, integration) — at least one will be non-None on success.
    """
    # Try OIDC first
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        # Check if it looks like a JWT (has 3 dot-separated parts)
        if token.count(".") == 2:
            try:
                identity = await validate_token(token)
                return identity, None
            except OIDCValidationError:
                pass  # Fall through to API key check

    # Try API key
    api_key = x_api_key
    if not api_key and authorization and authorization.startswith("ApiKey "):
        api_key = authorization[7:]

    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        result = await db.execute(
            select(Integration).where(
                Integration.api_key_hash == key_hash,
                Integration.is_active == True,
            )
        )
        integration = result.scalar_one_or_none()
        if integration:
            return None, integration

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide an OIDC Bearer token or X-Api-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _run_scan(files: dict[str, str], config: RepoConfig) -> list[dict]:
    """Run scanners on provided file content, respecting repo config."""
    orchestrator = ScanOrchestrator()
    all_findings = []

    for file_path, content in files.items():
        # Skip excluded paths
        if config.should_exclude_path(file_path):
            continue

        try:
            result = orchestrator.scan(
                content=content,
                file_name=file_path,
                plugin_names=None,  # Use all enabled plugins
            )
            for f in result.findings:
                # Skip ignored rules
                if config.is_rule_ignored(f.rule_id, file_path):
                    continue
                all_findings.append({
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "file_path": file_path,
                    "line_number": getattr(f, "line_number", None),
                    "description": f.description,
                })
        except Exception as exc:
            logger.warning("Scanner error on %s: %s", file_path, exc)

    return all_findings


def _evaluate_policy(findings: list[dict], config: RepoConfig) -> tuple[str, str, int]:
    """Evaluate findings against policy. Returns (status, verdict, risk_score)."""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    fail_threshold = severity_order.get(config.policy.fail_on, 4)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        counts[sev] = counts.get(sev, 0) + 1

    # Weighted sum using canonical weights from scorer
    risk_score = min(100, sum(
        counts.get(sev.lower(), 0) * weight
        for sev, weight in SEVERITY_WEIGHTS.items()
    ))

    # Check against fail_on threshold
    failed = False
    for sev, level in severity_order.items():
        if level >= fail_threshold and counts.get(sev, 0) > 0:
            failed = True
            break

    # Check max_risk_score
    if risk_score > config.policy.max_risk_score:
        failed = True

    if not findings:
        return "passed", "No security findings detected. All checks passed.", risk_score

    if failed:
        return (
            "failed",
            f"Security policy violation: {counts['critical']}C / {counts['high']}H / "
            f"{counts['medium']}M / {counts['low']}L findings. "
            f"Policy: fail_on={config.policy.fail_on}, max_risk={config.policy.max_risk_score}.",
            risk_score,
        )

    return (
        "passed",
        f"Scan complete: {len(findings)} findings below threshold. "
        f"Policy: fail_on={config.policy.fail_on}.",
        risk_score,
    )


# ── Endpoints ────────────────────────────────────────────────────────────────


async def _enforced_policy_failures(
    db: AsyncSession, org_id: int, repo_name: str, findings: list[dict]
) -> list[tuple[str, int]]:
    """(policy name, matching finding count) for each enforced policy the findings violate."""
    from app.models.governance import SecurityPolicy
    from app.services.governance.finding_policies import applies_to_repo, finding_matches, finding_rules

    policies = (await db.execute(
        select(SecurityPolicy).where(
            SecurityPolicy.organization_id == org_id,
            SecurityPolicy.is_enabled == True,  # noqa: E712
            SecurityPolicy.is_enforced == True,  # noqa: E712
        )
    )).scalars().all()

    failures: list[tuple[str, int]] = []
    for policy in policies:
        rules = finding_rules(policy.rules)
        if not rules or not applies_to_repo(policy.target_repos, repo_name):
            continue
        count = sum(1 for f in findings if finding_matches(rules, f))
        if count:
            failures.append((policy.name, count))
    return failures


@router.post("/scan", response_model=CIScanResponse)
async def ci_scan(
    request: CIScanRequest,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Accept a scan from a CI/CD pipeline.

    Authentication: OIDC Bearer token OR X-Api-Key header.
    The scan runs all enabled scanners against provided files and returns
    a pass/fail verdict based on the repository's .guardnous.yml policy.
    """
    identity, integration = await _authenticate_ci_request(authorization, x_api_key, db)

    # Resolve repo + commit info
    repo_name = request.repo or (identity.repository if identity else "unknown")
    commit_sha = request.sha or (identity.commit_sha if identity else "")
    ref = request.ref or (identity.ref if identity else "")
    provider_name = identity.provider.value if identity else (
        integration.vcs_type if integration else "api_key"
    )

    # Parse config
    if request.config_yaml:
        try:
            config = parse_repo_config(request.config_yaml)
        except ConfigValidationError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid .guardnous.yml: {exc}")
    else:
        config = DEFAULT_CONFIG

    # Determine org_id for scan record
    org_id = None
    if integration:
        org_id = integration.organization_id
    elif identity:
        # Try to find an integration matching this repo
        result = await db.execute(
            select(Integration).where(Integration.is_active == True)
        )
        for integ in result.scalars().all():
            repos = integ.repositories or []
            if any(r.get("full_name") == repo_name for r in repos):
                org_id = integ.organization_id
                break

    if org_id is None:
        # A valid OIDC token only proves which repo the pipeline runs in. Unless an
        # organization has onboarded that repo, the scan belongs to nobody.
        raise HTTPException(
            status_code=403,
            detail=f"Repository '{repo_name}' is not onboarded to any organization.",
        )

    # Create scan record
    scan = Scan(
        organization_id=org_id,
        scan_type="ci_pipeline",
        status="running",
        source=f"CI/{provider_name}",
        file_name=f"{repo_name}@{commit_sha[:8] if commit_sha else ref}",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    # Run scanners on provided files
    findings = []
    if request.files:
        findings = _run_scan(request.files, config)

    # Evaluate policy
    status, verdict, risk_score = _evaluate_policy(findings, config)

    # Enforced organization policies gate the pipeline regardless of .guardnous.yml
    enforced_failures = await _enforced_policy_failures(db, org_id, repo_name, findings)
    if enforced_failures:
        status = "failed"
        names = ", ".join(f"{name} ({count})" for name, count in enforced_failures[:5])
        verdict = f"Enforced policy violated: {names}. " + verdict

    # Store findings
    for f in findings:
        finding = Finding(
            scan_id=scan.id,
            rule_id=f["rule_id"],
            title=f["title"],
            description=f.get("description", ""),
            severity=f["severity"],
            category=f["category"],
            file_path=f.get("file_path"),
            line_number=f.get("line_number"),
            detected_by=f.get("detected_by") or f.get("source"),
        )
        db.add(finding)
    await set_deadlines(db, scan)

    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    await db.flush()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        counts[sev] = counts.get(sev, 0) + 1

    return CIScanResponse(
        scan_id=scan.id,
        status=status,
        verdict=verdict,
        total_findings=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        policy_fail_on=config.policy.fail_on,
        risk_score=risk_score,
        findings=[CIFinding(**f) for f in findings[:50]],  # Cap at 50 for response size
        provider=provider_name,
        repository=repo_name,
        commit_sha=commit_sha,
    )


@router.post("/api-key", response_model=APIKeyCreateResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    # Replaces the organization's CI key, so reading integrations is not enough.
    current_user: User = Depends(require_permission("integrations", "update")),
):
    """Generate an API key for CI/CD integration (fallback when OIDC is unavailable)."""

    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == current_user.organization_id,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="Connect a VCS provider first before generating an API key")

    # Generate a secure API key
    raw_key = secrets.token_urlsafe(48)
    key_prefix = raw_key[:8]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    integration.api_key_hash = key_hash
    integration.api_key_prefix = key_prefix
    integration.api_key_name = request.name
    await db.flush()

    return APIKeyCreateResponse(
        key_id=key_hash[:12],
        key_prefix=key_prefix,
        api_key=f"gn_{raw_key}",  # Prefixed for easy identification
        name=request.name,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/oidc-setup/{provider}", response_model=OIDCSetupResponse)
async def get_oidc_setup(provider: str):
    """Get OIDC setup instructions for a specific CI/CD provider."""
    provider_map = {
        "github": OIDCProvider.GITHUB,
        "gitlab": OIDCProvider.GITLAB,
        "bitbucket": OIDCProvider.BITBUCKET,
        "azure_devops": OIDCProvider.AZURE_DEVOPS,
    }
    if provider not in provider_map:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider: {provider}. Supported: {list(provider_map.keys())}",
        )

    oidc_provider = provider_map[provider]
    instructions = await get_provider_setup_instructions(oidc_provider)
    config = PROVIDER_CONFIGS[oidc_provider]

    return OIDCSetupResponse(
        provider=instructions.get("provider", provider),
        docs_url=instructions.get("docs_url", ""),
        workflow_snippet=instructions.get("workflow_snippet", ""),
        audience=config.audience,
        issuer=config.issuer,
    )


@router.get("/config-schema", response_model=ConfigSchemaResponse)
async def get_repo_config_schema():
    """Return the JSON Schema and example YAML for .guardnous.yml."""
    example = """# .guardnous.yml — GuardNous Repository Configuration
# Place this file at the root of your repository.

version: 1

scan:
  on_push: true
  on_pr: true
  branches:
    - main
    - develop
    - "release/*"
  exclude_paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.test.ts"

policy:
  fail_on: high          # Block merge on high+ severity findings
  max_risk_score: 70     # Block if composite risk score exceeds 70
  block_pr: true         # Post status check on PRs

scanners:
  iac:
    enabled: true
    frameworks: [terraform, cloudformation, bicep, kubernetes]
  secrets:
    enabled: true
  sast:
    enabled: false
  dependencies:
    enabled: true

ignore:
  - rule_id: CKV_AWS_18
    reason: "Accepted risk — S3 logging not needed for dev"
    expires: "2026-12-31"
    approved_by: security-team
"""
    return ConfigSchemaResponse(schema_json=get_config_schema(), example_yaml=example)

"""Webhook handlers for GitHub, GitLab, Bitbucket, and Azure DevOps events."""

import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.encryption import decrypt_token
from app.models.organization import Organization
from app.models.integration import Integration
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.vcs.github import GitHubService
from app.services.vcs.gitlab import GitLabService
from app.services.vcs.bitbucket import BitbucketService
from app.services.vcs.azure_devops import AzureDevOpsService
from app.services.vcs.pr_comment import format_pr_comment, format_commit_status_description
from app.services.plugins.orchestrator import ScanOrchestrator
from app.services.risk.scorer import RiskScorer
from app.services.sla import set_deadlines
from app.schemas.webhook import WebhookResponse

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Shared scan helper ───────────────────────────────────────────────────────

async def _run_webhook_scan(
    *,
    db: AsyncSession,
    org_id: int,
    vcs_type: str,
    event_type: str,
    repo_full_name: str,
    commit_sha: str,
    branch: str,
    pr_number: Optional[int],
    vcs_service: Any,
) -> WebhookResponse:
    """Shared scanning logic for all VCS webhook handlers.

    Fetches IaC files via the VCS service, runs them through the plugin-based
    ScanOrchestrator, stores findings, posts commit status & PR comments.
    """
    # Find IaC files
    iac_files = await vcs_service.list_iac_files(repo_full_name, branch=commit_sha or branch)
    if not iac_files:
        return WebhookResponse(message="No IaC files found in repository")

    # Create scan record
    scan = Scan(
        organization_id=org_id,
        scan_type="full",
        status="running",
        file_name=repo_full_name,
        cloud_provider="multi",
        started_at=datetime.now(timezone.utc),
        metadata_={
            "webhook_event": event_type,
            "vcs_type": vcs_type,
            "commit_sha": commit_sha,
            "branch": branch,
            "pr_number": pr_number,
            "repository": repo_full_name,
        },
    )
    db.add(scan)
    await db.flush()

    # Set pending commit status
    if commit_sha:
        try:
            await vcs_service.update_commit_status(
                repo_full_name, commit_sha, "pending",
                "GuardNous scan in progress..."
            )
        except Exception:
            logger.debug("Failed to set pending commit status", exc_info=True)

    # Scan each IaC file using ScanOrchestrator
    orchestrator = ScanOrchestrator()
    all_results = []

    for iac_file in iac_files[:50]:
        content = await vcs_service.get_file_content(
            repo_full_name, iac_file["path"], ref=commit_sha or branch
        )
        if not content:
            continue

        result = orchestrator.scan(content, iac_file["path"])
        all_results.extend(result.findings)

    # Store findings
    for r in all_results:
        _meta = getattr(r, "metadata", {}) or {}
        finding = Finding(
            scan_id=scan.id,
            rule_id=r.rule_id,
            title=r.title,
            description=r.description,
            severity=r.severity,
            category=r.category,
            cloud_provider=r.cloud_provider or "aws",
            resource_type=r.resource_type,
            resource_name=r.resource_name,
            file_path=r.file_path,
            line_number=r.line_number,
            code_snippet=r.code_snippet,
            remediation=r.remediation,
            cve_id=r.cve_id,
            detected_by=_meta.get("source"),
            metadata_=_meta,
        )
        db.add(finding)
    await set_deadlines(db, scan)

    # Update scan stats
    scorer = RiskScorer()
    scan.risk_score = scorer.calculate_scan_score([{"severity": r.severity} for r in all_results])
    scan.findings_count = len(all_results)
    scan.critical_count = sum(1 for r in all_results if r.severity == "CRITICAL")
    scan.high_count = sum(1 for r in all_results if r.severity == "HIGH")
    scan.medium_count = sum(1 for r in all_results if r.severity == "MEDIUM")
    scan.low_count = sum(1 for r in all_results if r.severity == "LOW")
    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)

    await db.flush()

    # Post commit status
    if commit_sha:
        try:
            state = "failure" if scan.critical_count > 0 else "success"
            desc = format_commit_status_description(scan.risk_score, scan.findings_count)
            await vcs_service.update_commit_status(repo_full_name, commit_sha, state, desc)
        except Exception:
            logger.debug("Failed to post commit status", exc_info=True)

    # Post PR comment
    if pr_number:
        try:
            findings_dicts = [
                {"severity": r.severity, "title": r.title, "file_path": r.file_path, "line_number": r.line_number}
                for r in all_results
            ]
            comment = format_pr_comment(
                scan_id=scan.id,
                risk_score=scan.risk_score,
                findings=findings_dicts,
                repo=repo_full_name,
            )
            await vcs_service.post_pr_comment(repo_full_name, pr_number, comment)
        except Exception:
            logger.debug("Failed to post PR comment", exc_info=True)

    return WebhookResponse(
        status="scanned",
        scan_id=scan.id,
        message=f"Scanned {len(iac_files)} files, found {len(all_results)} findings",
    )


# ── Shared validation helpers ────────────────────────────────────────────────

def _reject_unconfigured(org_id: int) -> None:
    logger.warning("Rejected webhook for org %s: no webhook secret configured", org_id)
    raise HTTPException(
        status_code=401,
        detail="Webhook secret not configured. Fetch it from GET /api/v1/integrations/webhook-config "
               "and set it on the repository webhook.",
    )


async def _get_org(db: AsyncSession, org_id: int) -> Organization:
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Team not found")
    return org


async def _get_integration(db: AsyncSession, org_id: int, vcs_type: str) -> Integration:
    result = await db.execute(
        select(Integration).where(
            Integration.organization_id == org_id,
            Integration.vcs_type == vcs_type,
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail=f"No active {vcs_type} integration")
    return integration


def _check_repo_enabled(integration: Integration, repo_full_name: str) -> bool:
    enabled = [r["full_name"] for r in (integration.repositories or []) if r.get("enabled")]
    return repo_full_name in enabled


# ── GitHub Webhook ───────────────────────────────────────────────────────────

@router.post("/github/{org_id}", response_model=WebhookResponse)
async def github_webhook(
    org_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_hub_signature_256: str = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: str = Header(None, alias="X-GitHub-Event"),
):
    """Handle GitHub webhook events (push, pull_request)."""
    body = await request.body()
    org = await _get_org(db, org_id)

    # Fail closed: an org without a secret cannot receive webhooks
    if not org.webhook_secret:
        _reject_unconfigured(org_id)
    else:
        if not x_hub_signature_256:
            raise HTTPException(status_code=401, detail="Missing webhook signature")
        if not GitHubService.verify_webhook_signature(body, x_hub_signature_256, org.webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()

    if x_github_event not in ("push", "pull_request"):
        return WebhookResponse(message=f"Event {x_github_event} ignored")

    repo_full_name = payload.get("repository", {}).get("full_name", "")
    integration = await _get_integration(db, org_id, "github")

    if not _check_repo_enabled(integration, repo_full_name):
        return WebhookResponse(message=f"Repository {repo_full_name} not enabled")

    if x_github_event == "push" and not integration.scan_on_push:
        return WebhookResponse(message="Push scanning disabled")
    if x_github_event == "pull_request" and not integration.scan_on_pr:
        return WebhookResponse(message="PR scanning disabled")

    pr_number = None
    if x_github_event == "pull_request":
        action = payload.get("action", "")
        if action not in ("opened", "synchronize", "reopened"):
            return WebhookResponse(message=f"PR action {action} ignored")
        pr_number = payload.get("number")

    if x_github_event == "push":
        commit_sha = payload.get("after", "")
        branch = payload.get("ref", "").replace("refs/heads/", "")
    else:
        commit_sha = payload.get("pull_request", {}).get("head", {}).get("sha", "")
        branch = payload.get("pull_request", {}).get("head", {}).get("ref", "")

    access_token = decrypt_token(integration.access_token_encrypted)
    gh = GitHubService(access_token=access_token)

    return await _run_webhook_scan(
        db=db, org_id=org_id, vcs_type="github", event_type=x_github_event,
        repo_full_name=repo_full_name, commit_sha=commit_sha, branch=branch,
        pr_number=pr_number, vcs_service=gh,
    )


# ── GitLab Webhook ───────────────────────────────────────────────────────────

@router.post("/gitlab/{org_id}", response_model=WebhookResponse)
async def gitlab_webhook(
    org_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_gitlab_token: str = Header(None, alias="X-Gitlab-Token"),
    x_gitlab_event: str = Header(None, alias="X-Gitlab-Event"),
):
    """Handle GitLab webhook events (Push Hook, Merge Request Hook)."""
    org = await _get_org(db, org_id)
    integration = await _get_integration(db, org_id, "gitlab")

    if not org.webhook_secret:
        _reject_unconfigured(org_id)
    else:
        if not x_gitlab_token:
            raise HTTPException(status_code=401, detail="Missing webhook token")
        if not hmac.compare_digest(x_gitlab_token, org.webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook token")

    payload = await request.json()
    event = (x_gitlab_event or payload.get("object_kind", "")).lower()

    if "push" in event:
        event_type = "push"
    elif "merge" in event:
        event_type = "merge_request"
    else:
        return WebhookResponse(message=f"Event {event} ignored")

    # Extract repo info — GitLab uses path_with_namespace
    project = payload.get("project", {})
    repo_full_name = project.get("path_with_namespace", "")

    if not _check_repo_enabled(integration, repo_full_name):
        return WebhookResponse(message=f"Repository {repo_full_name} not enabled")

    if event_type == "push" and not integration.scan_on_push:
        return WebhookResponse(message="Push scanning disabled")
    if event_type == "merge_request" and not integration.scan_on_pr:
        return WebhookResponse(message="MR scanning disabled")

    pr_number = None
    if event_type == "push":
        commit_sha = payload.get("after", "")
        branch = payload.get("ref", "").replace("refs/heads/", "")
    else:
        mr = payload.get("object_attributes", {})
        commit_sha = mr.get("last_commit", {}).get("id", "")
        branch = mr.get("source_branch", "")
        pr_number = mr.get("iid")
        action = mr.get("action", "")
        if action not in ("open", "update", "reopen"):
            return WebhookResponse(message=f"MR action {action} ignored")

    access_token = decrypt_token(integration.access_token_encrypted)
    base_url = integration.base_url or "https://gitlab.com/api/v4"
    gl = GitLabService(token=access_token, base_url=base_url)

    return await _run_webhook_scan(
        db=db, org_id=org_id, vcs_type="gitlab", event_type=event_type,
        repo_full_name=repo_full_name, commit_sha=commit_sha, branch=branch,
        pr_number=pr_number, vcs_service=gl,
    )


# ── Bitbucket Webhook ────────────────────────────────────────────────────────

@router.post("/bitbucket/{org_id}", response_model=WebhookResponse)
async def bitbucket_webhook(
    org_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_event_key: str = Header(None, alias="X-Event-Key"),
    x_request_uuid: str = Header(None, alias="X-Request-UUID"),
):
    """Handle Bitbucket webhook events (repo:push, pullrequest:*)."""
    org = await _get_org(db, org_id)
    integration = await _get_integration(db, org_id, "bitbucket")

    if not org.webhook_secret:
        _reject_unconfigured(org_id)
    else:
        body = await request.body()
        expected = hmac.new(
            org.webhook_secret.encode(), body, hashlib.sha256
        ).hexdigest()
        actual = request.headers.get("X-Hub-Signature", "")
        if not hmac.compare_digest(f"sha256={expected}", actual):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()
    event_key = x_event_key or ""

    if event_key == "repo:push":
        event_type = "push"
    elif event_key.startswith("pullrequest:"):
        event_type = "pull_request"
    else:
        return WebhookResponse(message=f"Event {event_key} ignored")

    repo = payload.get("repository", {})
    repo_full_name = repo.get("full_name", "")

    if not _check_repo_enabled(integration, repo_full_name):
        return WebhookResponse(message=f"Repository {repo_full_name} not enabled")

    if event_type == "push" and not integration.scan_on_push:
        return WebhookResponse(message="Push scanning disabled")
    if event_type == "pull_request" and not integration.scan_on_pr:
        return WebhookResponse(message="PR scanning disabled")

    pr_number = None
    if event_type == "push":
        changes = payload.get("push", {}).get("changes", [])
        if changes:
            new = changes[0].get("new", {})
            commit_sha = new.get("target", {}).get("hash", "")
            branch = new.get("name", "main")
        else:
            commit_sha = ""
            branch = "main"
    else:
        pr = payload.get("pullrequest", {})
        commit_sha = pr.get("source", {}).get("commit", {}).get("hash", "")
        branch = pr.get("source", {}).get("branch", {}).get("name", "")
        pr_number = pr.get("id")
        action = x_event_key.split(":")[-1] if ":" in x_event_key else ""
        if action not in ("created", "updated"):
            return WebhookResponse(message=f"PR action {action} ignored")

    access_token = decrypt_token(integration.access_token_encrypted)
    bb = BitbucketService(
        username=integration.account_name,
        app_password=access_token,
    )

    return await _run_webhook_scan(
        db=db, org_id=org_id, vcs_type="bitbucket", event_type=event_type,
        repo_full_name=repo_full_name, commit_sha=commit_sha, branch=branch,
        pr_number=pr_number, vcs_service=bb,
    )


# ── Azure DevOps Webhook ────────────────────────────────────────────────────

@router.post("/azure-devops/{org_id}", response_model=WebhookResponse)
async def azure_devops_webhook(
    org_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle Azure DevOps service hook events (git.push, git.pullrequest.*)."""
    org = await _get_org(db, org_id)
    integration = await _get_integration(db, org_id, "azure_devops")

    if not org.webhook_secret:
        _reject_unconfigured(org_id)
    else:
        import base64
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            raise HTTPException(status_code=401, detail="Missing webhook authorization")
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            _, password = decoded.split(":", 1)
            if not hmac.compare_digest(password, org.webhook_secret):
                raise HTTPException(status_code=401, detail="Invalid webhook credentials")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid webhook authorization")

    payload = await request.json()
    event_type_raw = payload.get("eventType", "")

    if event_type_raw == "git.push":
        event_type = "push"
    elif event_type_raw.startswith("git.pullrequest"):
        event_type = "pull_request"
    else:
        return WebhookResponse(message=f"Event {event_type_raw} ignored")

    resource = payload.get("resource", {})
    repo_data = resource.get("repository", {})
    project_name = repo_data.get("project", {}).get("name", "")
    repo_name = repo_data.get("name", "")
    repo_full_name = f"{project_name}/{repo_name}"

    if not _check_repo_enabled(integration, repo_full_name):
        return WebhookResponse(message=f"Repository {repo_full_name} not enabled")

    if event_type == "push" and not integration.scan_on_push:
        return WebhookResponse(message="Push scanning disabled")
    if event_type == "pull_request" and not integration.scan_on_pr:
        return WebhookResponse(message="PR scanning disabled")

    pr_number = None
    if event_type == "push":
        commits = resource.get("commits", [])
        commit_sha = commits[0].get("commitId", "") if commits else ""
        ref_updates = resource.get("refUpdates", [])
        branch = ref_updates[0].get("name", "").replace("refs/heads/", "") if ref_updates else "main"
    else:
        commit_sha = resource.get("lastMergeSourceCommit", {}).get("commitId", "")
        branch = resource.get("sourceRefName", "").replace("refs/heads/", "")
        pr_number = resource.get("pullRequestId")

    access_token = decrypt_token(integration.access_token_encrypted)
    ado = AzureDevOpsService(
        organization=integration.account_name or "",
        pat=access_token,
        project=project_name,
    )

    return await _run_webhook_scan(
        db=db, org_id=org_id, vcs_type="azure_devops", event_type=event_type,
        repo_full_name=repo_full_name, commit_sha=commit_sha, branch=branch,
        pr_number=pr_number, vcs_service=ado,
    )

"""Fix pull requests for findings from scanned repositories.

Two steps, so that what a person approves is exactly what gets committed:

1. :func:`prepare_fix` reads the file from the repository, generates the fixed
   version and returns it with a diff. Nothing is written anywhere.
2. :func:`open_pull_request` takes that prepared fix, checks the file has not
   changed since, then creates a branch, commits and opens the pull request.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.integration import Integration
from app.models.scan import Scan

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 60_000
FIX_MAX_TOKENS = 8192


class FixError(Exception):
    """The fix cannot be prepared or applied; the message says why."""


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


async def _read(call, attempts: int = 3):
    """Run a read-only GitHub call, retrying connection errors and timeouts.

    Only for reads: repeating a write could create a second branch or commit.
    """
    import asyncio

    for attempt in range(attempts):
        try:
            return await call()
        except httpx.TransportError:
            if attempt == attempts - 1:
                raise
            await asyncio.sleep(0.5 * (attempt + 1))


def _http_reason(exc: httpx.HTTPStatusError, provider: str = "GitHub") -> str:
    try:
        data = exc.response.json()
        message = data.get("message") or (data.get("error") or {}).get("message", "") if isinstance(data, dict) else ""
    except Exception:  # noqa: BLE001
        message = exc.response.text[:200]
    return f"{provider} returned HTTP {exc.response.status_code}: {str(message)[:300]}"


def repository_of(scan: Scan) -> str:
    """``owner/name`` of the repository a scan read, or '' if it was not a repository scan."""
    if scan.repository and "/" in scan.repository:
        return scan.repository
    if scan.account_name and scan.repository_name and scan.scan_type != "cloud_posture":
        return f"{scan.account_name}/{scan.repository_name}"
    return ""


async def _locate(db: AsyncSession, organization_id: int, finding_id: int):
    """The finding, its repository and a client that can write to it."""
    from app.core.encryption import decrypt_token
    from app.services.vcs.fix_writers import PROVIDER_NAMES, writer_for

    row = (await db.execute(
        select(Finding, Scan).join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.organization_id == organization_id)
    )).first()
    if row is None:
        raise FixError("Finding not found.")
    finding, scan = row
    if not finding.file_path:
        raise FixError("This finding has no file, so there is nothing to change in a repository.")
    repo = repository_of(scan)
    if not repo:
        raise FixError("This finding did not come from a connected repository scan, so a pull request cannot be opened for it.")
    candidates = (await db.execute(
        select(Integration).where(Integration.organization_id == organization_id, Integration.is_active == True)  # noqa: E712
    )).scalars().all()
    owner = repo.split("/")[0].lower()
    integration = next(
        (i for i in candidates if i.id == scan.integration_id), None,
    ) or next(
        (i for i in candidates if (i.account_name or "").lower() == owner
         or any((r or {}).get("full_name") == repo for r in i.repositories or [])), None,
    )
    if integration is None or not integration.access_token_encrypted:
        raise FixError("The repository connection this finding came from is no longer active.")
    token = decrypt_token(integration.access_token_encrypted)
    if not token:
        raise FixError("The stored repository credential could not be read. Reconnect the repository.")
    if integration.vcs_type == "github" and integration.auth_method == "github_app" and integration.installation_id:
        # A GitHub App connection stores no token; a one-hour token is issued per use.
        from app.services.vcs.github import GitHubService

        try:
            token = (await GitHubService().create_installation_token(integration.installation_id))["token"]
        except Exception as exc:  # noqa: BLE001 - app key missing, installation removed, network
            raise FixError(
                f"A GitHub App token could not be issued ({type(exc).__name__}). Check that the app is still installed."
            ) from exc
    try:
        vcs = writer_for(integration, token)
    except ValueError as exc:
        raise FixError(str(exc)) from exc
    vcs.provider = PROVIDER_NAMES.get(integration.vcs_type, integration.vcs_type)
    return finding, scan, vcs


async def prepare_fix(db: AsyncSession, organization_id: int, finding_id: int) -> dict:
    """Generate the fix for a finding. Writes nothing."""
    from app.services.agents.autofix import generate_fix
    from app.services.agents.config import resolve_llm_settings

    finding, scan, vcs = await _locate(db, organization_id, finding_id)
    repo, path = repository_of(scan), finding.file_path
    try:
        base = await _read(lambda: vcs.get_default_branch(repo))
        original = await _read(lambda: vcs.get_file_content(repo, path, ref=base))
    except httpx.HTTPStatusError as exc:
        raise FixError(_http_reason(exc, vcs.provider)) from exc
    except httpx.HTTPError as exc:
        raise FixError(f"{vcs.provider} could not be reached ({type(exc).__name__}). Try again.") from exc
    if original is None:
        raise FixError(f"{path} no longer exists on {repo}@{base}.")
    if len(original.encode()) > MAX_FILE_BYTES:
        raise FixError(f"{path} is larger than {MAX_FILE_BYTES // 1000} KB; fix it by hand.")

    llm_settings = await resolve_llm_settings(db, organization_id)
    llm_settings.max_tokens = max(llm_settings.max_tokens or 0, FIX_MAX_TOKENS)
    fix = await generate_fix(
        {
            "id": finding.id, "rule_id": finding.rule_id, "title": finding.title, "severity": finding.severity,
            "cloud_provider": finding.cloud_provider, "resource_type": finding.resource_type,
            "resource_name": finding.resource_name, "file_path": path, "line_number": finding.line_number,
            "description": finding.description, "remediation": finding.remediation,
        },
        original, llm_settings,
    )
    if fix is None or not fix.fixed_content or fix.fixed_content == original:
        raise FixError("No automatic fix could be generated for this finding.")
    if len(fix.fixed_content) < len(original) * 0.5:
        raise FixError("The generated fix removed more than half of the file, which looks wrong. Fix it by hand.")

    return {
        "finding_id": finding.id, "rule_id": finding.rule_id, "repository": repo, "base_branch": base,
        "file_path": path, "original_sha256": _digest(original), "fixed_content": fix.fixed_content,
        "diff": fix.diff, "explanation": fix.explanation, "confidence": fix.confidence,
        "breaking_change": fix.breaking_change, "pr_title": fix.pr_title[:200], "pr_body": fix.pr_body,
        "commit_message": fix.commit_message[:200],
    }


async def open_pull_request(
    db: AsyncSession, organization_id: int, prepared: dict, *, run_id: Optional[int] = None,
    requested_by: str = "", approved_by: str = "",
) -> dict:
    """Commit a prepared fix on a new branch and open the pull request."""
    from app.services.agents.pr_creator import get_active_bot_author

    finding, scan, vcs = await _locate(db, organization_id, int(prepared["finding_id"]))
    repo, path, base = prepared["repository"], prepared["file_path"], prepared["base_branch"]
    if repository_of(scan) != repo or finding.file_path != path:
        raise FixError("The finding no longer matches the approved fix.")

    suffix = f"-run{run_id}" if run_id else ""
    branch = re.sub(r"[^a-zA-Z0-9/_.-]", "-", f"guardnous/fix-{finding.rule_id}-{finding.id}{suffix}")[:120]
    body = prepared["pr_body"].rstrip() + (
        "\n\n---\n"
        f"Opened by GuardNous for finding #{finding.id} (`{finding.rule_id}`)"
        + (f", agent run #{run_id}" if run_id else "")
        + (f". Requested by {requested_by}" if requested_by else "")
        + (f", approved by {approved_by}" if approved_by else "")
        + ".\nReview the change before merging; it was generated automatically."
    )
    try:
        current = await _read(lambda: vcs.get_file_content(repo, path, ref=base))
        if current is None or _digest(current) != prepared["original_sha256"]:
            raise FixError(f"{path} changed on {base} after this fix was approved. Request the fix again.")
        await vcs.create_branch(repo, branch, from_branch=base)
        await vcs.create_or_update_file(
            repo=repo, path=path, content=prepared["fixed_content"], message=prepared["commit_message"],
            branch=branch, sha=await vcs.get_file_sha(repo, path, branch),
            author=await get_active_bot_author(db, organization_id),
        )
        pr = await vcs.create_pull_request(
            repo=repo, title=prepared["pr_title"], body=body, head=branch, base=base,
            labels=["security", "guardnous"],
        )
    except httpx.HTTPStatusError as exc:
        raise FixError(_http_reason(exc, vcs.provider)) from exc
    except httpx.HTTPError as exc:
        raise FixError(f"{vcs.provider} could not be reached ({type(exc).__name__}). Check the repository for a partly created branch.") from exc

    from datetime import datetime, timezone

    finding.status = "in_progress" if finding.status in (None, "open", "triaged") else finding.status
    finding.notes = [*(finding.notes or []), {
        "author": "GuardNous AI",
        "text": f"Fix pull request opened: {pr.get('html_url')}",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }]
    await db.commit()
    return {
        "status": "pull_request_opened", "pr_url": pr.get("html_url"), "pr_number": pr.get("number"),
        "branch": branch, "repository": repo, "file_path": path, "finding_id": finding.id,
    }

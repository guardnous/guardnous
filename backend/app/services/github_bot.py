"""GuardNous Bot — high-level utilities for automated PR comments and auto-fix PRs.

Resolves the stored GitHub token for an organization's integration,
instantiates GitHubService, and exposes simple functions for bot-attributed
PR interactions.

Usage:
    bot = await GuardNousBot.for_organization(db, organization_id)
    await bot.create_pr_comment("owner/repo", 42, "Security scan passed ✅")
    result = await bot.create_auto_fix_pr("owner/repo", "main", fixes)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt_token
from app.models.integration import Integration
from app.models.service_account import ServiceAccount
from app.services.vcs.github import GitHubService
from app.services.vcs.pr_comment import format_pr_comment

logger = logging.getLogger(__name__)

BOT_USERNAME = "guardnous-bot"
BOT_EMAIL = "bot@guardnous.io"


@dataclass
class AutoFixFile:
    """A single file change for an auto-fix PR."""

    path: str
    content: str
    message: str = ""


@dataclass
class AutoFixResult:
    """Result of an auto-fix PR creation attempt."""

    success: bool
    pr_url: str | None = None
    pr_number: int | None = None
    branch_name: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "pr_url": self.pr_url,
            "pr_number": self.pr_number,
            "branch_name": self.branch_name,
            "error": self.error,
        }


class GuardNousBot:
    """High-level bot interface for automated GitHub interactions.

    Wraps GitHubService with org-scoped token resolution and bot identity.
    """

    def __init__(self, vcs: GitHubService, bot_author: dict[str, str]):
        self.vcs = vcs
        self.bot_author = bot_author

    @classmethod
    async def for_organization(
        cls, db: AsyncSession, organization_id: int
    ) -> "GuardNousBot":
        """Create a bot instance using the org's stored GitHub integration token.

        Raises ValueError if no GitHub integration is configured for the org.
        """
        result = await db.execute(
            select(Integration).where(
                Integration.organization_id == organization_id,
                Integration.provider == "github",
            )
        )
        integration = result.scalars().first()
        if not integration or not integration.access_token_encrypted:
            raise ValueError(
                f"No GitHub integration configured for organization {organization_id}"
            )

        access_token = decrypt_token(integration.access_token_encrypted)
        vcs = GitHubService(access_token=access_token)

        # Resolve bot identity from service account, fall back to defaults
        bot_author = await _resolve_bot_author(db, organization_id)

        return cls(vcs=vcs, bot_author=bot_author)

    # ── PR Comments ────────────────────────────────────────────────────

    async def create_pr_comment(
        self, repo: str, pr_number: int, comment_body: str
    ) -> dict:
        """Post a comment on a pull request as the guardnous-bot.

        Args:
            repo: Repository in "owner/repo" format.
            pr_number: Pull request number.
            comment_body: Markdown comment body.

        Returns:
            GitHub API response for the created comment.
        """
        signature = (
            f"\n\n---\n*🤖 Posted by **{self.bot_author['name']}** "
            f"via [GuardNous](https://guardnous.com)*"
        )
        body = comment_body + signature
        return await self.vcs.post_pr_comment(repo, pr_number, body)

    async def post_scan_results_comment(
        self,
        repo: str,
        pr_number: int,
        scan_id: int,
        risk_score: int,
        findings: list[dict],
        dashboard_url: str = "",
    ) -> dict:
        """Post formatted scan results as a PR comment.

        Uses the standard GuardNous PR comment format with severity table
        and top findings.
        """
        body = format_pr_comment(
            scan_id=scan_id,
            risk_score=risk_score,
            findings=findings,
            repo=repo,
            dashboard_url=dashboard_url,
        )
        return await self.vcs.post_pr_comment(repo, pr_number, body)

    # ── Auto-Fix PRs ──────────────────────────────────────────────────

    async def create_auto_fix_pr(
        self,
        repo: str,
        base_branch: str,
        fixes: list[AutoFixFile],
        title: str = "",
        body: str = "",
        labels: list[str] | None = None,
    ) -> AutoFixResult:
        """Create a pull request with one or more file fixes.

        Args:
            repo: Repository in "owner/repo" format.
            base_branch: Branch to base the fix on (e.g. "main").
            fixes: List of file changes to commit.
            title: PR title (auto-generated if empty).
            body: PR body (auto-generated if empty).
            labels: PR labels (defaults to security/auto-fix/guardnous).

        Returns:
            AutoFixResult with PR URL and metadata.
        """
        if not fixes:
            return AutoFixResult(success=False, error="No fixes provided")

        branch_name = f"guardnous/auto-fix-{_short_hash(fixes)}"
        pr_labels = labels or ["security", "auto-fix", "guardnous"]
        pr_title = title or f"🔒 GuardNous Auto-Fix: {len(fixes)} security remediation(s)"
        pr_body = body or _build_pr_body(fixes)

        try:
            # Create feature branch
            await self.vcs.create_branch(repo, branch_name, from_branch=base_branch)

            # Commit each fix
            for fix in fixes:
                file_sha = await self.vcs.get_file_sha(repo, fix.path, branch_name)
                commit_msg = fix.message or f"fix: security remediation in {fix.path}"
                await self.vcs.create_or_update_file(
                    repo=repo,
                    path=fix.path,
                    content=fix.content,
                    message=commit_msg,
                    branch=branch_name,
                    sha=file_sha,
                    author=self.bot_author,
                )

            # Open PR
            pr = await self.vcs.create_pull_request(
                repo=repo,
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=base_branch,
                labels=pr_labels,
            )

            return AutoFixResult(
                success=True,
                pr_url=pr.get("html_url"),
                pr_number=pr.get("number"),
                branch_name=branch_name,
            )
        except Exception as exc:
            logger.exception("Failed to create auto-fix PR for %s", repo)
            return AutoFixResult(
                success=False,
                branch_name=branch_name,
                error=str(exc),
            )


# ── Helpers ────────────────────────────────────────────────────────────


async def _resolve_bot_author(
    db: AsyncSession, organization_id: int
) -> dict[str, str]:
    """Resolve bot git identity from service account or use defaults."""
    result = await db.execute(
        select(ServiceAccount).where(
            ServiceAccount.organization_id == organization_id,
            ServiceAccount.is_active == True,  # noqa: E712
        )
    )
    sa = result.scalars().first()
    if sa:
        return {"name": sa.bot_username, "email": sa.bot_email}
    return {"name": BOT_USERNAME, "email": BOT_EMAIL}


def _short_hash(fixes: list[AutoFixFile]) -> str:
    """Generate a short hash for branch naming."""
    import hashlib

    content = "|".join(f.path for f in fixes)
    return hashlib.sha1(content.encode(), usedforsecurity=False).hexdigest()[:8]


def _build_pr_body(fixes: list[AutoFixFile]) -> str:
    """Build a default PR body listing the fixed files."""
    lines = [
        "## 🔒 GuardNous Automated Security Fix",
        "",
        "This PR was automatically created by **guardnous-bot** to remediate "
        "security findings detected during scanning.",
        "",
        "### Files Modified",
        "",
    ]
    for fix in fixes:
        lines.append(f"- `{fix.path}`")
    lines.extend([
        "",
        "### Review Checklist",
        "- [ ] Changes are correct and don't break functionality",
        "- [ ] Tests pass with the applied fixes",
        "- [ ] No new security issues introduced",
        "",
        "---",
        "*🤖 Automated by [GuardNous](https://guardnous.com) — "
        "AI Security Intelligence Platform*",
    ])
    return "\n".join(lines)

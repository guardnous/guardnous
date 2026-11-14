"""Agentic PR creation pipeline — end-to-end remediation workflow.

Pipeline: Finding → Fetch file → Generate fix → Create branch → Commit → Open PR

This is the "hands" of the agentic system. The autofix engine (the "brain")
generates the code patch; this module executes it against the VCS provider
to create an actual pull request.

Supports GitHub (primary). GitLab, Bitbucket, and Azure DevOps use the same
interface pattern and can be added via the VCS factory.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.agents.autofix import CodeFix, generate_fix
from app.services.agents.llm import LLMSettings
from app.services.vcs.github import GitHubService

logger = logging.getLogger(__name__)


async def get_active_bot_author(db: AsyncSession, organization_id: int) -> dict | None:
    """Resolve the org's active service-account git identity for PR attribution.

    Returns {"name": ..., "email": ...} from the most recently created active
    service account, or None if the org has none (commits then fall back to the
    token owner's identity).
    """
    from sqlalchemy import select
    from app.models.service_account import ServiceAccount

    result = await db.execute(
        select(ServiceAccount)
        .where(
            ServiceAccount.organization_id == organization_id,
            ServiceAccount.is_active == True,  # noqa: E712
        )
        .order_by(ServiceAccount.created_at.desc())
    )
    sa = result.scalars().first()
    if not sa:
        return None
    return {"name": sa.bot_username, "email": sa.bot_email}


@dataclass
class RemediationResult:
    """Result of an auto-remediation attempt."""

    finding_id: int
    status: str  # "success" | "failed" | "skipped" | "needs_review"
    pr_url: str | None = None
    pr_number: int | None = None
    branch_name: str | None = None
    error: str | None = None
    fix: CodeFix | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "finding_id": self.finding_id,
            "status": self.status,
            "pr_url": self.pr_url,
            "pr_number": self.pr_number,
            "branch_name": self.branch_name,
            "error": self.error,
        }
        if self.fix:
            d["fix"] = self.fix.to_dict()
        if self.metadata:
            d["metadata"] = self.metadata
        return d


def _sanitize_branch_name(s: str) -> str:
    """Convert a string to a valid git branch name."""
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9\-/]", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    return s.strip("-")[:80]


class RemediationPipeline:
    """Orchestrates the full auto-remediation cycle.

    Usage:
        pipeline = RemediationPipeline(github_token="...", repo="owner/repo")
        result = await pipeline.remediate_finding(finding_dict)
    """

    def __init__(
        self,
        github_token: str,
        repo: str,
        llm_settings: LLMSettings | None = None,
        base_branch: str | None = None,
        dry_run: bool = False,
        labels: list[str] | None = None,
        bot_author: dict | None = None,
    ):
        self.vcs = GitHubService(access_token=github_token)
        self.repo = repo
        self.llm_settings = llm_settings
        self.base_branch = base_branch
        self.dry_run = dry_run
        self.labels = labels or ["security", "auto-fix", "guardnous"]
        # {"name": ..., "email": ...} — attributes commits to a bot/service account
        self.bot_author = bot_author

    async def remediate_finding(self, finding: dict) -> RemediationResult:
        """Full pipeline: fetch file → generate fix → create branch → commit → open PR."""
        finding_id = finding.get("id", 0)
        file_path = finding.get("file_path")

        if not file_path:
            return RemediationResult(
                finding_id=finding_id,
                status="skipped",
                error="No file_path on finding — cannot generate fix",
            )

        # Step 1: Fetch the file content from the repo
        try:
            base = self.base_branch or await self.vcs.get_default_branch(self.repo)
            file_content = await self.vcs.get_file_content(self.repo, file_path, ref=base)
            if file_content is None:
                return RemediationResult(
                    finding_id=finding_id,
                    status="skipped",
                    error=f"File {file_path} not found in {self.repo}@{base}",
                )
        except Exception as exc:
            logger.exception("Failed to fetch file %s from %s", file_path, self.repo)
            return RemediationResult(
                finding_id=finding_id,
                status="failed",
                error=f"VCS fetch failed: {exc}",
            )

        # Step 2: Generate the code fix
        fix = await generate_fix(finding, file_content, self.llm_settings)
        if not fix:
            return RemediationResult(
                finding_id=finding_id,
                status="skipped",
                error="No auto-fix available for this finding type",
            )

        # Dry-run: return the fix without creating a PR
        if self.dry_run:
            return RemediationResult(
                finding_id=finding_id,
                status="needs_review",
                fix=fix,
                metadata={"mode": "dry_run", "confidence": fix.confidence},
            )

        # Step 3: Create branch → commit fix → open PR
        try:
            branch_name = _sanitize_branch_name(
                f"guardnous/fix-{finding.get('rule_id', 'sec')}-{finding_id}"
            )
            await self.vcs.create_branch(self.repo, branch_name, from_branch=base)

            # Get existing file SHA for update
            file_sha = await self.vcs.get_file_sha(self.repo, file_path, branch_name)
            await self.vcs.create_or_update_file(
                repo=self.repo,
                path=file_path,
                content=fix.fixed_content,
                message=fix.commit_message,
                branch=branch_name,
                sha=file_sha,
                author=self.bot_author,
            )

            # Create the PR
            pr = await self.vcs.create_pull_request(
                repo=self.repo,
                title=fix.pr_title,
                body=fix.pr_body,
                head=branch_name,
                base=base,
                labels=self.labels,
            )

            return RemediationResult(
                finding_id=finding_id,
                status="success",
                pr_url=pr.get("html_url"),
                pr_number=pr.get("number"),
                branch_name=branch_name,
                fix=fix,
                metadata={
                    "confidence": fix.confidence,
                    "breaking_change": fix.breaking_change,
                    "fix_type": fix.fix_type,
                },
            )
        except Exception as exc:
            logger.exception("Failed to create remediation PR for finding %s", finding_id)
            return RemediationResult(
                finding_id=finding_id,
                status="failed",
                error=f"PR creation failed: {exc}",
                fix=fix,
            )

    async def remediate_batch(
        self, findings: list[dict], max_prs: int = 10
    ) -> list[RemediationResult]:
        """Remediate multiple findings, grouping by file to avoid PR conflicts.

        Creates one PR per file (with potentially multiple fixes chained).
        """

        # Group findings by file
        by_file: dict[str, list[dict]] = {}
        for f in findings:
            fp = f.get("file_path", "")
            if fp:
                by_file.setdefault(fp, []).append(f)

        results: list[RemediationResult] = []
        pr_count = 0

        for file_path, file_findings in by_file.items():
            if pr_count >= max_prs:
                for f in file_findings:
                    results.append(RemediationResult(
                        finding_id=f.get("id", 0),
                        status="skipped",
                        error=f"Max PR limit ({max_prs}) reached",
                    ))
                continue

            # For multi-finding files, remediate the highest severity first
            sorted_findings = sorted(
                file_findings,
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    x.get("severity", "MEDIUM"), 2
                ),
            )

            result = await self.remediate_finding(sorted_findings[0])
            results.append(result)
            if result.status == "success":
                pr_count += 1

            # Mark remaining findings in same file as grouped
            for f in sorted_findings[1:]:
                results.append(RemediationResult(
                    finding_id=f.get("id", 0),
                    status="skipped",
                    error=f"Grouped with finding {sorted_findings[0].get('id')} in same file",
                    metadata={"grouped_pr": result.pr_url},
                ))

        return results

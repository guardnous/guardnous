"""Azure DevOps VCS integration: PAT auth, repos, file ops, commit status, PR threads, webhooks."""

import base64
import hashlib
import hmac
import logging
from typing import Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

IAC_EXTENSIONS = {
    ".tf", ".tfvars", ".json", ".yaml", ".yml",
    ".bicep", ".template", ".dockerfile",
}


class AzureDevOpsService:
    """Azure DevOps REST API client using Personal Access Token.

    Args:
        organization: Azure DevOps organization name.
        pat: Personal Access Token.
        project: Default project name (optional — can be per-call).
    """

    def __init__(self, organization: str, pat: str, project: Optional[str] = None):
        self.organization = organization
        self.pat = pat
        self.project = project
        self.base_url = f"https://dev.azure.com/{quote(organization)}"

    def _headers(self) -> dict:
        b64 = base64.b64encode(f":{self.pat}".encode()).decode()
        return {
            "Authorization": f"Basic {b64}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _api_version(self, version: str = "7.1") -> dict:
        return {"api-version": version}

    # ── User & Repos ─────────────────────────────────────────────────────

    async def get_user(self) -> dict:
        """Get the authenticated user's profile."""
        url = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=self._headers(), params=self._api_version())
            resp.raise_for_status()
            return resp.json()

    async def list_projects(self) -> list[dict]:
        """List all projects in the organization."""
        url = f"{self.base_url}/_apis/projects"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=self._headers(), params=self._api_version())
            resp.raise_for_status()
            data = resp.json()
            return [
                {"id": p["id"], "name": p["name"], "description": p.get("description", "")}
                for p in data.get("value", [])
            ]

    async def list_repos(self, project: Optional[str] = None) -> list[dict]:
        """List Git repositories in a project.

        Args:
            project: Project name. Falls back to self.project.

        Returns:
            List of normalized repo dicts matching RepositoryInfo schema.
        """
        proj = project or self.project
        if not proj:
            raise ValueError("project is required — pass it or set it on the service")

        url = f"{self.base_url}/{quote(proj)}/_apis/git/repositories"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=self._headers(), params=self._api_version())
            resp.raise_for_status()
            data = resp.json()

        repos = []
        for r in data.get("value", []):
            default_branch = r.get("defaultBranch", "refs/heads/main")
            if default_branch.startswith("refs/heads/"):
                default_branch = default_branch[len("refs/heads/"):]
            repos.append({
                "full_name": f"{proj}/{r['name']}",
                "name": r["name"],
                "private": True,  # ADO repos are always org-scoped
                "default_branch": default_branch,
                "language": None,
                "html_url": r.get("webUrl", ""),
                "description": r.get("project", {}).get("description", ""),
                "repo_id": r["id"],
            })
        return repos

    async def validate_token(self) -> bool:
        """Validate PAT by listing projects."""
        try:
            projects = await self.list_projects()
            return len(projects) >= 0  # Even 0 projects is valid
        except (httpx.HTTPStatusError, httpx.RequestError):
            return False

    # ── File Operations ──────────────────────────────────────────────────

    async def list_iac_files(
        self,
        repo_full_name: str,
        branch: str = "main",
        path: str = "/",
    ) -> list[dict]:
        """List IaC files in an Azure DevOps Git repository.

        Args:
            repo_full_name: 'project/repo-name' format.
            branch: Branch name.
            path: Directory path to list.

        Returns:
            List of dicts with 'path', 'type', and 'size' keys.
        """
        parts = repo_full_name.split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Expected 'project/repo' format, got: {repo_full_name}")
        proj, repo_name = parts

        url = (
            f"{self.base_url}/{quote(proj)}/_apis/git/repositories"
            f"/{quote(repo_name)}/items"
        )
        params = {
            **self._api_version(),
            "recursionLevel": "Full",
            "scopePath": path,
            "versionDescriptor.version": branch,
            "versionDescriptor.versionType": "branch",
        }

        iac_files: list[dict] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("value", []):
                if item.get("isFolder", False):
                    continue
                item_path = item.get("path", "")
                ext = "." + item_path.rsplit(".", 1)[-1] if "." in item_path else ""
                if ext.lower() in IAC_EXTENSIONS:
                    iac_files.append({
                        "path": item_path.lstrip("/"),
                        "type": "file",
                        "size": item.get("contentMetadata", {}).get("size", 0),
                    })
        return iac_files

    async def get_file_content(
        self, repo_full_name: str, file_path: str, ref: str = "main"
    ) -> Optional[str]:
        """Get raw file content from an Azure DevOps Git repository.

        Args:
            repo_full_name: 'project/repo-name' format.
            file_path: Path to file in the repo.
            ref: Branch, tag, or commit SHA.

        Returns:
            File content as string, or None if not found.
        """
        parts = repo_full_name.split("/", 1)
        if len(parts) != 2:
            return None
        proj, repo_name = parts

        url = (
            f"{self.base_url}/{quote(proj)}/_apis/git/repositories"
            f"/{quote(repo_name)}/items"
        )
        params = {
            **self._api_version(),
            "path": file_path if file_path.startswith("/") else f"/{file_path}",
            "versionDescriptor.version": ref,
            "versionDescriptor.versionType": "branch",
            "includeContent": "true",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                url,
                headers={**self._headers(), "Accept": "application/octet-stream"},
                params=params,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.text

    # ── Commit Status (Build Status) ─────────────────────────────────────

    async def update_commit_status(
        self,
        repo_full_name: str,
        commit_sha: str,
        state: str,
        description: str = "",
        target_url: str = "",
        context: str = "GuardNous",
    ) -> dict:
        """Create a commit status on a specific commit.

        ADO states: succeeded, failed, pending, notSet, notApplicable, error.
        """
        state_map = {
            "success": "succeeded",
            "failure": "failed",
            "error": "error",
            "pending": "pending",
        }
        ado_state = state_map.get(state.lower(), state.lower())

        parts = repo_full_name.split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Expected 'project/repo' format, got: {repo_full_name}")
        proj, repo_name = parts

        url = (
            f"{self.base_url}/{quote(proj)}/_apis/git/repositories"
            f"/{quote(repo_name)}/commits/{commit_sha}/statuses"
        )

        payload = {
            "state": ado_state,
            "description": description[:255] if description else "GuardNous scan",
            "context": {
                "name": context,
                "genre": "security",
            },
        }
        if target_url:
            payload["targetUrl"] = target_url

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url, json=payload, headers=self._headers(), params=self._api_version()
            )
            resp.raise_for_status()
            return resp.json()

    # ── PR Comments (Threads) ────────────────────────────────────────────

    async def post_pr_comment(
        self, repo_full_name: str, pr_id: int, body: str
    ) -> dict:
        """Post a comment thread on an Azure DevOps pull request.

        Args:
            repo_full_name: 'project/repo-name' format.
            pr_id: Pull request ID.
            body: Comment body in markdown.

        Returns:
            Created thread dict.
        """
        parts = repo_full_name.split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Expected 'project/repo' format, got: {repo_full_name}")
        proj, repo_name = parts

        url = (
            f"{self.base_url}/{quote(proj)}/_apis/git/repositories"
            f"/{quote(repo_name)}/pullRequests/{pr_id}/threads"
        )

        payload = {
            "comments": [
                {
                    "parentCommentId": 0,
                    "content": body,
                    "commentType": 1,  # text
                }
            ],
            "status": 1,  # active
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url, json=payload, headers=self._headers(), params=self._api_version()
            )
            resp.raise_for_status()
            return resp.json()

    # ── Webhooks (Service Hooks) ─────────────────────────────────────────

    async def create_webhook(
        self,
        project: str,
        webhook_url: str,
        event_type: str = "git.push",
        secret: Optional[str] = None,
    ) -> dict:
        """Create a service hook subscription in Azure DevOps.

        Args:
            project: Project name.
            webhook_url: URL to receive webhook payloads.
            event_type: Event type (git.push, git.pullrequest.created, etc.).
            secret: Optional shared secret for HMAC verification.

        Returns:
            Created subscription dict.
        """
        url = f"{self.base_url}/_apis/hooks/subscriptions"

        consumer_inputs: dict = {"url": webhook_url}
        if secret:
            consumer_inputs["basicAuthPassword"] = secret

        payload = {
            "publisherId": "tfs",
            "eventType": event_type,
            "consumerId": "webHooks",
            "consumerActionId": "httpRequest",
            "publisherInputs": {
                "projectId": project,
            },
            "consumerInputs": consumer_inputs,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url, json=payload, headers=self._headers(), params=self._api_version()
            )
            resp.raise_for_status()
            return resp.json()

    async def delete_webhook(self, subscription_id: str) -> bool:
        """Delete a service hook subscription.

        Args:
            subscription_id: Subscription GUID.

        Returns:
            True if deleted successfully.
        """
        url = f"{self.base_url}/_apis/hooks/subscriptions/{subscription_id}"
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                url, headers=self._headers(), params=self._api_version()
            )
            return resp.status_code in (200, 204)

    @staticmethod
    def verify_webhook_signature(
        payload_body: bytes, signature: str, secret: str
    ) -> bool:
        """Verify Azure DevOps webhook HMAC signature.

        Azure DevOps can send a basic auth or HMAC header depending on config.
        This validates the HMAC-SHA1 approach (when a shared secret is configured).

        Args:
            payload_body: Raw request body bytes.
            signature: Signature from the request header.
            secret: Shared secret configured on the service hook.

        Returns:
            True if signature is valid.
        """
        expected = hmac.new(
            secret.encode("utf-8"),
            payload_body,
            hashlib.sha1,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

"""Bitbucket VCS integration: App Password auth, repos, file ops, commit status, PR comments, webhooks."""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

BITBUCKET_API = "https://api.bitbucket.org"
BITBUCKET_CLOUD_IPS = [
    "104.192.136.0/21",
    "185.166.140.0/22",
    "18.205.93.0/25",
    "18.234.32.128/25",
    "13.52.5.0/25",
]

IAC_EXTENSIONS = {
    ".tf", ".tfvars", ".json", ".yaml", ".yml",
    ".bicep", ".template", ".dockerfile",
}


class BitbucketService:
    """Bitbucket Cloud API client using App Password (HTTP Basic Auth).

    Args:
        username: Bitbucket username (workspace owner).
        app_password: Bitbucket App Password with appropriate scopes.
        workspace: Optional workspace slug (defaults to username).
    """

    def __init__(self, username: str, app_password: str, workspace: Optional[str] = None):
        self.username = username
        self.app_password = app_password
        self.workspace = workspace or username

    def _auth(self) -> httpx.BasicAuth:
        """Return HTTP Basic Auth credentials."""
        return httpx.BasicAuth(username=self.username, password=self.app_password)

    def _headers(self) -> dict:
        return {"Accept": "application/json"}

    # ── User & Repos ─────────────────────────────────────────────────────

    async def get_user(self) -> dict:
        """Get authenticated Bitbucket user info."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{BITBUCKET_API}/2.0/user",
                auth=self._auth(),
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def list_repos(self, pagelen: int = 100) -> list[dict]:
        """List repositories with pagination support."""
        repos: list[dict] = []
        url: Optional[str] = f"{BITBUCKET_API}/2.0/repositories/{self.workspace}"
        params = {"role": "member", "pagelen": pagelen}

        async with httpx.AsyncClient() as client:
            while url:
                resp = await client.get(url, params=params, auth=self._auth(), headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                for r in data.get("values", []):
                    repos.append({
                        "full_name": r["full_name"],
                        "name": r["name"],
                        "private": r.get("is_private", False),
                        "default_branch": (
                            r.get("mainbranch", {}).get("name", "main")
                            if r.get("mainbranch")
                            else "main"
                        ),
                        "language": r.get("language"),
                        "html_url": r.get("links", {}).get("html", {}).get("href", ""),
                        "description": r.get("description") or "",
                    })
                url = data.get("next")
                params = {}  # next URL already has params
        return repos

    async def validate_token(self) -> bool:
        """Validate the App Password by hitting the /2.0/user endpoint."""
        try:
            await self.get_user()
            return True
        except (httpx.HTTPStatusError, httpx.RequestError):
            return False

    # ── File Operations ──────────────────────────────────────────────────

    async def list_iac_files(
        self, repo_full_name: str, branch: str = "main", path: str = ""
    ) -> list[dict]:
        """List IaC files in a Bitbucket repository using the source API.

        Args:
            repo_full_name: 'workspace/repo-slug' format.
            branch: Branch or commit to list from.
            path: Directory path to list (empty for root).

        Returns:
            List of dicts with 'path', 'type', and 'size' keys.
        """
        iac_files: list[dict] = []
        dirs_to_scan = [path]

        async with httpx.AsyncClient(timeout=30.0) as client:
            while dirs_to_scan:
                current_path = dirs_to_scan.pop()
                url = f"{BITBUCKET_API}/2.0/repositories/{repo_full_name}/src/{branch}/{current_path}"
                page_url: Optional[str] = url

                while page_url:
                    resp = await client.get(page_url, auth=self._auth(), headers=self._headers())
                    if resp.status_code == 404:
                        break
                    resp.raise_for_status()
                    data = resp.json()

                    for entry in data.get("values", []):
                        entry_path = entry.get("path", "")
                        entry_type = entry.get("type", "")

                        if entry_type == "commit_directory":
                            dirs_to_scan.append(entry_path)
                        elif entry_type == "commit_file":
                            ext = "." + entry_path.rsplit(".", 1)[-1] if "." in entry_path else ""
                            if ext.lower() in IAC_EXTENSIONS:
                                iac_files.append({
                                    "path": entry_path,
                                    "type": "file",
                                    "size": entry.get("size", 0),
                                })
                    page_url = data.get("next")
        return iac_files

    async def get_file_content(
        self, repo_full_name: str, file_path: str, ref: str = "main"
    ) -> Optional[str]:
        """Get raw file content from a Bitbucket repository.

        Args:
            repo_full_name: 'workspace/repo-slug' format.
            file_path: Path to file in the repo.
            ref: Branch, tag, or commit SHA.

        Returns:
            File content as string, or None if not found.
        """
        url = f"{BITBUCKET_API}/2.0/repositories/{repo_full_name}/src/{ref}/{file_path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, auth=self._auth())
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.text

    # ── Commit Status ────────────────────────────────────────────────────

    async def update_commit_status(
        self,
        repo_full_name: str,
        commit_sha: str,
        state: str,
        description: str = "",
        url: str = "",
        key: str = "guardnous",
    ) -> dict:
        """Update build status on a commit.

        Bitbucket states: SUCCESSFUL, FAILED, INPROGRESS, STOPPED.
        """
        state_map = {
            "success": "SUCCESSFUL",
            "failure": "FAILED",
            "error": "FAILED",
            "pending": "INPROGRESS",
        }
        bb_state = state_map.get(state.lower(), state.upper())

        api_url = (
            f"{BITBUCKET_API}/2.0/repositories/{repo_full_name}"
            f"/commit/{commit_sha}/statuses/build"
        )
        payload = {
            "state": bb_state,
            "key": key,
            "name": "GuardNous Scan",
            "description": description[:255] if description else "",
        }
        if url:
            payload["url"] = url

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                api_url,
                json=payload,
                auth=self._auth(),
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # ── PR Comments ──────────────────────────────────────────────────────

    async def post_pr_comment(
        self, repo_full_name: str, pr_id: int, body: str
    ) -> dict:
        """Post a comment on a Bitbucket pull request.

        Args:
            repo_full_name: 'workspace/repo-slug' format.
            pr_id: Pull request ID (integer).
            body: Comment body in markdown.

        Returns:
            API response dict.
        """
        url = (
            f"{BITBUCKET_API}/2.0/repositories/{repo_full_name}"
            f"/pullrequests/{pr_id}/comments"
        )
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json={"content": {"raw": body}},
                auth=self._auth(),
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # ── Webhooks ─────────────────────────────────────────────────────────

    async def create_webhook(
        self,
        repo_full_name: str,
        webhook_url: str,
        events: Optional[list[str]] = None,
        description: str = "GuardNous",
    ) -> dict:
        """Create a webhook on a Bitbucket repository.

        Args:
            repo_full_name: 'workspace/repo-slug' format.
            webhook_url: URL to receive webhook payloads.
            events: List of event types. Default: repo:push, pullrequest:created, pullrequest:updated.
            description: Human-readable hook name.

        Returns:
            Created webhook dict with 'uuid' key.
        """
        if events is None:
            events = ["repo:push", "pullrequest:created", "pullrequest:updated"]

        url = f"{BITBUCKET_API}/2.0/repositories/{repo_full_name}/hooks"
        payload = {
            "description": description,
            "url": webhook_url,
            "active": True,
            "events": events,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json=payload,
                auth=self._auth(),
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def delete_webhook(self, repo_full_name: str, hook_uuid: str) -> bool:
        """Delete a webhook from a Bitbucket repository.

        Args:
            repo_full_name: 'workspace/repo-slug'.
            hook_uuid: UUID of the webhook (with or without braces).

        Returns:
            True if deleted successfully.
        """
        clean_uuid = hook_uuid.strip("{}")
        url = (
            f"{BITBUCKET_API}/2.0/repositories/{repo_full_name}"
            f"/hooks/{{{clean_uuid}}}"
        )
        async with httpx.AsyncClient() as client:
            resp = await client.delete(url, auth=self._auth())
            return resp.status_code in (200, 204)

    @staticmethod
    def verify_webhook_ip(request_ip: str) -> bool:
        """Verify the webhook request comes from Bitbucket Cloud IP ranges.

        Bitbucket Cloud does not support webhook secrets — IP allowlisting
        is the recommended verification method.

        Args:
            request_ip: Source IP of the incoming webhook request.

        Returns:
            True if the IP is in Bitbucket's published ranges.
        """
        import ipaddress

        try:
            ip = ipaddress.ip_address(request_ip)
        except ValueError:
            return False

        for cidr in BITBUCKET_CLOUD_IPS:
            if ip in ipaddress.ip_network(cidr):
                return True
        return False

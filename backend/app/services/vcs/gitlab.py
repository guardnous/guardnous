"""GitLab VCS integration: PAT-based auth, repos, file content, MR comments, webhooks."""
import base64
import hmac
from urllib.parse import quote as url_quote

import httpx

from app.core.encryption import encrypt_token, decrypt_token

DEFAULT_GITLAB_API = "https://gitlab.com/api/v4"


class GitLabService:
    """GitLab API client using Personal Access Token authentication.

    Supports both gitlab.com and self-hosted instances.

    Args:
        token: GitLab Personal Access Token with api scope.
        base_url: GitLab API base URL. Defaults to https://gitlab.com/api/v4.
    """

    def __init__(self, token: str, base_url: str = DEFAULT_GITLAB_API):
        self.token = token
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict:
        return {
            "PRIVATE-TOKEN": self.token,
            "Accept": "application/json",
        }

    # ─── User & repos ─────────────────────────────────────────────────────

    async def get_user(self) -> dict:
        """Get authenticated GitLab user info."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/user", headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    async def list_repos(self, per_page: int = 100) -> list[dict]:
        """List projects accessible by the authenticated user."""
        async with httpx.AsyncClient() as client:
            repos: list[dict] = []
            page = 1
            while True:
                resp = await client.get(
                    f"{self.base_url}/projects",
                    params={
                        "membership": "true",
                        "per_page": per_page,
                        "page": page,
                        "order_by": "last_activity_at",
                    },
                    headers=self._headers(),
                )
                resp.raise_for_status()
                projects = resp.json()
                if not projects:
                    break
                for p in projects:
                    repos.append({
                        "full_name": p["path_with_namespace"],
                        "name": p["name"],
                        "private": p.get("visibility") == "private",
                        "default_branch": p.get("default_branch", "main"),
                        "language": None,
                        "html_url": p.get("web_url", ""),
                        "description": p.get("description") or "",
                    })
                if len(projects) < per_page:
                    break
                page += 1
            return repos

    async def validate_token(self) -> bool:
        try:
            await self.get_user()
            return True
        except (httpx.HTTPStatusError, httpx.RequestError):
            return False

    # ─── File operations ──────────────────────────────────────────────────

    async def list_iac_files(self, project_path: str, ref: str = "main") -> list[dict]:
        """Find all IaC files in a project using the repository tree API.

        Args:
            project_path: URL-encoded project path (e.g. ``group/project``).
            ref: Branch name or commit SHA.
        """
        encoded = url_quote(project_path, safe="")
        iac_extensions = (".tf", ".yaml", ".yml", ".json", ".bicep")
        files: list[dict] = []
        page = 1

        async with httpx.AsyncClient() as client:
            while True:
                resp = await client.get(
                    f"{self.base_url}/projects/{encoded}/repository/tree",
                    params={"ref": ref, "recursive": "true", "per_page": 100, "page": page},
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    break
                items = resp.json()
                if not items:
                    break
                for item in items:
                    if item.get("type") == "blob" and item["path"].endswith(iac_extensions):
                        files.append({"path": item["path"], "sha": item.get("id", "")})
                if len(items) < 100:
                    break
                page += 1
        return files

    async def get_file_content(self, project_path: str, file_path: str, ref: str = "main") -> str | None:
        """Get raw file content from a project.

        Args:
            project_path: Project path (e.g. ``group/project``).
            file_path: Path to the file within the repo.
            ref: Branch or commit SHA.
        """
        encoded_proj = url_quote(project_path, safe="")
        encoded_file = url_quote(file_path, safe="")
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/projects/{encoded_proj}/repository/files/{encoded_file}",
                params={"ref": ref},
                headers=self._headers(),
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8")
            return data.get("content")

    # ─── Commit status & MR comments ──────────────────────────────────────

    async def update_commit_status(
        self, project_path: str, sha: str, state: str, description: str, target_url: str = ""
    ) -> dict:
        """Set commit build status (pending, running, success, failed, canceled).

        GitLab uses different state names than GitHub so we map them.
        """
        state_map = {"pending": "pending", "success": "success", "failure": "failed", "error": "failed"}
        gl_state = state_map.get(state, state)

        encoded = url_quote(project_path, safe="")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/projects/{encoded}/statuses/{sha}",
                json={
                    "state": gl_state,
                    "description": description[:140],
                    "target_url": target_url,
                    "name": "GuardNous",
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def post_mr_comment(self, project_path: str, mr_iid: int, body: str) -> dict:
        """Post a note (comment) on a merge request."""
        encoded = url_quote(project_path, safe="")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/projects/{encoded}/merge_requests/{mr_iid}/notes",
                json={"body": body},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # ─── Webhooks ─────────────────────────────────────────────────────────

    async def create_webhook(self, project_path: str, webhook_url: str, secret: str) -> dict:
        """Create a project webhook for push and MR events."""
        encoded = url_quote(project_path, safe="")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/projects/{encoded}/hooks",
                json={
                    "url": webhook_url,
                    "push_events": True,
                    "merge_requests_events": True,
                    "token": secret,
                    "enable_ssl_verification": True,
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def delete_webhook(self, project_path: str, hook_id: int) -> None:
        encoded = url_quote(project_path, safe="")
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.base_url}/projects/{encoded}/hooks/{hook_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()

    @staticmethod
    def verify_webhook_signature(payload: bytes, token_header: str, secret: str) -> bool:
        """Verify GitLab webhook token (X-Gitlab-Token header must match the secret)."""
        return hmac.compare_digest(token_header, secret)

    @staticmethod
    def encrypt_access_token(token: str) -> str:
        return encrypt_token(token)

    @staticmethod
    def decrypt_access_token(encrypted: str) -> str:
        return decrypt_token(encrypted)

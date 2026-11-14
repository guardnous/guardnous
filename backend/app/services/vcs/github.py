"""GitHub VCS integration: GitHub App installation flow, OAuth, repos, file content, PR comments, webhooks."""
import hashlib
import hmac
import time
import httpx
from jose import jwt as jose_jwt
from app.core.config import settings
from app.core.encryption import encrypt_token, decrypt_token


GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"


class GitHubService:
    def __init__(self, access_token: str | None = None):
        self.access_token = access_token

    # ─── GitHub App JWT ────────────────────────────────────────────────────

    @staticmethod
    def _generate_app_jwt() -> str:
        """Generate a short-lived JWT for GitHub App authentication.

        Uses the App's private key to sign a JWT that identifies us to GitHub.
        This JWT is then exchanged for an installation access token.
        """
        if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
            raise ValueError("GitHub App credentials not configured (GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY required)")

        private_key = settings.GITHUB_APP_PRIVATE_KEY
        # Support both inline PEM (\\n-escaped) and file path
        if private_key.startswith("/") or private_key.startswith("file://"):
            path = private_key.removeprefix("file://")
            with open(path, "r") as f:
                private_key = f.read()
        else:
            private_key = private_key.replace("\\n", "\n")

        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued at (60s clock skew buffer)
            "exp": now + (10 * 60),  # 10-minute max lifetime
            "iss": settings.GITHUB_APP_ID,
        }
        return jose_jwt.encode(payload, private_key, algorithm="RS256")

    @staticmethod
    def get_app_install_url(state: str = "") -> str:
        """Get the GitHub App installation URL.

        This redirects the user to GitHub to install/configure the App
        on their org or personal account — like Claude Code does it.
        """
        slug = settings.GITHUB_APP_SLUG or "guardnous"
        base = f"https://github.com/apps/{slug}/installations/new"
        if state:
            return f"{base}?state={state}"
        return base

    async def get_app_installation_for_setup(self, installation_id: int) -> dict:
        """Get installation details after a user completes GitHub App setup.

        Called during the callback after a user installs the app or
        modifies its configuration.
        """
        app_jwt = self._generate_app_jwt()
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/app/installations/{installation_id}",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def create_installation_token(self, installation_id: int) -> dict:
        """Create an installation access token for API calls.

        This is the enterprise-grade approach — tokens are short-lived (1h),
        scoped to the installation's repositories, and never stored long-term.
        """
        app_jwt = self._generate_app_jwt()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_app_installations(self) -> list[dict]:
        """List all installations of the GitHub App."""
        app_jwt = self._generate_app_jwt()
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/app/installations",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def get_installation_repos(self, installation_id: int) -> list[dict]:
        """List repositories accessible to an installation."""
        token_data = await self.create_installation_token(installation_id)
        access_token = token_data["token"]
        async with httpx.AsyncClient() as client:
            repos = []
            page = 1
            while True:
                resp = await client.get(
                    f"{GITHUB_API}/installation/repositories",
                    params={"per_page": 100, "page": page},
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                for r in data.get("repositories", []):
                    repos.append({
                        "full_name": r["full_name"],
                        "name": r["name"],
                        "private": r["private"],
                        "default_branch": r.get("default_branch", "main"),
                        "language": r.get("language"),
                        "html_url": r["html_url"],
                        "description": r.get("description", ""),
                    })
                if len(data.get("repositories", [])) < 100:
                    break
                page += 1
            return repos

    # ─── Legacy OAuth (kept for backward compat) ──────────────────────────

    def get_oauth_url(self, state: str = "") -> str:
        """Generate GitHub OAuth authorization URL."""
        from urllib.parse import urlencode

        params = urlencode({
            "client_id": settings.GITHUB_CLIENT_ID,
            "redirect_uri": settings.GITHUB_CALLBACK_URL,
            "scope": "repo,read:org,write:repo_hook",
            "state": state,
        })
        return f"{GITHUB_AUTH_URL}?{params}"

    async def exchange_code(self, code: str) -> dict:
        """Exchange OAuth code for access token."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.GITHUB_CALLBACK_URL,
                },
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                raise ValueError(f"GitHub OAuth error: {data['error_description']}")
            return data

    # ─── Authenticated API calls ──────────────────────────────────────────

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_user(self) -> dict:
        """Get authenticated GitHub user info."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{GITHUB_API}/user", headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    async def list_repos(self, page: int = 1, per_page: int = 100) -> list[dict]:
        """List repositories accessible by the authenticated user."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/user/repos",
                params={
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": per_page,
                    "page": page,
                    "type": "all",
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            repos = resp.json()
            return [
                {
                    "full_name": r["full_name"],
                    "name": r["name"],
                    "private": r["private"],
                    "default_branch": r["default_branch"],
                    "language": r.get("language"),
                    "html_url": r["html_url"],
                    "description": r.get("description", ""),
                }
                for r in repos
            ]

    async def get_file_content(self, repo: str, path: str, ref: str = "main") -> str | None:
        """Get file content from a repository."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo}/contents/{path}",
                params={"ref": ref},
                headers=self._headers(),
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            if data.get("encoding") == "base64":
                import base64
                return base64.b64decode(data["content"]).decode("utf-8")
            return data.get("content")

    async def list_iac_files(self, repo: str, ref: str = "main") -> list[dict]:
        """Find all IaC files in a repository using the Git tree API."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo}/git/trees/{ref}",
                params={"recursive": "1"},
                headers=self._headers(),
            )
            if resp.status_code != 200:
                return []
            tree = resp.json().get("tree", [])
            iac_extensions = (".tf", ".yaml", ".yml", ".json", ".bicep")
            return [
                {"path": item["path"], "sha": item["sha"]}
                for item in tree
                if item["type"] == "blob" and item["path"].endswith(iac_extensions)
            ]

    async def create_webhook(self, repo: str, webhook_url: str, secret: str) -> dict:
        """Create a webhook on a repository."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{repo}/hooks",
                json={
                    "name": "web",
                    "active": True,
                    "events": ["push", "pull_request"],
                    "config": {
                        "url": webhook_url,
                        "content_type": "json",
                        "secret": secret,
                        "insecure_ssl": "0",
                    },
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def delete_webhook(self, repo: str, hook_id: str) -> None:
        """Delete a webhook from a repository."""
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{GITHUB_API}/repos/{repo}/hooks/{hook_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()

    async def post_pr_comment(self, repo: str, pr_number: int, body: str) -> dict:
        """Post a comment on a pull request."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments",
                json={"body": body},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # ─── Write operations (agentic auto-fix) ─────────────────────────────

    async def get_default_branch(self, repo: str) -> str:
        """Get the default branch name for a repository."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json().get("default_branch", "main")

    async def get_branch_sha(self, repo: str, branch: str) -> str:
        """Get the latest commit SHA for a branch."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo}/git/ref/heads/{branch}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()["object"]["sha"]

    async def create_branch(self, repo: str, branch_name: str, from_branch: str | None = None) -> dict:
        """Create a new branch from the specified base (or default branch).

        Returns the ref object: {"ref": "refs/heads/...", "object": {"sha": "..."}}.
        """
        base = from_branch or await self.get_default_branch(repo)
        sha = await self.get_branch_sha(repo, base)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{repo}/git/refs",
                json={"ref": f"refs/heads/{branch_name}", "sha": sha},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def create_or_update_file(
        self, repo: str, path: str, content: str, message: str, branch: str,
        sha: str | None = None, author: dict | None = None,
    ) -> dict:
        """Create or update a file in a repository via the Contents API.

        If the file already exists, pass its blob SHA to update it.
        Content is base64-encoded automatically.

        Args:
            author: Optional {"name": ..., "email": ...} to attribute the commit to
                a service account / bot identity instead of the token owner.
        """
        import base64
        payload: dict = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        if author and author.get("name") and author.get("email"):
            payload["author"] = {"name": author["name"], "email": author["email"]}
            payload["committer"] = {"name": author["name"], "email": author["email"]}
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{GITHUB_API}/repos/{repo}/contents/{path}",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def get_file_sha(self, repo: str, path: str, branch: str) -> str | None:
        """Get the blob SHA of a file (needed for updates). Returns None if not found."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo}/contents/{path}",
                params={"ref": branch},
                headers=self._headers(),
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json().get("sha")

    async def create_pull_request(
        self, repo: str, title: str, body: str, head: str, base: str | None = None,
        labels: list[str] | None = None,
    ) -> dict:
        """Create a pull request.

        Args:
            repo: "owner/repo" format.
            title: PR title.
            body: PR description (markdown).
            head: Source branch name.
            base: Target branch (defaults to repo default branch).
            labels: Optional labels to apply.

        Returns:
            The PR object from GitHub API.
        """
        target = base or await self.get_default_branch(repo)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{repo}/pulls",
                json={
                    "title": title,
                    "body": body,
                    "head": head,
                    "base": target,
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            pr = resp.json()
            # Apply labels if provided
            if labels and pr.get("number"):
                await client.post(
                    f"{GITHUB_API}/repos/{repo}/issues/{pr['number']}/labels",
                    json={"labels": labels},
                    headers=self._headers(),
                )
            return pr

    async def update_commit_status(
        self, repo: str, sha: str, state: str, description: str, target_url: str = ""
    ) -> dict:
        """Set commit status (pending, success, failure, error)."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{repo}/statuses/{sha}",
                json={
                    "state": state,
                    "description": description[:140],
                    "target_url": target_url,
                    "context": "GuardNous",
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
        """Verify GitHub webhook HMAC-SHA256 signature."""
        if not signature.startswith("sha256="):
            return False
        expected = hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(f"sha256={expected}", signature)

    @staticmethod
    def encrypt_access_token(token: str) -> str:
        return encrypt_token(token)

    @staticmethod
    def decrypt_access_token(encrypted: str) -> str:
        return decrypt_token(encrypted)

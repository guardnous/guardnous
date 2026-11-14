"""Write access for fix pull requests on GitLab, Bitbucket Cloud and Azure DevOps.

Each class offers the six calls the fix flow needs, with the same names and
arguments as :class:`app.services.vcs.github.GitHubService`:

    get_default_branch, get_file_content, create_branch, get_file_sha,
    create_or_update_file, create_pull_request

``create_pull_request`` returns ``{"html_url": ..., "number": ...}`` whatever
the provider calls its pull requests.
"""

from __future__ import annotations

import base64
from typing import Optional
from urllib.parse import quote

import httpx

TIMEOUT = 30.0
PROVIDER_NAMES = {"github": "GitHub", "gitlab": "GitLab", "bitbucket": "Bitbucket", "azure_devops": "Azure DevOps"}


def _author(author: Optional[dict]) -> tuple[str, str]:
    author = author or {}
    return author.get("name") or "GuardNous", author.get("email") or "guardnous@users.noreply.local"


class GitLabFixWriter:
    """GitLab REST API v4, gitlab.com or self-managed. Token needs the ``api`` scope."""

    def __init__(self, token: str, base_url: Optional[str] = None):
        self.base_url = (base_url or "https://gitlab.com/api/v4").rstrip("/")
        self._headers = {"PRIVATE-TOKEN": token, "Accept": "application/json"}

    def _project(self, repo: str) -> str:
        return f"{self.base_url}/projects/{quote(repo, safe='')}"

    async def _request(self, method: str, url: str, **kw) -> httpx.Response:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            return await client.request(method, url, headers=self._headers, **kw)

    async def get_default_branch(self, repo: str) -> str:
        resp = await self._request("GET", self._project(repo))
        resp.raise_for_status()
        return resp.json().get("default_branch") or "main"

    async def get_file_content(self, repo: str, path: str, ref: str = "main") -> Optional[str]:
        resp = await self._request("GET", f"{self._project(repo)}/repository/files/{quote(path, safe='')}/raw", params={"ref": ref})
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.text

    async def create_branch(self, repo: str, branch_name: str, from_branch: Optional[str] = None) -> dict:
        resp = await self._request(
            "POST", f"{self._project(repo)}/repository/branches",
            params={"branch": branch_name, "ref": from_branch or await self.get_default_branch(repo)},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_file_sha(self, repo: str, path: str, branch: str) -> Optional[str]:
        return None                              # GitLab commits do not need the previous blob id

    async def create_or_update_file(self, *, repo: str, path: str, content: str, message: str, branch: str,
                                    sha: Optional[str] = None, author: Optional[dict] = None) -> dict:
        name, email = _author(author)
        resp = await self._request("POST", f"{self._project(repo)}/repository/commits", json={
            "branch": branch, "commit_message": message, "author_name": name, "author_email": email,
            "actions": [{"action": "update", "file_path": path, "content": content}],
        })
        resp.raise_for_status()
        return resp.json()

    async def create_pull_request(self, repo: str, title: str, body: str, head: str, base: Optional[str] = None,
                                  labels: Optional[list[str]] = None) -> dict:
        resp = await self._request("POST", f"{self._project(repo)}/merge_requests", json={
            "source_branch": head, "target_branch": base or await self.get_default_branch(repo),
            "title": title, "description": body, "labels": ",".join(labels or []), "remove_source_branch": True,
        })
        resp.raise_for_status()
        data = resp.json()
        return {"html_url": data.get("web_url"), "number": data.get("iid")}


class BitbucketFixWriter:
    """Bitbucket Cloud REST API 2.0 with an app password (repository write, pull request write)."""

    API = "https://api.bitbucket.org/2.0"

    def __init__(self, username: str, app_password: str):
        self._auth = httpx.BasicAuth(username=username, password=app_password)

    def _repo(self, repo: str) -> str:
        workspace, _, slug = repo.partition("/")
        return f"{self.API}/repositories/{quote(workspace, safe='')}/{quote(slug, safe='')}"

    async def _request(self, method: str, url: str, **kw) -> httpx.Response:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            return await client.request(method, url, auth=self._auth, **kw)

    async def get_default_branch(self, repo: str) -> str:
        resp = await self._request("GET", self._repo(repo))
        resp.raise_for_status()
        return (resp.json().get("mainbranch") or {}).get("name") or "main"

    async def get_file_content(self, repo: str, path: str, ref: str = "main") -> Optional[str]:
        resp = await self._request("GET", f"{self._repo(repo)}/src/{quote(ref, safe='')}/{quote(path)}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.text

    async def create_branch(self, repo: str, branch_name: str, from_branch: Optional[str] = None) -> dict:
        resp = await self._request("POST", f"{self._repo(repo)}/refs/branches", json={
            "name": branch_name, "target": {"hash": from_branch or await self.get_default_branch(repo)},
        })
        resp.raise_for_status()
        return resp.json()

    async def get_file_sha(self, repo: str, path: str, branch: str) -> Optional[str]:
        return None

    async def create_or_update_file(self, *, repo: str, path: str, content: str, message: str, branch: str,
                                    sha: Optional[str] = None, author: Optional[dict] = None) -> dict:
        name, email = _author(author)
        # The "src" endpoint takes a form: one field per file path, plus the commit fields.
        resp = await self._request("POST", f"{self._repo(repo)}/src", data={
            path: content, "message": message, "branch": branch, "author": f"{name} <{email}>",
        })
        resp.raise_for_status()
        return {"committed": True}

    async def create_pull_request(self, repo: str, title: str, body: str, head: str, base: Optional[str] = None,
                                  labels: Optional[list[str]] = None) -> dict:
        resp = await self._request("POST", f"{self._repo(repo)}/pullrequests", json={
            "title": title, "description": body, "close_source_branch": True,
            "source": {"branch": {"name": head}},
            "destination": {"branch": {"name": base or await self.get_default_branch(repo)}},
        })
        resp.raise_for_status()
        data = resp.json()
        return {"html_url": ((data.get("links") or {}).get("html") or {}).get("href"), "number": data.get("id")}


class AzureDevOpsFixWriter:
    """Azure DevOps Services REST API 7.1 with a personal access token (Code: read and write).

    ``repo`` is ``project/repository``. Azure DevOps creates a branch and its
    first commit in one "push", so :meth:`create_branch` only records where the
    branch starts and :meth:`create_or_update_file` sends the push.
    """

    VERSION = {"api-version": "7.1"}

    def __init__(self, organization: str, pat: str):
        self.organization = organization
        self.base_url = f"https://dev.azure.com/{quote(organization)}"
        token = base64.b64encode(f":{pat}".encode()).decode()
        self._headers = {"Authorization": f"Basic {token}", "Accept": "application/json", "Content-Type": "application/json"}
        self._starts: dict[tuple[str, str], str] = {}        # (repo, new branch) -> commit it starts from

    def _git(self, repo: str) -> str:
        project, _, name = repo.partition("/")
        return f"{self.base_url}/{quote(project)}/_apis/git/repositories/{quote(name)}"

    async def _request(self, method: str, url: str, **kw) -> httpx.Response:
        params = {**self.VERSION, **kw.pop("params", {})}
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            return await client.request(method, url, headers=self._headers, params=params, **kw)

    async def get_default_branch(self, repo: str) -> str:
        resp = await self._request("GET", self._git(repo))
        resp.raise_for_status()
        return (resp.json().get("defaultBranch") or "refs/heads/main").removeprefix("refs/heads/")

    async def get_file_content(self, repo: str, path: str, ref: str = "main") -> Optional[str]:
        resp = await self._request("GET", f"{self._git(repo)}/items", params={
            "path": "/" + path.lstrip("/"), "versionDescriptor.version": ref, "versionDescriptor.versionType": "branch",
            "includeContent": "true", "$format": "text",
        }, )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.text

    async def _head(self, repo: str, branch: str) -> str:
        resp = await self._request("GET", f"{self._git(repo)}/refs", params={"filter": f"heads/{branch}"})
        resp.raise_for_status()
        for ref in resp.json().get("value", []):
            if ref.get("name") == f"refs/heads/{branch}":
                return ref["objectId"]
        raise httpx.HTTPStatusError(f"branch {branch} not found", request=resp.request, response=resp)

    async def create_branch(self, repo: str, branch_name: str, from_branch: Optional[str] = None) -> dict:
        start = await self._head(repo, from_branch or await self.get_default_branch(repo))
        self._starts[(repo, branch_name)] = start
        return {"name": branch_name, "starts_at": start}

    async def get_file_sha(self, repo: str, path: str, branch: str) -> Optional[str]:
        return None

    async def create_or_update_file(self, *, repo: str, path: str, content: str, message: str, branch: str,
                                    sha: Optional[str] = None, author: Optional[dict] = None) -> dict:
        start = self._starts.get((repo, branch)) or await self._head(repo, branch)
        name, email = _author(author)
        resp = await self._request("POST", f"{self._git(repo)}/pushes", json={
            "refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": start}],
            "commits": [{
                "comment": message, "author": {"name": name, "email": email},
                "changes": [{
                    "changeType": "edit", "item": {"path": "/" + path.lstrip("/")},
                    "newContent": {"content": content, "contentType": "rawtext"},
                }],
            }],
        })
        resp.raise_for_status()
        return resp.json()

    async def create_pull_request(self, repo: str, title: str, body: str, head: str, base: Optional[str] = None,
                                  labels: Optional[list[str]] = None) -> dict:
        resp = await self._request("POST", f"{self._git(repo)}/pullrequests", json={
            "sourceRefName": f"refs/heads/{head}",
            "targetRefName": f"refs/heads/{base or await self.get_default_branch(repo)}",
            "title": title, "description": body[:4000],          # Azure DevOps limits the description
            "labels": [{"name": label} for label in labels or []],
        })
        resp.raise_for_status()
        number = resp.json().get("pullRequestId")
        project, _, name = repo.partition("/")
        return {
            "html_url": f"{self.base_url}/{quote(project)}/_git/{quote(name)}/pullrequest/{number}",
            "number": number,
        }


def writer_for(integration, token: str):
    """The client that can open a fix pull request for this repository connection."""
    kind = integration.vcs_type
    if kind == "github":
        from app.services.vcs.github import GitHubService

        return GitHubService(access_token=token)
    if kind == "gitlab":
        return GitLabFixWriter(token, integration.base_url)
    if kind == "bitbucket":
        return BitbucketFixWriter(integration.account_name or "", token)
    if kind in ("azure_devops", "azure"):
        return AzureDevOpsFixWriter(integration.account_name or "", token)
    raise ValueError(f"Fix pull requests are not supported on {kind}.")

"""Fix pull requests on GitLab, Bitbucket Cloud and Azure DevOps: the requests each provider receives."""

import json
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from app.services.vcs import fix_writers
from app.services.vcs.fix_writers import AzureDevOpsFixWriter, BitbucketFixWriter, GitLabFixWriter, writer_for

FIXED = 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n'


def _path(request: httpx.Request) -> str:
    """The path exactly as sent, so an encoded project name stays encoded."""
    return request.url.raw_path.decode().split("?")[0]


@pytest.fixture
def provider(monkeypatch):
    """Answer provider calls from a table of (method, path ending) -> JSON, and record every request."""
    calls, replies = [], {}
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        for (method, ending), reply in replies.items():
            if request.method == method and _path(request).endswith(ending):
                if isinstance(reply, int):
                    return httpx.Response(reply, json={"message": "no"})
                return httpx.Response(200, text=reply) if isinstance(reply, str) else httpx.Response(200, json=reply)
        return httpx.Response(404, json={"message": "not found"})

    monkeypatch.setattr(fix_writers.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    return SimpleNamespace(calls=calls, replies=replies)


async def _open_fix(writer, repo):
    """The same sequence of calls the fix flow makes."""
    base = await writer.get_default_branch(repo)
    original = await writer.get_file_content(repo, "main.tf", base)
    await writer.create_branch(repo, "guardnous/fix-1", base)
    sha = await writer.get_file_sha(repo, "main.tf", "guardnous/fix-1")
    await writer.create_or_update_file(
        repo=repo, path="main.tf", content=FIXED, message="fix: private bucket", branch="guardnous/fix-1", sha=sha,
        author={"name": "GuardNous", "email": "bot@example.com"},
    )
    pr = await writer.create_pull_request(repo, "fix: private bucket", "Makes the bucket private.", "guardnous/fix-1", base, ["security"])
    return original, pr


def _sent(provider, method, ending):
    return next(r for r in provider.calls if r.method == method and _path(r).endswith(ending))


async def test_gitlab_commits_to_a_new_branch_and_opens_a_merge_request(provider):
    provider.replies.update({
        ("GET", "/projects/acme%2Finfra"): {"default_branch": "trunk"},
        ("GET", "/repository/files/main.tf/raw"): "old",
        ("POST", "/repository/branches"): {"name": "guardnous/fix-1"},
        ("POST", "/repository/commits"): {"id": "abc"},
        ("POST", "/merge_requests"): {"web_url": "https://gitlab.example.com/acme/infra/-/merge_requests/7", "iid": 7},
    })

    original, pr = await _open_fix(GitLabFixWriter("tok", "https://gitlab.example.com/api/v4/"), "acme/infra")

    assert original == "old"
    assert pr == {"html_url": "https://gitlab.example.com/acme/infra/-/merge_requests/7", "number": 7}
    branch = _sent(provider, "POST", "/repository/branches")
    assert branch.url.host == "gitlab.example.com" and branch.headers["PRIVATE-TOKEN"] == "tok"
    assert dict(branch.url.params) == {"branch": "guardnous/fix-1", "ref": "trunk"}
    commit = json.loads(_sent(provider, "POST", "/repository/commits").content)
    assert commit["branch"] == "guardnous/fix-1"
    assert commit["actions"] == [{"action": "update", "file_path": "main.tf", "content": FIXED}]
    merge = json.loads(_sent(provider, "POST", "/merge_requests").content)
    assert (merge["source_branch"], merge["target_branch"], merge["labels"]) == ("guardnous/fix-1", "trunk", "security")


async def test_bitbucket_commits_to_a_new_branch_and_opens_a_pull_request(provider):
    provider.replies.update({
        ("GET", "/repositories/acme/infra"): {"mainbranch": {"name": "master"}},
        ("GET", "/src/master/main.tf"): "old",
        ("POST", "/refs/branches"): {"name": "guardnous/fix-1"},
        ("POST", "/infra/src"): {},
        ("POST", "/pullrequests"): {"id": 12, "links": {"html": {"href": "https://bitbucket.org/acme/infra/pull-requests/12"}}},
    })

    original, pr = await _open_fix(BitbucketFixWriter("acme", "app-pass"), "acme/infra")

    assert original == "old"
    assert pr == {"html_url": "https://bitbucket.org/acme/infra/pull-requests/12", "number": 12}
    assert json.loads(_sent(provider, "POST", "/refs/branches").content) == {"name": "guardnous/fix-1", "target": {"hash": "master"}}
    commit = _sent(provider, "POST", "/infra/src")
    assert commit.headers["Authorization"].startswith("Basic ")
    form = parse_qs(commit.content.decode())
    assert form["main.tf"] == [FIXED] and form["branch"] == ["guardnous/fix-1"] and form["message"] == ["fix: private bucket"]
    request = json.loads(_sent(provider, "POST", "/pullrequests").content)
    assert request["source"] == {"branch": {"name": "guardnous/fix-1"}}
    assert request["destination"] == {"branch": {"name": "master"}}


async def test_azure_devops_pushes_a_new_branch_and_opens_a_pull_request(provider):
    provider.replies.update({
        ("GET", "/repositories/infra"): {"defaultBranch": "refs/heads/main"},
        ("GET", "/items"): "old",
        ("GET", "/refs"): {"value": [{"name": "refs/heads/main-old", "objectId": "000"}, {"name": "refs/heads/main", "objectId": "a1b2"}]},
        ("POST", "/pushes"): {"pushId": 3},
        ("POST", "/pullrequests"): {"pullRequestId": 41},
    })

    original, pr = await _open_fix(AzureDevOpsFixWriter("acme", "pat"), "Platform/infra")

    assert original == "old"
    assert pr == {"html_url": "https://dev.azure.com/acme/Platform/_git/infra/pullrequest/41", "number": 41}
    assert all(r.url.params["api-version"] == "7.1" for r in provider.calls)
    push = json.loads(_sent(provider, "POST", "/pushes").content)
    assert push["refUpdates"] == [{"name": "refs/heads/guardnous/fix-1", "oldObjectId": "a1b2"}]
    change = push["commits"][0]["changes"][0]
    assert change["changeType"] == "edit" and change["item"] == {"path": "/main.tf"}
    assert change["newContent"] == {"content": FIXED, "contentType": "rawtext"}
    request = json.loads(_sent(provider, "POST", "/pullrequests").content)
    assert (request["sourceRefName"], request["targetRefName"]) == ("refs/heads/guardnous/fix-1", "refs/heads/main")
    assert request["labels"] == [{"name": "security"}]


async def test_a_missing_file_is_none_and_a_refused_write_raises(provider):
    provider.replies[("POST", "/repository/commits")] = 403
    writer = GitLabFixWriter("tok")

    assert await writer.get_file_content("acme/infra", "gone.tf", "main") is None
    with pytest.raises(httpx.HTTPStatusError):
        await writer.create_or_update_file(repo="acme/infra", path="main.tf", content=FIXED, message="m", branch="b")


def test_each_connection_gets_the_client_for_its_provider():
    def connection(kind, **kw):
        return SimpleNamespace(vcs_type=kind, base_url=kw.get("base_url"), account_name=kw.get("account_name", "acme"))

    gitlab = writer_for(connection("gitlab", base_url="https://git.corp.example/api/v4"), "t")
    assert isinstance(gitlab, GitLabFixWriter) and gitlab.base_url == "https://git.corp.example/api/v4"
    assert isinstance(writer_for(connection("bitbucket"), "t"), BitbucketFixWriter)
    assert isinstance(writer_for(connection("azure_devops"), "t"), AzureDevOpsFixWriter)
    assert type(writer_for(connection("github"), "t")).__name__ == "GitHubService"
    with pytest.raises(ValueError, match="not supported on subversion"):
        writer_for(connection("subversion"), "t")

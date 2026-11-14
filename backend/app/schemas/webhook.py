from pydantic import BaseModel


class WebhookEvent(BaseModel):
    """Generic webhook event parsed from any VCS provider."""
    event_type: str  # push, pull_request
    vcs_type: str  # github, gitlab, azure
    repository: str  # full_name e.g. "org/repo"
    branch: str
    commit_sha: str | None = None
    pr_number: int | None = None
    pr_title: str | None = None
    sender: str | None = None


class WebhookResponse(BaseModel):
    status: str = "accepted"
    scan_id: int | None = None
    message: str = "Webhook received"

from pydantic import BaseModel, Field, model_validator
from datetime import datetime
from typing import Optional


class FindingNote(BaseModel):
    author: str
    text: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    rule_id: str
    title: str
    description: Optional[str]
    severity: str
    category: str
    cloud_provider: Optional[str]
    resource_type: Optional[str]
    resource_name: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    code_snippet: Optional[str]
    remediation: Optional[str]
    cve_id: Optional[str]
    is_fixed: bool
    is_ignored: bool
    status: str = "open"
    assigned_to: Optional[str] = None
    notes: list[FindingNote] = []
    false_positive_reason: Optional[str] = None
    resolved_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None
    first_seen_at: Optional[datetime] = None
    # Computed when the response is built (app.services.sla): none, on_track, due_soon, overdue, met, missed
    sla_status: str = "none"
    sla_days_remaining: Optional[int] = None   # open findings only; negative when overdue
    created_at: datetime
    repository_url: Optional[str] = None

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def _sla(self):
        from app.services import sla

        self.sla_status = sla.status(self)
        self.sla_days_remaining = sla.days_remaining(self)
        return self


class FindingUpdate(BaseModel):
    is_fixed: Optional[bool] = None
    is_ignored: Optional[bool] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    false_positive_reason: Optional[str] = None
    sla_deadline: Optional[datetime] = None    # an explicit null removes the deadline


class FindingTriageRequest(BaseModel):
    """Mark a finding as false positive or resolved with reason."""
    status: str  # false_positive, resolved, triaged, in_progress
    reason: Optional[str] = None
    assigned_to: Optional[str] = None


class FindingNoteRequest(BaseModel):
    text: str


class FindingBulkUpdateRequest(BaseModel):
    finding_ids: list[int]
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    is_ignored: Optional[bool] = None
    is_fixed: Optional[bool] = None


class FindingBulkUpdateResponse(BaseModel):
    updated: int
    finding_ids: list[int]


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int

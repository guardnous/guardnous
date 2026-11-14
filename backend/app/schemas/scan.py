from pydantic import BaseModel, computed_field
from datetime import datetime
from typing import Optional

# Map scan_type to job ID type segment
JOB_TYPE_SEGMENTS = {
    "terraform": "SCN",
    "cloudformation": "SCN",
    "bicep": "SCN",
    "secrets": "SCN",
    "full": "SCN",
    "scan": "SCN",
    "policy": "POL",
    "audit": "AUD",
    "drift": "DRF",
    "sync": "SYN",
    "report": "RPT",
    "export": "EXP",
    "remediation": "REM",
    "discovery": "DIS",
    "repository": "SCN",
}


def format_job_id(numeric_id: int, scan_type: str) -> str:
    """Generate display job ID: GN-SCN-00004"""
    segment = JOB_TYPE_SEGMENTS.get(scan_type, "SCN")
    return f"GN-{segment}-{str(numeric_id).zfill(5)}"


class ScanCreate(BaseModel):
    scan_type: str = "terraform"  # terraform, cloudformation, bicep, secrets, full, policy
    source: str  # file content
    file_name: Optional[str] = None
    cloud_provider: Optional[str] = None  # aws, gcp, azure


class RepoScanCreate(BaseModel):
    repository_full_name: str  # e.g. "owner/repo"
    scan_types: list[str] = ["terraform", "cloudformation", "bicep"]


class ScanResponse(BaseModel):
    id: int
    organization_id: int
    scan_type: str
    status: str
    file_name: Optional[str] = None
    cloud_provider: Optional[str] = None
    risk_score: Optional[int] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    # Job tracking — 14-stage enterprise pipeline
    stage: Optional[str] = None
    progress: Optional[int] = 0
    repository_url: Optional[str] = None
    repository_name: Optional[str] = None
    account_name: Optional[str] = None
    error_message: Optional[str] = None
    files_scanned: Optional[int] = 0
    files_total: Optional[int] = 0
    report_id: Optional[int] = None
    # Enterprise stage fields
    secrets_found: Optional[int] = 0
    dependencies_analyzed: Optional[int] = 0
    policies_evaluated: Optional[int] = 0
    policies_passed: Optional[int] = 0
    policies_failed: Optional[int] = 0
    compliance_frameworks: Optional[dict] = None
    notifications_sent: Optional[bool] = False
    stage_details: Optional[dict] = None
    cancelled_by: Optional[str] = None
    timeout_seconds: Optional[int] = 3600

    @computed_field
    @property
    def job_id(self) -> str:
        """Display ID: GN-SCN-00004"""
        return format_job_id(self.id, self.scan_type)

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


class JobListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int

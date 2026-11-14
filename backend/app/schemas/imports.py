"""Schemas for universal SARIF / scan-result imports."""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


# ── Request ──────────────────────────────────────────────────────────────────


class SARIFImportRequest(BaseModel):
    """Upload a SARIF v2.1.0 JSON document for ingestion."""

    sarif: dict = Field(
        ...,
        description="Full SARIF v2.1.0 JSON object. Must contain 'version' and 'runs' keys.",
    )
    scan_label: Optional[str] = Field(
        None,
        max_length=200,
        description="Optional label for this import (e.g. 'nightly-trivy-scan').",
    )
    repository: Optional[str] = Field(
        None,
        max_length=500,
        description="Repository identifier (e.g. 'org/repo'). Helps group findings.",
    )
    commit_sha: Optional[str] = Field(
        None,
        max_length=100,
        description="Git commit SHA this scan was run against.",
    )
    branch: Optional[str] = Field(
        None,
        max_length=200,
        description="Git branch name.",
    )
    environment: Optional[str] = Field(
        None,
        max_length=100,
        description="Target environment (e.g. 'production', 'staging').",
    )
    override_tool_name: Optional[str] = Field(
        None,
        max_length=100,
        description="Force a specific tool name instead of reading from SARIF.",
    )
    tags: Optional[dict[str, str]] = Field(
        None,
        description="Arbitrary key-value tags to attach to the scan record.",
    )


# ── Response ─────────────────────────────────────────────────────────────────


class ImportFindingSummary(BaseModel):
    rule_id: str
    title: str
    severity: str
    category: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    detected_by: Optional[str] = None


class SARIFImportResponse(BaseModel):
    """Result of a SARIF import operation."""

    scan_id: int
    status: str  # "completed" | "partial" | "failed"
    message: str

    # Counters
    findings_imported: int = 0
    findings_skipped: int = 0
    runs_processed: int = 0
    tools_detected: list[str] = []

    # Severity breakdown
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    risk_score: int = 0
    sarif_version: str = ""
    errors: list[str] = []

    # Top findings preview (capped at 20 for response size)
    top_findings: list[ImportFindingSummary] = []

    # Metadata
    repository: Optional[str] = None
    commit_sha: Optional[str] = None
    imported_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ImportListItem(BaseModel):
    scan_id: int
    scan_type: str
    status: str
    findings_count: int
    tools: Optional[list[str]] = None
    repository: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ImportListResponse(BaseModel):
    items: list[ImportListItem]
    total: int
    page: int
    page_size: int

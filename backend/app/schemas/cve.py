from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class CVEResponse(BaseModel):
    id: int
    cve_id: str
    description: Optional[str]
    severity: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    affected_packages: list
    fix_versions: list
    references: list
    published_date: Optional[datetime]
    last_modified: Optional[datetime]
    source: Optional[str] = "nvd"
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False
    kev_date_added: Optional[str] = None

    model_config = {"from_attributes": True}


class CVESyncResponse(BaseModel):
    status: str
    total_stored: int
    sources: dict
    epss_enriched: int
    kev_flagged: int = 0


class CVEStatsResponse(BaseModel):
    total_cves: int
    by_severity: dict
    by_source: dict
    with_epss: int
    kev_flagged: int = 0
    last_sync: Optional[datetime] = None


class CVESearchResponse(BaseModel):
    items: list[CVEResponse]
    total: int
    page: int
    page_size: int

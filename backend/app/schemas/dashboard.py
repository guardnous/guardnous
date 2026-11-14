from typing import Optional, List, Dict, Any

from pydantic import BaseModel


class RiskScoreResponse(BaseModel):
    overall: int
    aws: int
    gcp: int
    azure: int
    trend: List[Dict[str, Any]]


class SeverityBreakdown(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class CloudBreakdown(BaseModel):
    aws: int
    gcp: int
    azure: int


class TopRisk(BaseModel):
    id: int
    title: str
    severity: str
    cloud_provider: Optional[str] = None
    resource_name: Optional[str] = None


class DashboardResponse(BaseModel):
    risk_score: RiskScoreResponse
    severity_breakdown: SeverityBreakdown
    cloud_breakdown: CloudBreakdown
    category_breakdown: Dict[str, int] = {}
    recent_scans: List[Dict[str, Any]]
    top_risks: List[TopRisk]
    total_findings: int
    total_scans: int
    passed_checks: int = 0
    failed_checks: int = 0


class DashboardSummaryResponse(BaseModel):
    total_scans: int
    total_findings: int
    open_findings: int
    fixed_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: int
    integrations_count: int
    recent_activity: List[Dict[str, Any]]

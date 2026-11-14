"""Enterprise Governance schemas."""
from pydantic import BaseModel
from datetime import datetime
from typing import Any, Optional


class FrameworkResponse(BaseModel):
    id: int
    name: str
    version: str = "latest"
    description: Optional[str] = None
    is_enabled: bool = True
    total_controls: int = 0
    passing_controls: int = 0
    failing_controls: int = 0
    not_applicable: int = 0  # controls that need manual attestation
    not_assessed: int = 0
    compliance_score: Optional[float] = None  # None until at least one control is assessed
    reference_url: Optional[str] = None
    last_assessed: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FrameworkCreate(BaseModel):
    name: str
    version: str = "latest"
    description: Optional[str] = None


class ControlResponse(BaseModel):
    id: int
    framework_id: int
    control_id: str
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    status: str = "not_assessed"
    severity: str = "medium"
    automated: bool = True
    evidence: list = []
    last_checked: Optional[datetime] = None
    remediation_notes: Optional[str] = None
    reference_url: Optional[str] = None
    finding_categories: list = []
    failed_resources: int = 0
    passed_resources: int = 0
    total_resources: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    policy_type: str
    severity: str = "medium"
    rules: Any = []
    is_enabled: bool = True
    is_enforced: bool = False
    is_builtin: bool = False
    target_repos: Optional[list] = None
    violations_count: int = 0
    last_evaluated: Optional[datetime] = None
    resources_in_scope: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    policy_type: str = "resource"
    severity: str = "medium"
    rules: Any = []
    is_enabled: bool = True
    is_enforced: bool = False
    target_repos: Optional[list] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    policy_type: Optional[str] = None
    severity: Optional[str] = None
    is_enabled: Optional[bool] = None
    is_enforced: Optional[bool] = None
    rules: Optional[Any] = None
    target_repos: Optional[list] = None


class ViolationResponse(BaseModel):
    id: int
    policy_id: int
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    cloud_provider: Optional[str] = None
    violation_details: dict = {}
    severity: str
    status: str = "open"
    accepted_by: Optional[str] = None
    accepted_at: Optional[datetime] = None
    acceptance_reason: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ExceptionResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    risk_type: Optional[str] = None
    reference_id: Optional[int] = None
    severity: str
    justification: str
    compensating_controls: Optional[str] = None
    status: str = "pending"
    requested_by: str
    approved_by: Optional[str] = None
    policy_id: Optional[int] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    resource_type: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ExceptionCreate(BaseModel):
    title: str
    description: Optional[str] = None
    risk_type: Optional[str] = None
    reference_id: Optional[int] = None
    severity: str
    justification: str
    compensating_controls: Optional[str] = None
    # Scope: which policy and/or resource the exception exempts (at least one)
    policy_id: Optional[int] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    resource_type: Optional[str] = None
    expires_at: Optional[datetime] = None


class ExceptionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    risk_type: Optional[str] = None
    severity: Optional[str] = None
    justification: Optional[str] = None
    compensating_controls: Optional[str] = None
    policy_id: Optional[int] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    resource_type: Optional[str] = None
    expires_at: Optional[datetime] = None


class GovernanceDashboardStats(BaseModel):
    frameworks_count: int = 0
    avg_compliance_score: Optional[float] = None  # None until a scan has been assessed
    total_controls: int = 0
    passing_controls: int = 0
    failing_controls: int = 0
    not_assessed_controls: int = 0
    manual_controls: int = 0
    policies_count: int = 0
    active_policies: int = 0
    total_violations: int = 0
    open_violations: int = 0
    critical_violations: int = 0
    exceptions_pending: int = 0
    exceptions_approved: int = 0
    frameworks: list = []

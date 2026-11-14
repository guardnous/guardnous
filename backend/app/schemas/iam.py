"""IAM Threat Intelligence schemas."""
from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class IdentityResponse(BaseModel):
    id: int
    cloud_provider: str
    identity_type: str
    external_id: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    last_activity: Optional[datetime] = None
    days_inactive: int = 0
    risk_score: float = 0
    risk_level: str = "info"
    risk_factors: list = []
    permissions_count: int = 0
    admin_access: bool = False
    mfa_enabled: Optional[bool] = None
    has_console_access: Optional[bool] = None
    has_programmatic_access: Optional[bool] = None
    access_keys: list = []
    credential_age_days: int = 0
    attached_policies: list = []
    group_memberships: list = []
    created_at: datetime

    class Config:
        from_attributes = True


class IdentityCreate(BaseModel):
    cloud_provider: str
    identity_type: str
    external_id: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    risk_score: float = 0
    risk_level: str = "info"
    admin_access: bool = False
    mfa_enabled: Optional[bool] = None
    permissions_count: int = 0
    attached_policies: list = []
    group_memberships: list = []


class ThreatResponse(BaseModel):
    id: int
    identity_id: int
    threat_type: str
    title: str
    description: Optional[str] = None
    severity: str
    confidence: float = 0.8
    detection_method: Optional[str] = None
    evidence: dict = {}
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: str = "open"
    remediation_steps: list = []
    auto_remediable: bool = False
    created_at: datetime
    identity: Optional[IdentityResponse] = None

    class Config:
        from_attributes = True


class AttackPathResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: str
    complexity: str = "medium"
    source_identity_id: int
    target_resource: Optional[str] = None
    path_steps: list = []
    risk_score: float = 0
    is_exploitable: bool = True
    status: str = "open"
    created_at: datetime

    class Config:
        from_attributes = True


class IAMDashboardStats(BaseModel):
    total_identities: int = 0
    active_identities: int = 0
    dormant_identities: int = 0
    service_accounts: int = 0
    admin_users: int = 0
    mfa_disabled: int = 0
    total_threats: int = 0
    critical_threats: int = 0
    high_threats: int = 0
    open_threats: int = 0
    attack_paths: int = 0
    avg_risk_score: float = 0
    by_provider: dict = {}
    by_identity_type: dict = {}
    by_risk_level: dict = {}
    credential_issues: int = 0
    excessive_permissions: int = 0


class IAMScanRequest(BaseModel):
    cloud_provider: str = "aws"
    scan_type: str = "full"


class IAMScanResultResponse(BaseModel):
    id: int
    cloud_provider: str
    scan_type: str
    status: str
    identities_scanned: int = 0
    threats_found: int = 0
    attack_paths_found: int = 0
    duration_seconds: Optional[float] = None
    summary: dict = {}
    started_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

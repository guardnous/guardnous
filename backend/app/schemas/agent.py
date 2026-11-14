from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel


class ProviderInfo(BaseModel):
    provider: str
    model: str
    supports_tools: bool
    live: bool


class AgentStatus(BaseModel):
    enabled: bool
    provider: ProviderInfo


class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[int] = None
    agent_id: Optional[str] = None  # Route to a specific agent (auto-routes if None)
    attachment_ids: list[int] = []  # files uploaded with POST /agents/chat/files


class ChatFileResponse(BaseModel):
    id: int
    kind: str                       # upload | generated
    filename: str
    content_type: Optional[str] = None
    size_bytes: int = 0
    truncated: bool = False
    redactions: int = 0             # secrets replaced in the text on upload (reported once, at upload)
    model_config = {"from_attributes": True}


class ToolTraceItem(BaseModel):
    tool: str
    arguments: dict = {}


class ChatResponse(BaseModel):
    conversation_id: int
    message: str
    tool_trace: list[ToolTraceItem] = []
    provider: ProviderInfo


class AgentMessageResponse(BaseModel):
    id: int
    role: str
    content: Optional[str] = None
    tool_trace: list[Any] = []
    files: list[ChatFileResponse] = []
    created_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class ConversationSummary(BaseModel):
    id: int
    title: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class ConversationDetail(ConversationSummary):
    messages: list[AgentMessageResponse] = []


class TriageRequest(BaseModel):
    scan_id: Optional[int] = None
    limit: int = 25


class TriageItem(BaseModel):
    id: Optional[int] = None
    priority: int = 0
    action: Optional[str] = None
    rationale: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    cloud_provider: Optional[str] = None
    resource_name: Optional[str] = None
    rule_id: Optional[str] = None


class TriageResponse(BaseModel):
    items: list[TriageItem] = []
    provider: ProviderInfo
    count: int = 0


class SkillManifestItem(BaseModel):
    name: str
    description: str
    kind: str
    execution_mode: str = "sync"
    requires_approval: bool = False
    input_schema: dict = {}


class SkillExecutionRequest(BaseModel):
    params: dict = {}


class SkillPlanRequest(BaseModel):
    message: str
    params: dict = {}


class SkillPlanResponse(BaseModel):
    skill: str
    description: Optional[str] = None
    status: str
    requires_approval: bool = False
    input_schema: dict = {}
    params: dict = {}


class SkillExecutionResponse(BaseModel):
    skill: str
    status: str
    result: dict = {}


class RemediationResponse(BaseModel):
    finding_id: int
    content: str
    provider: ProviderInfo


class InsightResponse(BaseModel):
    id: int
    finding_id: Optional[int] = None
    kind: str
    content: Optional[str] = None
    data: Optional[dict] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    created_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class LLMConfigUpdate(BaseModel):
    provider: str
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    api_key: Optional[str] = None  # blank = keep existing stored key
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    enabled: bool = True


class LLMConfigResponse(BaseModel):
    provider: str
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    enabled: bool = True
    has_api_key: bool = False
    source: str = "platform"  # "org" | "platform"
    providers: list[dict] = []
    effective: ProviderInfo


class LLMTestResult(BaseModel):
    ok: bool
    provider: ProviderInfo
    latency_ms: Optional[int] = None
    sample: Optional[str] = None
    error: Optional[str] = None


# ── Agent listing ────────────────────────────────────────────────────────

class AgentCapability(BaseModel):
    name: str
    description: str


class AgentInfo(BaseModel):
    id: str
    name: str
    description: str
    avatar: str
    capabilities: list[AgentCapability] = []
    status: str = "available"


# ── Chat history ─────────────────────────────────────────────────────────

class ChatHistoryMessage(BaseModel):
    id: int
    conversation_id: int
    role: str
    content: Optional[str] = None
    status: str = "completed"
    task_id: Optional[str] = None
    created_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


class ChatHistoryResponse(BaseModel):
    messages: list[ChatHistoryMessage] = []
    total: int = 0


# ── Auto-fix schemas ───────────────────────────────────────────────

class AutoFixRequest(BaseModel):
    finding_ids: list[int]
    dry_run: bool = True
    repo: Optional[str] = None  # "owner/repo" — uses default if not provided


class AutoFixResultItem(BaseModel):
    finding_id: int
    status: str  # "fix_generated" | "no_fix" | "error"
    file_path: Optional[str] = None
    diff: Optional[str] = None
    pr_title: Optional[str] = None
    commit_message: Optional[str] = None
    confidence: Optional[float] = None
    breaking_change: bool = False
    explanation: Optional[str] = None
    pr_url: Optional[str] = None
    error: Optional[str] = None


class AutoFixResponse(BaseModel):
    total: int
    results: list[AutoFixResultItem] = []
    dry_run: bool = True


class AutoTriageRequest(BaseModel):
    severity_filter: Optional[str] = None  # Only triage findings of this severity
    limit: int = 50


class AutoTriageResultItem(BaseModel):
    finding_id: int
    previous_status: str
    new_status: str
    reason: str
    priority_score: int = 0


class AutoTriageResponse(BaseModel):
    total: int
    triaged: int
    results: list[AutoTriageResultItem] = []


class KnowledgeStatsResponse(BaseModel):
    total_rules_covered: int = 0
    total_patterns: int = 0
    total_successes: int = 0
    total_failures: int = 0
    avg_confidence: float = 0.0
    top_patterns: list[dict] = []

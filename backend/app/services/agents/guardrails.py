"""Production-grade guardrails for the GuardNous AI agent system.

Enterprise-grade safety layer that wraps every agent interaction. Designed for
organizations like Tesla, Palo Alto Networks, CrowdStrike, and FireEye where
AI agent misbehavior could lead to security incidents.

Guardrail layers:
  1. Input sanitization — block prompt injection, PII leakage, jailbreak attempts
  2. Output sanitization — strip secrets, PII, internal paths from responses
  3. Token budget enforcement — prevent runaway LLM costs
  4. Rate limiting — per-org, per-user throttling
  5. Hallucination detection — ground responses in actual data
  6. Action approval gates — require confirmation for destructive actions
  7. Audit logging — immutable record of all agent actions
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ── 1. Input Sanitization ───────────────────────────────────────────

_INJECTION_PATTERNS = [
    # Prompt injection attempts
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?prior\s+(instructions|context|rules)",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"new\s+instructions?\s*:",
    r"system\s*prompt\s*:",
    r"forget\s+(everything|all|your)\s+(you|instructions|rules)",
    r"override\s+(system|safety|security)\s+(prompt|instructions|rules)",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"act\s+as\s+(if\s+you\s+are|a)\s+",
    r"jailbreak",
    r"DAN\s+mode",
    r"developer\s+mode\s+enabled",
    # Data exfiltration
    r"(show|reveal|print|display|output)\s+(your|the|all)\s+(system|instructions|prompt|rules|config)",
    r"what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions|message)",
    # Encoded injection
    r"base64\s*:\s*[A-Za-z0-9+/=]{20,}",
    r"\\x[0-9a-f]{2}",
    # Role-play and persona hijack
    r"you\s+must\s+comply",
    r"respond\s+only\s+in\s+(?:json|xml|yaml)\s+from\s+now\s+on",
    r"translate\s+(all|every)\s+(response|output)\s+to",
    r"repeat\s+after\s+me",
    # Indirect injection via tool abuse
    r"execute\s+(this|the\s+following)\s+(command|script|code)",
    r"run\s+(this|the\s+following)\s+(?:shell|bash|python)",
    r"eval\s*\(",
    r"import\s+os\s*;",
    r"subprocess\.\w+",
]

_COMPILED_INJECTIONS = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

# PII patterns to detect in input
_PII_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "api_key_generic": re.compile(r"\b(?:sk|pk|api|key|token|secret)[-_]?[A-Za-z0-9]{20,}\b", re.IGNORECASE),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "aws_account_id": re.compile(r"\b\d{12}\b"),
    "ip_address": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "github_token": re.compile(r"\bgh[ps]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[bpras]-[A-Za-z0-9-]+\b"),
}


@dataclass
class InputSanitizationResult:
    is_safe: bool
    blocked_reason: str | None = None
    pii_detected: list[str] = field(default_factory=list)
    sanitized_message: str = ""
    risk_score: float = 0.0


def sanitize_input(message: str) -> InputSanitizationResult:
    """Sanitize user input — block injection attempts, flag PII."""
    if not message or not message.strip():
        return InputSanitizationResult(is_safe=True, sanitized_message="")

    # Check for prompt injection
    for pattern in _COMPILED_INJECTIONS:
        if pattern.search(message):
            logger.warning("Prompt injection blocked: %s", pattern.pattern[:60])
            return InputSanitizationResult(
                is_safe=False,
                blocked_reason="Message contains potentially harmful instructions. "
                               "Please rephrase your security question.",
                risk_score=1.0,
            )

    # Detect PII (warn but don't block)
    pii_found = []
    sanitized = message
    for pii_type, pattern in _PII_PATTERNS.items():
        if pattern.search(message):
            pii_found.append(pii_type)
            # Redact PII from the message sent to LLM
            sanitized = pattern.sub(f"[REDACTED_{pii_type.upper()}]", sanitized)

    return InputSanitizationResult(
        is_safe=True,
        pii_detected=pii_found,
        sanitized_message=sanitized,
        risk_score=0.3 if pii_found else 0.0,
    )


# ── 2. Output Sanitization ──────────────────────────────────────────

_SECRET_PATTERNS = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?:aws_secret_access_key|AWS_SECRET)\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "[REDACTED_AWS_SECRET]"),
    # Azure
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE), "[REDACTED_UUID]"),
    # GCP
    (re.compile(r'"private_key"\s*:\s*"-----BEGIN'), '[REDACTED_GCP_KEY]'),
    # Generic secrets
    (re.compile(r"(?:password|passwd|secret|token|api_key|apikey|auth)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE), "[REDACTED_SECRET]"),
    # Bearer tokens
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    # JWT
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED_JWT]"),
    # Private keys
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Connection strings
    (re.compile(r"(?:mongodb|postgres|mysql|redis|amqp)://[^\s]+", re.IGNORECASE), "[REDACTED_CONN_STRING]"),
]

# Internal paths that should never leak
_INTERNAL_PATH_PATTERNS = [
    re.compile(r"/home/\w+/"),
    re.compile(r"C:\\Users\\\w+\\"),
    re.compile(r"/var/lib/docker/"),
    re.compile(r"/proc/\d+/"),
    re.compile(r"/etc/(?:shadow|passwd|sudoers)"),
    re.compile(r"/root/"),
    re.compile(r"/var/run/secrets/kubernetes\.io/"),
    re.compile(r"~/.kube/config"),
    re.compile(r"~/.aws/credentials"),
    re.compile(r"~/.ssh/"),
]


def sanitize_output(content: str) -> str:
    """Strip secrets, internal paths, and PII from agent output."""
    if not content:
        return content

    result = content

    # Remove secrets
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)

    # Remove internal system paths
    for pattern in _INTERNAL_PATH_PATTERNS:
        result = pattern.sub("[internal_path]/", result)

    # Redact PII in output
    for pii_type, pattern in _PII_PATTERNS.items():
        if pii_type != "email":  # emails in output are sometimes legitimate
            result = pattern.sub(f"[REDACTED_{pii_type.upper()}]", result)

    return result


# ── 3. Token Budget Enforcement ──────────────────────────────────────

@dataclass
class TokenBudget:
    max_input_tokens: int = 8000
    max_output_tokens: int = 4000
    max_total_per_conversation: int = 50000
    max_tool_calls_per_turn: int = 10
    max_turns_per_conversation: int = 50
    warn_at_percentage: float = 0.8

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate: ~4 chars per token for English."""
        return len(text) // 4

    def check_budget(
        self,
        input_text: str,
        total_used: int,
        tool_calls_this_turn: int,
        turn_count: int,
    ) -> tuple[bool, str | None]:
        """Returns (within_budget, warning_message)."""
        input_tokens = self.estimate_tokens(input_text)

        if input_tokens > self.max_input_tokens:
            return False, f"Input too long ({input_tokens} estimated tokens, max {self.max_input_tokens}). Please shorten your message."

        if total_used > self.max_total_per_conversation:
            return False, "Conversation token budget exceeded. Please start a new conversation."

        if tool_calls_this_turn >= self.max_tool_calls_per_turn:
            return False, f"Too many tool calls in one turn ({tool_calls_this_turn}/{self.max_tool_calls_per_turn}). Limiting to prevent runaway."

        if turn_count >= self.max_turns_per_conversation:
            return False, "Maximum conversation length reached. Please start a new conversation."

        # Warnings
        usage_pct = total_used / self.max_total_per_conversation
        if usage_pct >= self.warn_at_percentage:
            return True, f"⚠️ Token budget {usage_pct:.0%} used. Consider starting a new conversation soon."

        return True, None


# ── 4. Rate Limiting ─────────────────────────────────────────────────

class RateLimiter:
    """In-memory sliding window rate limiter per organization."""

    def __init__(
        self,
        max_requests_per_minute: int = 30,
        max_requests_per_hour: int = 500,
        max_tool_calls_per_minute: int = 60,
    ):
        self.max_rpm = max_requests_per_minute
        self.max_rph = max_requests_per_hour
        self.max_tcpm = max_tool_calls_per_minute
        self._requests: dict[int, list[float]] = defaultdict(list)
        self._tool_calls: dict[int, list[float]] = defaultdict(list)

    def _cleanup(self, timestamps: list[float], window_seconds: int) -> list[float]:
        cutoff = time.time() - window_seconds
        return [t for t in timestamps if t > cutoff]

    def check_request(self, org_id: int) -> tuple[bool, str | None]:
        now = time.time()
        self._requests[org_id] = self._cleanup(self._requests[org_id], 3600)

        minute_count = sum(1 for t in self._requests[org_id] if t > now - 60)
        if minute_count >= self.max_rpm:
            return False, f"Rate limit exceeded ({self.max_rpm} requests/minute). Please wait."

        hour_count = len(self._requests[org_id])
        if hour_count >= self.max_rph:
            return False, f"Hourly rate limit exceeded ({self.max_rph}/hour). Please try again later."

        self._requests[org_id].append(now)
        return True, None

    def check_tool_call(self, org_id: int) -> tuple[bool, str | None]:
        now = time.time()
        self._tool_calls[org_id] = self._cleanup(self._tool_calls[org_id], 60)

        if len(self._tool_calls[org_id]) >= self.max_tcpm:
            return False, f"Tool call rate limit exceeded ({self.max_tcpm}/minute)."

        self._tool_calls[org_id].append(now)
        return True, None


# Singleton rate limiter
_rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    return _rate_limiter


# ── 5. Hallucination Detection ───────────────────────────────────────

def check_hallucination(response: str, context_data: dict) -> dict:
    """Detect potential hallucinations by cross-referencing response claims with data.

    Returns a confidence assessment of the response's grounding.
    """
    warnings: list[str] = []

    # Check for fabricated finding IDs
    mentioned_ids = re.findall(r"#(\d+)", response)
    if context_data.get("finding_ids"):
        valid_ids = {str(fid) for fid in context_data["finding_ids"]}
        for mid in mentioned_ids:
            if mid not in valid_ids and int(mid) > 0:
                warnings.append(f"Finding #{mid} not found in current data — may be hallucinated")

    # Check for fabricated CVE IDs
    mentioned_cves = re.findall(r"CVE-\d{4}-\d{4,}", response)
    if context_data.get("known_cves"):
        known = set(context_data["known_cves"])
        for cve in mentioned_cves:
            if cve not in known:
                warnings.append(f"{cve} not in current CVE database — verify independently")

    # Check for fabricated statistics
    mentioned_counts = re.findall(r"(\d+)\s+(?:critical|high|medium|low)\s+findings?", response, re.IGNORECASE)
    sev_breakdown = context_data.get("severity_breakdown", {})
    if sev_breakdown and mentioned_counts:
        for count_str in mentioned_counts:
            count = int(count_str)
            total = sum(sev_breakdown.values())
            if count > total * 2:
                warnings.append(f"Mentioned count {count} seems inflated vs actual total {total}")

    # Check for absolute claims without data backing
    absolute_phrases = [
        "no vulnerabilities", "completely secure", "zero risk",
        "100% compliant", "no findings", "all clear",
    ]
    for phrase in absolute_phrases:
        if phrase in response.lower():
            total_findings = context_data.get("total_findings", 0)
            if total_findings > 0:
                warnings.append(f'Claim "{phrase}" contradicts {total_findings} active findings')

    grounding_score = max(0.0, 1.0 - (len(warnings) * 0.2))
    return {
        "grounding_score": round(grounding_score, 2),
        "warnings": warnings,
        "is_grounded": grounding_score >= 0.6,
    }


# ── 6. Action Approval Gates ────────────────────────────────────────

# Actions that require explicit user confirmation
GATED_ACTIONS = {
    "triage_finding": {
        "gate_level": "confirm",
        "description": "Changing finding triage status",
        "reversible": True,
    },
    "auto_fix_finding": {
        "gate_level": "approve",
        "description": "Generating and applying automated code fix",
        "reversible": False,
    },
    "create_pr": {
        "gate_level": "approve",
        "description": "Creating a pull request with code changes",
        "reversible": True,
    },
    "bulk_triage": {
        "gate_level": "approve",
        "description": "Bulk triaging multiple findings at once",
        "reversible": True,
    },
}


def check_action_gate(tool_name: str, arguments: dict) -> dict | None:
    """Check if a tool call requires user approval.

    Returns gate info if approval is needed, None if action can proceed.
    """
    gate = GATED_ACTIONS.get(tool_name)
    if not gate:
        return None

    # Auto-fix with dry_run=true doesn't need approval
    if tool_name == "auto_fix_finding" and arguments.get("dry_run", True):
        return None

    return {
        "tool": tool_name,
        "gate_level": gate["gate_level"],
        "description": gate["description"],
        "reversible": gate["reversible"],
        "arguments": arguments,
        "requires_confirmation": True,
    }


# ── 7. Audit Logging ────────────────────────────────────────────────

@dataclass
class AgentAuditEntry:
    timestamp: float
    organization_id: int
    user_id: int | None
    action: str
    tool_name: str | None
    arguments_hash: str | None
    result_summary: str
    guardrail_flags: list[str]
    token_estimate: int

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "organization_id": self.organization_id,
            "user_id": self.user_id,
            "action": self.action,
            "tool_name": self.tool_name,
            "arguments_hash": self.arguments_hash,
            "result_summary": self.result_summary[:200],
            "guardrail_flags": self.guardrail_flags,
            "token_estimate": self.token_estimate,
        }


def create_audit_entry(
    org_id: int,
    action: str,
    tool_name: str | None = None,
    arguments: dict | None = None,
    result: str = "",
    flags: list[str] | None = None,
    user_id: int | None = None,
    token_estimate: int = 0,
) -> AgentAuditEntry:
    """Create an immutable audit log entry for agent actions."""
    args_hash = None
    if arguments:
        args_hash = hashlib.sha256(
            str(sorted(arguments.items())).encode()
        ).hexdigest()[:16]

    return AgentAuditEntry(
        timestamp=time.time(),
        organization_id=org_id,
        user_id=user_id,
        action=action,
        tool_name=tool_name,
        arguments_hash=args_hash,
        result_summary=result[:200] if result else "",
        guardrail_flags=flags or [],
        token_estimate=token_estimate,
    )


# ── Unified Guardrail Pipeline ──────────────────────────────────────

@dataclass
class GuardrailResult:
    """Result of the full guardrail pipeline."""
    allowed: bool
    sanitized_input: str
    warnings: list[str] = field(default_factory=list)
    blocked_reason: str | None = None
    pii_detected: list[str] = field(default_factory=list)
    rate_limit_ok: bool = True
    budget_ok: bool = True
    audit_entry: AgentAuditEntry | None = None


def run_guardrails(
    message: str,
    org_id: int,
    user_id: int | None = None,
    total_tokens_used: int = 0,
    tool_calls_this_turn: int = 0,
    turn_count: int = 0,
) -> GuardrailResult:
    """Run the full guardrail pipeline on an incoming message.

    Call this BEFORE sending anything to the LLM.
    """
    warnings: list[str] = []
    flags: list[str] = []

    # 1. Input sanitization
    input_result = sanitize_input(message)
    if not input_result.is_safe:
        flags.append("injection_blocked")
        return GuardrailResult(
            allowed=False,
            sanitized_input="",
            blocked_reason=input_result.blocked_reason,
            audit_entry=create_audit_entry(
                org_id, "blocked_injection", flags=flags, user_id=user_id,
            ),
        )

    if input_result.pii_detected:
        flags.append("pii_detected")
        warnings.append(
            f"PII detected and redacted: {', '.join(input_result.pii_detected)}. "
            "Your sensitive data was not sent to the AI model."
        )

    # 2. Rate limiting
    rate_ok, rate_msg = _rate_limiter.check_request(org_id)
    if not rate_ok:
        flags.append("rate_limited")
        return GuardrailResult(
            allowed=False,
            sanitized_input="",
            blocked_reason=rate_msg,
            rate_limit_ok=False,
            audit_entry=create_audit_entry(
                org_id, "rate_limited", flags=flags, user_id=user_id,
            ),
        )

    # 3. Token budget
    budget = TokenBudget()
    budget_ok, budget_msg = budget.check_budget(
        message, total_tokens_used, tool_calls_this_turn, turn_count,
    )
    if not budget_ok:
        flags.append("budget_exceeded")
        return GuardrailResult(
            allowed=False,
            sanitized_input="",
            blocked_reason=budget_msg,
            budget_ok=False,
            audit_entry=create_audit_entry(
                org_id, "budget_exceeded", flags=flags, user_id=user_id,
            ),
        )
    if budget_msg:
        warnings.append(budget_msg)

    return GuardrailResult(
        allowed=True,
        sanitized_input=input_result.sanitized_message or message,
        warnings=warnings,
        pii_detected=input_result.pii_detected,
        audit_entry=create_audit_entry(
            org_id, "allowed", flags=flags, user_id=user_id,
            token_estimate=budget.estimate_tokens(message),
        ),
    )


def run_output_guardrails(
    response: str,
    context_data: dict | None = None,
) -> tuple[str, dict]:
    """Run guardrails on agent output.

    Returns (sanitized_response, hallucination_check).
    """
    sanitized = sanitize_output(response)
    hallucination = check_hallucination(sanitized, context_data or {})
    return sanitized, hallucination

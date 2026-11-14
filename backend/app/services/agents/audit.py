"""Agent decision audit trail for Project AEGIS.

Records every agent decision, tool call, handoff, and finding
for compliance, debugging, and explainability.
"""
from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    timestamp: float
    conversation_id: int
    event_type: str  # plan_created, agent_spawned, tool_called, tool_result, handoff, finding, error, synthesis
    agent_id: str | None = None
    agent_name: str | None = None
    tool_name: str | None = None
    tool_args: dict | None = None
    result_summary: str | None = None
    duration_ms: float | None = None
    metadata: dict = field(default_factory=dict)


class AuditTrail:
    """In-memory audit trail with optional Redis persistence."""

    def __init__(self, conversation_id: int, redis_client=None):
        self._conversation_id = conversation_id
        self._entries: list[AuditEntry] = []
        self._redis = redis_client
        self._start_time = time.time()

    def record(self, event_type: str, **kwargs) -> AuditEntry:
        entry = AuditEntry(
            timestamp=time.time(),
            conversation_id=self._conversation_id,
            event_type=event_type,
            **kwargs,
        )
        self._entries.append(entry)
        self._persist(entry)
        return entry

    def record_tool_call(self, agent_id: str, tool_name: str, tool_args: dict, result: str, duration_ms: float):
        self.record("tool_called", agent_id=agent_id, tool_name=tool_name, tool_args=tool_args, result_summary=result[:500], duration_ms=duration_ms)

    def record_handoff(self, from_agent: str, to_agent: str, task: str):
        self.record("handoff", agent_id=from_agent, metadata={"to_agent": to_agent, "task": task})

    def record_finding(self, agent_id: str, finding: dict):
        self.record("finding", agent_id=agent_id, result_summary=json.dumps(finding, default=str)[:500])

    def record_error(self, agent_id: str, error: str):
        self.record("error", agent_id=agent_id, result_summary=error[:500])

    def get_entries(self, event_type: str | None = None) -> list[AuditEntry]:
        if event_type:
            return [e for e in self._entries if e.event_type == event_type]
        return list(self._entries)

    def summary(self) -> dict:
        elapsed = time.time() - self._start_time
        return {
            "conversation_id": self._conversation_id,
            "total_events": len(self._entries),
            "agents_used": list({e.agent_id for e in self._entries if e.agent_id}),
            "tools_called": len([e for e in self._entries if e.event_type == "tool_called"]),
            "findings_count": len([e for e in self._entries if e.event_type == "finding"]),
            "errors": len([e for e in self._entries if e.event_type == "error"]),
            "total_duration_ms": round(elapsed * 1000, 1),
        }

    def to_json(self) -> str:
        return json.dumps([asdict(e) for e in self._entries], default=str)

    def _persist(self, entry: AuditEntry):
        if not self._redis:
            return
        try:
            key = f"audit:{self._conversation_id}"
            self._redis.rpush(key, json.dumps(asdict(entry), default=str))
            self._redis.expire(key, 86400 * 7)  # 7 day TTL
        except Exception as exc:
            logger.warning("Audit persist failed: %s", exc)

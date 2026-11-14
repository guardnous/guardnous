"""Cross-turn conversation context for Project AEGIS.

Manages agent context persistence across multiple conversation turns
using Redis, so agents remember what was discussed and investigated.
"""
from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TurnContext:
    """Context from a single conversation turn."""
    turn_number: int
    user_message: str
    agents_used: list[str]
    tools_called: list[str]
    findings: list[dict]
    topics_investigated: list[str]
    timestamp: float = field(default_factory=time.time)


class CrossTurnContext:
    """Manages conversation context across multiple turns.

    Persists to Redis with a 24h TTL per conversation.
    Provides context injection for agents to avoid repeating work.
    """

    def __init__(self, conversation_id: int, redis_client=None):
        self._conversation_id = conversation_id
        self._redis = redis_client
        self._turns: list[TurnContext] = []
        self._load()

    def _load(self):
        if not self._redis:
            return
        try:
            key = f"conv_ctx:{self._conversation_id}"
            data = self._redis.get(key)
            if data:
                turns = json.loads(data)
                self._turns = [TurnContext(**t) for t in turns]
        except Exception as exc:
            logger.warning("Context load failed: %s", exc)

    def save_turn(self, turn: TurnContext):
        self._turns.append(turn)
        self._persist()

    def _persist(self):
        if not self._redis:
            return
        try:
            key = f"conv_ctx:{self._conversation_id}"
            data = json.dumps([{
                "turn_number": t.turn_number,
                "user_message": t.user_message[:200],
                "agents_used": t.agents_used,
                "tools_called": t.tools_called,
                "findings": t.findings[:10],
                "topics_investigated": t.topics_investigated,
                "timestamp": t.timestamp,
            } for t in self._turns[-20:]], default=str)  # keep last 20 turns
            self._redis.setex(key, 86400, data)
        except Exception as exc:
            logger.warning("Context persist failed: %s", exc)

    def all_findings(self) -> list[dict]:
        findings = []
        for t in self._turns:
            findings.extend(t.findings)
        return findings

    def all_topics(self) -> list[str]:
        topics = []
        for t in self._turns:
            topics.extend(t.topics_investigated)
        return list(set(topics))

    def all_agents_used(self) -> list[str]:
        agents = []
        for t in self._turns:
            agents.extend(t.agents_used)
        return list(set(agents))

    def to_injection_prompt(self) -> str:
        if not self._turns:
            return ""
        lines = ["Previous conversation context:"]
        for t in self._turns[-5:]:
            lines.append(f"- Turn {t.turn_number}: User asked about '{t.user_message[:100]}'. "
                        f"Agents {', '.join(t.agents_used)} investigated {', '.join(t.topics_investigated[:5])}. "
                        f"Found {len(t.findings)} findings.")
        if self.all_findings():
            lines.append(f"\nTotal prior findings: {len(self.all_findings())}. "
                        f"Topics already investigated: {', '.join(self.all_topics()[:10])}. "
                        f"Do NOT re-investigate these unless the user explicitly asks.")
        return "\n".join(lines)

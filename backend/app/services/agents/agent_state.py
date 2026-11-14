"""
Persistent agent state machine for GuardNous (Project AEGIS).

Stores agent memory across conversation turns using Redis so that
multi-turn investigations avoid redundant work and maintain context.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_STATE_TTL_SECONDS = 86400  # 24 hours


def _redis_key(conversation_id: int, agent_id: str) -> str:
    return f"agent_state:{conversation_id}:{agent_id}"


@dataclass
class AgentState:
    """Per-agent persistent state scoped to a single conversation."""

    conversation_id: int
    agent_id: str = "supervisor"
    investigated: dict[str, list[str]] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    pending_actions: list[str] = field(default_factory=list)
    agent_history: list[dict] = field(default_factory=list)
    plan_history: list[dict] = field(default_factory=list)
    turn_count: int = 0

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def save(self, redis_client: Any) -> None:
        """Serialize state to Redis with a 24-hour TTL."""
        key = _redis_key(self.conversation_id, self.agent_id)
        payload = json.dumps(
            {
                "conversation_id": self.conversation_id,
                "agent_id": self.agent_id,
                "investigated": self.investigated,
                "findings": self.findings,
                "pending_actions": self.pending_actions,
                "agent_history": self.agent_history,
                "plan_history": self.plan_history,
                "turn_count": self.turn_count,
            }
        )
        try:
            await redis_client.setex(key, _STATE_TTL_SECONDS, payload)
        except Exception:
            logger.warning("Failed to save agent state to Redis for key %s", key, exc_info=True)

    @classmethod
    async def load(
        cls,
        conversation_id: int,
        agent_id: str,
        redis_client: Any,
    ) -> AgentState:
        """Load state from Redis. Returns a blank state if the key is missing or Redis is down."""
        key = _redis_key(conversation_id, agent_id)
        try:
            raw = await redis_client.get(key)
        except Exception:
            logger.warning("Redis unavailable when loading agent state for key %s", key, exc_info=True)
            return cls(conversation_id=conversation_id, agent_id=agent_id)

        if raw is None:
            return cls(conversation_id=conversation_id, agent_id=agent_id)

        data: dict = json.loads(raw)
        return cls(
            conversation_id=data.get("conversation_id", conversation_id),
            agent_id=data.get("agent_id", agent_id),
            investigated=data.get("investigated", {}),
            findings=data.get("findings", []),
            pending_actions=data.get("pending_actions", []),
            agent_history=data.get("agent_history", []),
            plan_history=data.get("plan_history", []),
            turn_count=data.get("turn_count", 0),
        )

    # ------------------------------------------------------------------
    # Investigation tracking
    # ------------------------------------------------------------------

    def record_investigation(self, topic: str, subtopics: list[str]) -> None:
        existing = self.investigated.setdefault(topic, [])
        for sub in subtopics:
            if sub not in existing:
                existing.append(sub)

    def add_finding(self, finding: dict) -> None:
        self.findings.append(finding)

    def record_agent_run(
        self,
        agent_id: str,
        summary: str,
        tools_used: list[str],
    ) -> None:
        self.turn_count += 1
        self.agent_history.append(
            {
                "agent": agent_id,
                "summary": summary,
                "turn": self.turn_count,
                "tools_used": tools_used,
            }
        )

    # ------------------------------------------------------------------
    # Pending actions
    # ------------------------------------------------------------------

    def add_pending_action(self, action: str) -> None:
        if action not in self.pending_actions:
            self.pending_actions.append(action)

    def complete_action(self, action: str) -> None:
        try:
            self.pending_actions.remove(action)
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

    def to_context_string(self) -> str:
        """Build a compact text summary suitable for LLM context injection."""
        parts: list[str] = []

        if self.investigated:
            lines = [f"  - {topic}: {', '.join(subs)}" for topic, subs in self.investigated.items()]
            parts.append("Already investigated:\n" + "\n".join(lines))

        if self.findings:
            summaries = [
                f"  - [{f.get('severity', 'info')}] {f.get('title', f.get('summary', str(f)))}"
                for f in self.findings
            ]
            parts.append(f"Findings ({len(self.findings)}):\n" + "\n".join(summaries))

        if self.pending_actions:
            parts.append("Pending actions:\n" + "\n".join(f"  - {a}" for a in self.pending_actions))

        if self.agent_history:
            agent_lines = [
                f"  - turn {h['turn']}: {h['agent']} — {h['summary']}"
                for h in self.agent_history
            ]
            parts.append("Agents that already ran:\n" + "\n".join(agent_lines))

        if not parts:
            return "No prior investigation context."

        return "\n\n".join(parts)

    def should_skip_tool(self, tool_name: str) -> bool:
        """Return True if *tool_name* was already used in a prior agent run."""
        for entry in self.agent_history:
            if tool_name in entry.get("tools_used", []):
                return True
        return False

    def get_prior_findings_for_agent(self, agent_id: str) -> list[dict]:
        """Return findings produced by agents other than *agent_id*."""
        other_agents: set[str] = set()
        for entry in self.agent_history:
            if entry["agent"] != agent_id:
                other_agents.add(entry["agent"])

        if not other_agents:
            return []

        return [
            f
            for f in self.findings
            if f.get("source_agent") in other_agents or f.get("agent") in other_agents
        ]


# ======================================================================
# Conversation-wide context (aggregates all agent states)
# ======================================================================


@dataclass
class ConversationContext:
    """Aggregated view across every agent's state in a conversation."""

    conversation_id: int
    agent_states: dict[str, AgentState] = field(default_factory=dict)

    @classmethod
    async def load_all(
        cls,
        conversation_id: int,
        redis_client: Any,
    ) -> ConversationContext:
        """Discover and load all agent states for a conversation.

        We scan for keys matching ``agent_state:{conversation_id}:*``.
        If Redis is unavailable the returned context is empty.
        """
        ctx = cls(conversation_id=conversation_id)
        try:
            pattern = f"agent_state:{conversation_id}:*"
            keys: list[bytes | str] = []
            async for key in redis_client.scan_iter(match=pattern):
                keys.append(key)
        except Exception:
            logger.warning(
                "Redis unavailable when scanning agent states for conversation %s",
                conversation_id,
                exc_info=True,
            )
            return ctx

        for key in keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            agent_id = key_str.rsplit(":", 1)[-1]
            state = await AgentState.load(conversation_id, agent_id, redis_client)
            ctx.agent_states[agent_id] = state

        return ctx

    # ------------------------------------------------------------------
    # Merged views
    # ------------------------------------------------------------------

    def all_findings(self) -> list[dict]:
        merged: list[dict] = []
        for state in self.agent_states.values():
            merged.extend(state.findings)
        return merged

    def all_investigated(self) -> dict[str, list[str]]:
        merged: dict[str, list[str]] = {}
        for state in self.agent_states.values():
            for topic, subs in state.investigated.items():
                existing = merged.setdefault(topic, [])
                for sub in subs:
                    if sub not in existing:
                        existing.append(sub)
        return merged

    def to_injection_prompt(self) -> str:
        """Full context block for the Supervisor's system prompt."""
        parts: list[str] = [f"=== Conversation {self.conversation_id} — Prior Context ==="]

        investigated = self.all_investigated()
        if investigated:
            lines = [f"  - {t}: {', '.join(s)}" for t, s in investigated.items()]
            parts.append("Topics already investigated:\n" + "\n".join(lines))

        findings = self.all_findings()
        if findings:
            summaries = [
                f"  - [{f.get('severity', 'info')}] {f.get('title', f.get('summary', str(f)))}"
                for f in findings
            ]
            parts.append(f"All findings ({len(findings)}):\n" + "\n".join(summaries))

        all_history: list[dict] = []
        for state in self.agent_states.values():
            all_history.extend(state.agent_history)
        all_history.sort(key=lambda h: h.get("turn", 0))

        if all_history:
            agent_lines = [
                f"  - turn {h['turn']}: {h['agent']} — {h['summary']}"
                for h in all_history
            ]
            parts.append("Agent execution history:\n" + "\n".join(agent_lines))

        pending: list[str] = []
        for state in self.agent_states.values():
            pending.extend(state.pending_actions)
        if pending:
            parts.append("Pending actions:\n" + "\n".join(f"  - {a}" for a in pending))

        if len(parts) == 1:
            parts.append("No prior context available.")

        return "\n\n".join(parts)

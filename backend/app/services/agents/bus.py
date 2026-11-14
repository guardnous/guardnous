"""Inter-agent communication bus for GuardNous (Project AEGIS).

Provides async message routing between security agents during
multi-agent orchestration. Pure infrastructure — no project imports.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

MSG_TYPES = frozenset({"finding", "request", "handoff", "result", "alert", "status"})


@dataclass(slots=True)
class AgentMessage:
    """A single message routed between agents."""

    from_agent: str
    to_agent: str | None
    msg_type: str
    payload: dict
    conversation_id: int
    correlation_id: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.msg_type not in MSG_TYPES:
            raise ValueError(
                f"Invalid msg_type {self.msg_type!r}; must be one of {sorted(MSG_TYPES)}"
            )


class AgentBus:
    """In-process async message bus for inter-agent communication."""

    def __init__(self) -> None:
        self._queues: dict[str, asyncio.Queue[AgentMessage]] = {}
        self._subscribers: dict[str, list[Callable]] = {}
        self._history: list[AgentMessage] = []
        self._event_log: list[dict] = []

    def _ensure_queue(self, agent_id: str) -> asyncio.Queue[AgentMessage]:
        if agent_id not in self._queues:
            self._queues[agent_id] = asyncio.Queue()
        return self._queues[agent_id]

    async def send(self, msg: AgentMessage) -> None:
        """Route *msg* to a specific agent queue or broadcast to all."""
        self._history.append(msg)

        if msg.to_agent is not None:
            queue = self._ensure_queue(msg.to_agent)
            await queue.put(msg)
            logger.debug(
                "bus: %s -> %s [%s] cid=%s",
                msg.from_agent,
                msg.to_agent,
                msg.msg_type,
                msg.correlation_id,
            )
        else:
            for agent_id, queue in self._queues.items():
                if agent_id != msg.from_agent:
                    await queue.put(msg)
            logger.debug(
                "bus: %s -> * (broadcast) [%s] cid=%s",
                msg.from_agent,
                msg.msg_type,
                msg.correlation_id,
            )

        for callback in self._subscribers.get(msg.msg_type, []):
            try:
                result = callback(msg)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Subscriber callback failed for %s", msg.msg_type)

    async def receive(
        self, agent_id: str, timeout: float = 30.0
    ) -> AgentMessage | None:
        """Get next message for *agent_id*, returning ``None`` on timeout."""
        queue = self._ensure_queue(agent_id)
        try:
            msg = await asyncio.wait_for(queue.get(), timeout=timeout)
            logger.debug(
                "bus: %s <- %s [%s]", agent_id, msg.from_agent, msg.msg_type
            )
            return msg
        except asyncio.TimeoutError:
            return None

    def subscribe(
        self, agent_id: str, msg_type: str, callback: Callable
    ) -> None:
        """Register *callback* to fire whenever a message of *msg_type* arrives."""
        self._ensure_queue(agent_id)
        self._subscribers.setdefault(msg_type, []).append(callback)
        logger.debug("bus: %s subscribed to %s", agent_id, msg_type)

    def get_chain(self, correlation_id: str) -> list[AgentMessage]:
        """Return the full message chain for an audit trail."""
        return [m for m in self._history if m.correlation_id == correlation_id]

    def get_history(self, conversation_id: int) -> list[AgentMessage]:
        """Return all messages belonging to *conversation_id*."""
        return [m for m in self._history if m.conversation_id == conversation_id]

    def emit_sse(self, event: dict) -> None:
        """Append an SSE event for the streaming generator to yield."""
        self._event_log.append(event)

    def drain_sse_events(self) -> list[dict]:
        """Pop and return all pending SSE events."""
        events = list(self._event_log)
        self._event_log.clear()
        return events


def create_message(
    from_agent: str,
    to_agent: str | None,
    msg_type: str,
    payload: dict,
    conversation_id: int,
    correlation_id: str | None = None,
) -> AgentMessage:
    """Build an :class:`AgentMessage` with auto-generated *id* and *timestamp*."""
    return AgentMessage(
        from_agent=from_agent,
        to_agent=to_agent,
        msg_type=msg_type,
        payload=payload,
        conversation_id=conversation_id,
        correlation_id=correlation_id or str(uuid.uuid4()),
    )


def create_handoff_message(
    from_agent: str,
    to_agent: str,
    task: str,
    context: dict,
    conversation_id: int,
    correlation_id: str,
) -> AgentMessage:
    """Create a handoff message that transfers work between agents."""
    return AgentMessage(
        from_agent=from_agent,
        to_agent=to_agent,
        msg_type="handoff",
        payload={"task": task, "context": context},
        conversation_id=conversation_id,
        correlation_id=correlation_id,
    )

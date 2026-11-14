"""Server-side chat processing via Celery.

The chat endpoint saves the user message and an empty assistant placeholder
(status='processing'), then enqueues this task.  The task runs the full
orchestrator loop, publishes every token/event to a Redis pub/sub channel,
and progressively persists partial content to Postgres.  The frontend
subscribes to the Redis channel via an SSE endpoint to receive live tokens.
If the client disconnects, processing continues to completion.
"""

import asyncio
import json
import logging
import time

import redis
from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.models.agent import AgentMessage

logger = logging.getLogger(__name__)

sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_size=3)

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


CHANNEL_PREFIX = "chat:progress:"
FLUSH_INTERVAL = 2.0  # seconds between partial DB saves


def _publish(r: redis.Redis, channel: str, event: dict):
    """Publish an SSE event dict to Redis pub/sub."""
    r.publish(channel, json.dumps(event))


def _update_message(session: Session, message_id: int, **fields):
    """Update an AgentMessage row."""
    session.execute(
        update(AgentMessage).where(AgentMessage.id == message_id).values(**fields)
    )
    session.commit()


@celery_app.task(name="process_chat_message", bind=True, max_retries=1, acks_late=True)
def process_chat_message(
    self,
    assistant_message_id: int,
    conversation_id: int,
    organization_id: int,
    history: list[dict],
    agent_id: str | None = None,
    use_supervisor: bool = False,
):
    """Run the full agentic loop and stream results via Redis pub/sub.

    Args:
        assistant_message_id: ID of the pre-created assistant placeholder row.
        conversation_id: Conversation this message belongs to.
        organization_id: Org context for LLM config and RBAC.
        history: Full conversation history including the new user message.
        agent_id: Optional explicit agent to route to.
        use_supervisor: Whether to use the supervised multi-agent path.
    """
    channel = f"{CHANNEL_PREFIX}{assistant_message_id}"
    r = _get_redis()

    # Run the async orchestrator inside the Celery sync worker
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run_orchestrator(
                r, channel, assistant_message_id, conversation_id,
                organization_id, history, agent_id, use_supervisor,
            )
        )
    except Exception as exc:
        logger.exception("Chat task failed for message %s", assistant_message_id)
        # Mark as failed in DB
        with Session(sync_engine) as session:
            _update_message(
                session, assistant_message_id,
                status="failed",
                content="An error occurred while processing your request. Please try again.",
            )
        _publish(r, channel, {"type": "error", "message": str(exc), "done": True})
    finally:
        # Always send a terminal event so subscribers know to disconnect
        _publish(r, channel, {"type": "stream_end"})
        loop.close()


async def _run_orchestrator(
    r: redis.Redis,
    channel: str,
    assistant_message_id: int,
    conversation_id: int,
    organization_id: int,
    history: list[dict],
    agent_id: str | None,
    use_supervisor: bool,
):
    """Async orchestrator wrapper that publishes events and persists results."""
    from app.core.database import async_session as _session_factory
    from app.services.agents.orchestrator import run_agent_stream
    from app.services.agents.config import resolve_llm_settings

    _SUPERVISOR_EVENT_TYPES = frozenset({
        "plan", "plan_update", "agent_spawn", "agent_thinking",
        "agent_tool", "agent_finding", "agent_handoff", "agent_complete",
        "progress", "synthesis",
    })

    full_content: list[str] = []
    tool_trace: list[dict] = []
    last_flush = time.monotonic()

    async with _session_factory() as db:
        try:
            if use_supervisor:
                from app.services.agents.supervisor import run_supervised
                llm_settings = await resolve_llm_settings(db, organization_id)
                event_source = run_supervised(
                    db,
                    organization_id=organization_id,
                    history=history,
                    llm_settings=llm_settings,
                    conversation_id=conversation_id,
                )
            else:
                from app.models.agent import AgentConversation

                conversation = await db.get(AgentConversation, conversation_id)
                event_source = run_agent_stream(
                    db, organization_id, history, agent_id=agent_id,
                    user_id=conversation.user_id if conversation else None,
                )

            async for event in event_source:
                etype = event.get("type", "")

                if etype == "routing":
                    _publish(r, channel, {
                        "type": "routing",
                        "agent_id": event["agent_id"],
                        "agent_name": event["agent_name"],
                        "confidence": event["confidence"],
                        "done": False,
                    })

                elif etype == "tool_start":
                    _publish(r, channel, {
                        "type": "tool_start",
                        "tool": event["tool"],
                        "step": event.get("step", 0),
                        "done": False,
                    })

                elif etype == "tool_result":
                    tool_trace.append({"tool": event["tool"]})
                    _publish(r, channel, {
                        "type": "tool_result",
                        "tool": event["tool"],
                        "step": event.get("step", 0),
                        "done": False,
                    })

                elif etype == "token":
                    token = event.get("content", "")
                    full_content.append(token)
                    _publish(r, channel, {"token": token, "done": False})

                    # Periodic partial save to DB
                    now = time.monotonic()
                    if now - last_flush >= FLUSH_INTERVAL:
                        await _flush_partial(db, assistant_message_id, full_content, tool_trace)
                        last_flush = now

                elif etype == "done":
                    _publish(r, channel, {
                        "token": "",
                        "done": True,
                        "conversation_id": conversation_id,
                        "provider": event.get("provider", {}).get("provider", "mock"),
                        "model": event.get("provider", {}).get("model"),
                        "live": event.get("provider", {}).get("live", False),
                        "tool_trace": event.get("tool_trace", tool_trace),
                    })

                elif etype == "error":
                    _publish(r, channel, {
                        "type": "error",
                        "message": event.get("message", "Unknown error"),
                        "done": True,
                    })

                elif etype in _SUPERVISOR_EVENT_TYPES:
                    payload = {k: v for k, v in event.items()}
                    payload["done"] = False
                    _publish(r, channel, payload)

        except Exception:
            logger.exception("Orchestrator error for message %s", assistant_message_id)
            raise

        # Final persist — complete content
        content = "".join(full_content)
        from sqlalchemy import update as sa_update
        stmt = (
            sa_update(AgentMessage)
            .where(AgentMessage.id == assistant_message_id)
            .values(
                content=content if content.strip() else "I wasn't able to generate a response. Please try again.",
                tool_trace=tool_trace,
                status="completed",
            )
        )
        await db.execute(stmt)
        await db.commit()


async def _flush_partial(db, message_id: int, content_parts: list[str], tool_trace: list[dict]):
    """Save partial content to DB so it survives crashes."""
    from sqlalchemy import update as sa_update
    content = "".join(content_parts)
    if not content.strip():
        return
    stmt = (
        sa_update(AgentMessage)
        .where(AgentMessage.id == message_id)
        .values(content=content, tool_trace=tool_trace)
    )
    await db.execute(stmt)
    await db.commit()

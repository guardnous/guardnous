"""Sub-Agent Delegation — spawns specialized child agents.

A parent agent can delegate a sub-task to a child agent with:
- A custom system prompt scoped to the sub-task
- A tool whitelist (only tools relevant to the sub-task)
- An iteration budget (max tool calls the child can make)
- Shared notebook for findings accumulation

Supports structured agent-to-agent handoff via the message bus
for traceable, budget-scoped delegation chains.

Inspired by Nudgebee's agent_delegate.go but adapted for Python/async.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import AsyncGenerator

from app.services.agents.bus import AgentBus, create_handoff_message, create_message
from app.services.agents.llm import LLMClient, LLMResponse, LLMSettings
from app.services.agents.notebook import Notebook
from app.services.agents.planner import PlanState
from app.services.agents.registry import AgentDefinition, filter_tools_for_agent, get_agent_or_default
from app.services.agents.tools import TOOL_SCHEMAS, ToolContext, execute_tool

logger = logging.getLogger(__name__)

MIN_BUDGET = 2
MAX_BUDGET = 15
DEFAULT_BUDGET = 5


@dataclass
class HandoffContext:
    """Structured context passed between agents during handoff."""

    source_agent: str
    target_agent: str
    task_description: str
    prior_findings: list[dict]
    investigated_topics: list[str]
    parent_notebook_summary: str
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    urgency: str = "normal"  # normal | high | critical
    max_budget: int = 5


@dataclass
class DelegationRequest:
    """Describes what to delegate to a sub-agent."""
    agent_id: str
    task_description: str
    budget: int = DEFAULT_BUDGET
    extra_context: str = ""


@dataclass
class DelegationResult:
    """Result from a sub-agent delegation."""
    agent_id: str
    response: str
    tool_trace: list[dict]
    steps_used: int
    notebook_entries: list[dict]


async def delegate(
    request: DelegationRequest,
    llm: LLMClient,
    tool_ctx: ToolContext,
    parent_notebook: Notebook | None = None,
) -> DelegationResult:
    """Run a sub-agent with a scoped task and return its result."""
    budget = max(MIN_BUDGET, min(MAX_BUDGET, request.budget))
    agent = get_agent_or_default(request.agent_id)
    child_notebook = Notebook()

    # Build scoped system prompt
    system_prompt = (
        f"{agent.system_prompt}\n\n"
        f"── DELEGATED TASK ──\n"
        f"{request.task_description}\n"
    )
    if request.extra_context:
        system_prompt += f"\n── ADDITIONAL CONTEXT ──\n{request.extra_context}\n"
    if parent_notebook:
        nb_ctx = parent_notebook.to_context_string()
        if nb_ctx:
            system_prompt += f"\n{nb_ctx}\n"

    system_prompt += (
        f"\nYou have a budget of {budget} tool calls. Use them wisely.\n"
        f"When you have enough information, synthesize your answer immediately.\n"
    )

    # Filter tools to agent's whitelist
    tools = filter_tools_for_agent(agent, TOOL_SCHEMAS)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": request.task_description},
    ]

    tool_trace = []
    plan_state = PlanState()

    for step in range(budget):
        resp: LLMResponse = await llm.chat(messages, tools=tools if llm.supports_tools else None)

        # No tool calls — agent is done
        if not resp.tool_calls:
            # Merge findings to parent notebook
            if parent_notebook:
                for entry in child_notebook.read_all():
                    parent_notebook.write(
                        key=f"[{agent.id}] {entry.key}",
                        value=entry.value,
                        source=f"delegate:{agent.id}",
                        tags=entry.tags,
                    )
                for finding in child_notebook.get_findings():
                    parent_notebook.add_finding(finding)

            return DelegationResult(
                agent_id=agent.id,
                response=resp.content or "",
                tool_trace=tool_trace,
                steps_used=step + 1,
                notebook_entries=[
                    {"key": e.key, "value": e.value, "source": e.source}
                    for e in child_notebook.read_all()
                ],
            )

        # Execute tool calls
        messages.append({"role": "assistant", "content": resp.content, "tool_calls": [
            {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": str(tc.arguments)}}
            for tc in resp.tool_calls
        ]})

        for tc in resp.tool_calls:
            # Stall detection
            if plan_state.record_call(tc.name, tc.arguments):
                logger.warning("Delegate %s stalled on %s — breaking", agent.id, tc.name)
                return DelegationResult(
                    agent_id=agent.id,
                    response=f"Investigation stalled after {step + 1} steps (repeated {tc.name} calls). "
                             f"Partial findings: {resp.content or 'none'}",
                    tool_trace=tool_trace,
                    steps_used=step + 1,
                    notebook_entries=[],
                )

            result = await execute_tool(tool_ctx, tc.name, tc.arguments)
            tool_trace.append({"tool": tc.name, "args": tc.arguments, "result_preview": result[:200]})

            # Record in child notebook
            child_notebook.write(key=tc.name, value=result[:500], source=f"tool:{tc.name}", tags=["tool_result"])

            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

    # Budget exhausted
    return DelegationResult(
        agent_id=agent.id,
        response=f"Sub-agent {agent.name} used full budget of {budget} steps. Last response: {resp.content or 'none'}",
        tool_trace=tool_trace,
        steps_used=budget,
        notebook_entries=[],
    )


async def delegate_stream(
    request: DelegationRequest,
    llm: LLMClient,
    tool_ctx: ToolContext,
    parent_notebook: Notebook | None = None,
) -> AsyncGenerator[dict, None]:
    """Streaming version of delegate — yields events as they happen."""
    agent = get_agent_or_default(request.agent_id)

    yield {"type": "delegate_start", "agent_id": agent.id, "agent_name": agent.name, "task": request.task_description}

    result = await delegate(request, llm, tool_ctx, parent_notebook)

    for trace in result.tool_trace:
        yield {"type": "delegate_tool", "agent_id": agent.id, "tool": trace["tool"]}

    yield {
        "type": "delegate_done",
        "agent_id": agent.id,
        "response": result.response,
        "steps_used": result.steps_used,
    }


# ---------------------------------------------------------------------------
# Structured handoff via message bus
# ---------------------------------------------------------------------------


def build_handoff_context(
    source_agent: str,
    target_agent: str,
    task: str,
    notebook: Notebook,
    correlation_id: str | None = None,
    urgency: str = "normal",
    max_budget: int = 5,
) -> HandoffContext:
    """Construct a :class:`HandoffContext` from a notebook and agent state."""
    findings = [
        {"key": f.key, "value": f.value, "severity": f.severity}
        for f in notebook.get_findings()
    ]
    investigated = [
        entry.key
        for entry in notebook.read_all()
        if "tool_result" in (entry.tags or [])
    ]
    return HandoffContext(
        source_agent=source_agent,
        target_agent=target_agent,
        task_description=task,
        prior_findings=findings,
        investigated_topics=investigated,
        parent_notebook_summary=notebook.to_context_string(),
        correlation_id=correlation_id or str(uuid.uuid4()),
        urgency=urgency,
        max_budget=max_budget,
    )


def _build_handoff_system_prompt(
    agent: AgentDefinition,
    handoff: HandoffContext,
) -> str:
    """Build a system prompt that includes handoff context so the child
    agent does not re-investigate already-covered topics."""
    parts = [agent.system_prompt]

    parts.append("\n── DELEGATED TASK (handoff) ──")
    parts.append(handoff.task_description)

    if handoff.prior_findings:
        parts.append("\n── PRIOR FINDINGS (do NOT re-investigate) ──")
        for f in handoff.prior_findings:
            parts.append(f"• [{f.get('severity', '?')}] {f.get('key', '?')}: {f.get('value', '')[:200]}")

    if handoff.investigated_topics:
        parts.append("\n── ALREADY INVESTIGATED (skip these) ──")
        parts.append(", ".join(handoff.investigated_topics))

    if handoff.parent_notebook_summary:
        parts.append(f"\n── PARENT NOTEBOOK ──\n{handoff.parent_notebook_summary}")

    parts.append(
        f"\nUrgency: {handoff.urgency}. "
        f"You have a budget of {handoff.max_budget} tool calls. "
        f"Focus only on new information. Synthesize quickly."
    )
    return "\n".join(parts)


async def structured_handoff(
    handoff: HandoffContext,
    bus: AgentBus,
    db,
    organization_id: int,
    llm_settings: LLMSettings,
    conversation_id: int,
) -> DelegationResult:
    """Execute a structured agent handoff via the message bus.

    1. Publishes handoff message to bus
    2. Spawns child agent with full context
    3. Child runs with scoped budget
    4. Returns result and publishes completion to bus
    """
    # Announce handoff on the bus
    await bus.send(
        create_handoff_message(
            from_agent=handoff.source_agent,
            to_agent=handoff.target_agent,
            task=handoff.task_description,
            context={
                "prior_findings": handoff.prior_findings,
                "investigated_topics": handoff.investigated_topics,
                "urgency": handoff.urgency,
            },
            conversation_id=conversation_id,
            correlation_id=handoff.correlation_id,
        )
    )
    bus.emit_sse({
        "type": "agent_handoff",
        "from": handoff.source_agent,
        "to": handoff.target_agent,
        "task": handoff.task_description,
    })

    # Build child LLM client and tool context
    llm = LLMClient(llm_settings)
    agent = get_agent_or_default(handoff.target_agent)

    parent_notebook = Notebook()
    if handoff.parent_notebook_summary:
        parent_notebook.write(
            key="parent_context",
            value=handoff.parent_notebook_summary,
            source=handoff.source_agent,
        )
    for f in handoff.prior_findings:
        parent_notebook.write(
            key=f.get("key", "finding"),
            value=f.get("value", ""),
            source=handoff.source_agent,
            tags=["prior_finding"],
        )

    extra_context = _build_handoff_system_prompt(agent, handoff)

    request = DelegationRequest(
        agent_id=handoff.target_agent,
        task_description=handoff.task_description,
        budget=handoff.max_budget,
        extra_context=extra_context,
    )

    tool_ctx = ToolContext(db=db, organization_id=organization_id)
    result = await delegate(request, llm, tool_ctx, parent_notebook)

    # Publish completion on the bus
    await bus.send(
        create_message(
            from_agent=handoff.target_agent,
            to_agent=handoff.source_agent,
            msg_type="result",
            payload={
                "response": result.response[:500],
                "steps_used": result.steps_used,
                "notebook_entries": result.notebook_entries,
            },
            conversation_id=conversation_id,
            correlation_id=handoff.correlation_id,
        )
    )
    bus.emit_sse({
        "type": "agent_complete",
        "agent": handoff.target_agent,
        "summary": result.response[:200],
    })

    return result


async def structured_handoff_stream(
    handoff: HandoffContext,
    bus: AgentBus,
    db,
    organization_id: int,
    llm_settings: LLMSettings,
    conversation_id: int,
) -> AsyncGenerator[dict, None]:
    """Streaming version of :func:`structured_handoff`.

    Yields SSE-compatible events as the child agent executes:
    ``agent_handoff``, ``agent_thinking``, ``tool_start``,
    ``tool_result``, ``agent_complete``.
    """
    # Announce handoff
    await bus.send(
        create_handoff_message(
            from_agent=handoff.source_agent,
            to_agent=handoff.target_agent,
            task=handoff.task_description,
            context={
                "prior_findings": handoff.prior_findings,
                "investigated_topics": handoff.investigated_topics,
                "urgency": handoff.urgency,
            },
            conversation_id=conversation_id,
            correlation_id=handoff.correlation_id,
        )
    )

    yield {
        "type": "agent_handoff",
        "from": handoff.source_agent,
        "to": handoff.target_agent,
        "task": handoff.task_description,
        "correlation_id": handoff.correlation_id,
    }

    # Build delegation request with handoff context
    agent = get_agent_or_default(handoff.target_agent)
    extra_context = _build_handoff_system_prompt(agent, handoff)

    parent_notebook = Notebook()
    if handoff.parent_notebook_summary:
        parent_notebook.write(
            key="parent_context",
            value=handoff.parent_notebook_summary,
            source=handoff.source_agent,
        )

    request = DelegationRequest(
        agent_id=handoff.target_agent,
        task_description=handoff.task_description,
        budget=handoff.max_budget,
        extra_context=extra_context,
    )

    llm = LLMClient(llm_settings)
    tool_ctx = ToolContext(db=db, organization_id=organization_id)

    yield {"type": "agent_thinking", "agent": handoff.target_agent}

    # Stream the inner delegation
    async for event in delegate_stream(request, llm, tool_ctx, parent_notebook):
        if event["type"] == "delegate_tool":
            yield {"type": "tool_start", "agent": handoff.target_agent, "tool": event["tool"]}
            yield {"type": "tool_result", "agent": handoff.target_agent, "tool": event["tool"]}
        elif event["type"] == "delegate_done":
            # Publish completion on the bus
            await bus.send(
                create_message(
                    from_agent=handoff.target_agent,
                    to_agent=handoff.source_agent,
                    msg_type="result",
                    payload={
                        "response": event["response"][:500],
                        "steps_used": event["steps_used"],
                    },
                    conversation_id=conversation_id,
                    correlation_id=handoff.correlation_id,
                )
            )
            yield {
                "type": "agent_complete",
                "agent": handoff.target_agent,
                "summary": event["response"][:200],
                "steps_used": event["steps_used"],
                "correlation_id": handoff.correlation_id,
            }

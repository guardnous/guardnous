"""Parallel Agent Executor for GuardNous (Project AEGIS).

Runs multiple agents concurrently with DAG-based dependency awareness.
Converts an AgentExecutionPlan into parallel AgentTasks, respects
dependency ordering, and streams SSE events as agents work.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.services.agents.bus import AgentBus

if TYPE_CHECKING:
    from app.services.agents.llm import LLMSettings
    from app.services.agents.planner import AgentExecutionPlan

logger = logging.getLogger(__name__)


# ── Data classes ────────────────────────────────────────────────────


@dataclass
class AgentTask:
    """A single unit of work to be executed by an agent."""

    agent_id: str
    task_description: str
    tool_whitelist: list[str] | None = None
    depends_on: list[str] = field(default_factory=list)
    max_budget: int = 5
    priority: int = 0  # higher = runs first among ready tasks


@dataclass
class AgentTaskResult:
    """Outcome of a single agent task execution."""

    agent_id: str
    success: bool
    result: str
    findings: list[dict]
    tools_used: list[str]
    duration_ms: int
    error: str | None = None


# ── Parallel executor ───────────────────────────────────────────────


class ParallelExecutor:
    """Execute agent tasks concurrently, respecting a DAG of dependencies."""

    def __init__(self, bus: AgentBus, max_concurrency: int = 4) -> None:
        self._bus = bus
        self._max_concurrency = max_concurrency
        self._results: dict[str, AgentTaskResult] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def execute_plan(
        self,
        tasks: list[AgentTask],
        db,
        organization_id: int,
        llm_settings: "LLMSettings",
        conversation_id: int,
    ) -> dict[str, AgentTaskResult]:
        """Execute a set of agent tasks respecting dependencies.

        Uses a DAG-based scheduler:
        1. Find tasks with all dependencies satisfied
        2. Run them concurrently (up to max_concurrency)
        3. As tasks complete, unlock dependents
        4. Repeat until all done or deadlock
        """
        self._results.clear()

        completed: set[str] = set()
        started: set[str] = set()
        events: dict[str, asyncio.Event] = {
            t.agent_id: asyncio.Event() for t in tasks
        }
        pending_futures: set[asyncio.Task] = set()

        while len(completed) < len(tasks):
            # Find tasks whose dependencies are all satisfied and not yet started
            ready = [
                t
                for t in tasks
                if t.agent_id not in started
                and all(dep in completed for dep in t.depends_on)
            ]
            ready.sort(key=lambda t: t.priority, reverse=True)

            if not ready and not pending_futures:
                remaining = {
                    t.agent_id for t in tasks if t.agent_id not in completed
                }
                raise RuntimeError(
                    f"Deadlock: no tasks are ready and none are running. "
                    f"Blocked tasks: {remaining}"
                )

            for task in ready:
                started.add(task.agent_id)
                parent_results = {
                    dep: self._results[dep]
                    for dep in task.depends_on
                    if dep in self._results
                }

                async def _wrapped(
                    t: AgentTask = task,
                    pr: dict = parent_results,
                ) -> None:
                    await self._semaphore.acquire()
                    try:
                        self._bus.emit_sse(
                            {
                                "type": "agent_spawn",
                                "agent_id": t.agent_id,
                                "task": t.task_description,
                                "depends_on": t.depends_on,
                            }
                        )
                        result = await self._run_single_agent(
                            t, db, organization_id, llm_settings,
                            conversation_id, pr,
                        )
                        self._results[t.agent_id] = result
                        self._bus.emit_sse(
                            {
                                "type": "agent_complete",
                                "agent_id": t.agent_id,
                                "success": result.success,
                                "finding_count": len(result.findings),
                                "duration_ms": result.duration_ms,
                            }
                        )
                    except Exception as exc:
                        logger.exception("Agent %s failed unexpectedly", t.agent_id)
                        self._results[t.agent_id] = AgentTaskResult(
                            agent_id=t.agent_id,
                            success=False,
                            result="",
                            findings=[],
                            tools_used=[],
                            duration_ms=0,
                            error=str(exc),
                        )
                    finally:
                        self._semaphore.release()
                        completed.add(t.agent_id)
                        events[t.agent_id].set()

                pending_futures.add(asyncio.create_task(_wrapped()))

            if pending_futures:
                done, pending_futures = await asyncio.wait(
                    pending_futures, return_when=asyncio.FIRST_COMPLETED
                )
                for fut in done:
                    if fut.exception():
                        logger.error("Task future raised: %s", fut.exception())

        return dict(self._results)

    async def execute_plan_stream(
        self,
        tasks: list[AgentTask],
        db,
        organization_id: int,
        llm_settings: "LLMSettings",
        conversation_id: int,
    ) -> AsyncIterator[dict]:
        """Streaming version that yields SSE events as agents work."""
        self._results.clear()

        completed: set[str] = set()
        started: set[str] = set()
        events: dict[str, asyncio.Event] = {
            t.agent_id: asyncio.Event() for t in tasks
        }
        pending_futures: set[asyncio.Task] = set()

        yield {
            "type": "progress",
            "message": f"Starting execution of {len(tasks)} agent tasks",
            "done": 0,
            "total": len(tasks),
        }

        while len(completed) < len(tasks):
            ready = [
                t
                for t in tasks
                if t.agent_id not in started
                and all(dep in completed for dep in t.depends_on)
            ]
            ready.sort(key=lambda t: t.priority, reverse=True)

            if not ready and not pending_futures:
                remaining = {
                    t.agent_id for t in tasks if t.agent_id not in completed
                }
                yield {
                    "type": "error",
                    "message": f"Deadlock detected. Blocked tasks: {remaining}",
                }
                return

            for task in ready:
                started.add(task.agent_id)
                parent_results = {
                    dep: self._results[dep]
                    for dep in task.depends_on
                    if dep in self._results
                }

                yield {
                    "type": "agent_spawn",
                    "agent_id": task.agent_id,
                    "task": task.task_description,
                    "depends_on": task.depends_on,
                }

                async def _wrapped(
                    t: AgentTask = task,
                    pr: dict = parent_results,
                ) -> None:
                    await self._semaphore.acquire()
                    try:
                        result = await self._run_single_agent(
                            t, db, organization_id, llm_settings,
                            conversation_id, pr,
                        )
                        self._results[t.agent_id] = result
                        self._bus.emit_sse(
                            {
                                "type": "agent_complete",
                                "agent_id": t.agent_id,
                                "success": result.success,
                                "finding_count": len(result.findings),
                                "duration_ms": result.duration_ms,
                                "tools_used": result.tools_used,
                            }
                        )
                    except Exception as exc:
                        logger.exception("Agent %s failed unexpectedly", t.agent_id)
                        self._results[t.agent_id] = AgentTaskResult(
                            agent_id=t.agent_id,
                            success=False,
                            result="",
                            findings=[],
                            tools_used=[],
                            duration_ms=0,
                            error=str(exc),
                        )
                        self._bus.emit_sse(
                            {
                                "type": "agent_complete",
                                "agent_id": t.agent_id,
                                "success": False,
                                "error": str(exc),
                            }
                        )
                    finally:
                        self._semaphore.release()
                        completed.add(t.agent_id)
                        events[t.agent_id].set()

                pending_futures.add(asyncio.create_task(_wrapped()))

            if pending_futures:
                done, pending_futures = await asyncio.wait(
                    pending_futures, return_when=asyncio.FIRST_COMPLETED
                )
                for fut in done:
                    if fut.exception():
                        logger.error("Task future raised: %s", fut.exception())

            # Drain SSE events emitted during agent execution
            for sse_event in self._bus.drain_sse_events():
                yield sse_event

            yield {
                "type": "progress",
                "done": len(completed),
                "total": len(tasks),
                "running": [
                    aid for aid in started if aid not in completed
                ],
            }

        # Final drain
        for sse_event in self._bus.drain_sse_events():
            yield sse_event

        yield {
            "type": "progress",
            "message": "All agent tasks completed",
            "done": len(completed),
            "total": len(tasks),
        }

    async def _run_single_agent(
        self,
        task: AgentTask,
        db,
        organization_id: int,
        llm_settings: "LLMSettings",
        conversation_id: int,
        parent_results: dict[str, AgentTaskResult],
    ) -> AgentTaskResult:
        """Run a single agent task with budget and context from parent results."""
        from app.services.agents.delegate import DelegationRequest, delegate
        from app.services.agents.llm import LLMClient
        from app.services.agents.notebook import Notebook
        from app.services.agents.tools import ToolContext

        start_ms = _now_ms()

        # Build context from upstream dependency results
        context_parts: list[str] = []
        for dep_id, dep_result in parent_results.items():
            context_parts.append(
                f"── Results from {dep_id} ──\n"
                f"Success: {dep_result.success}\n"
                f"Summary: {dep_result.result[:500]}\n"
            )
            if dep_result.findings:
                context_parts.append(
                    f"Findings ({len(dep_result.findings)}):\n"
                    + "\n".join(
                        f"  - {f.get('title', f.get('summary', str(f)))}"
                        for f in dep_result.findings[:10]
                    )
                )

        extra_context = "\n\n".join(context_parts) if context_parts else ""

        try:
            llm = LLMClient(settings=llm_settings)
            tool_ctx = ToolContext(
                db=db,
                organization_id=organization_id,
                conversation_id=conversation_id,
            )
            notebook = Notebook()

            req = DelegationRequest(
                agent_id=task.agent_id,
                task_description=task.task_description,
                budget=task.max_budget,
                extra_context=extra_context,
            )

            result = await delegate(
                request=req,
                llm=llm,
                tool_ctx=tool_ctx,
                parent_notebook=notebook,
            )

            duration_ms = _now_ms() - start_ms
            tools_used = [
                entry.get("tool", "") for entry in result.tool_trace
                if entry.get("tool")
            ]
            findings = result.notebook_entries

            return AgentTaskResult(
                agent_id=task.agent_id,
                success=True,
                result=result.response,
                findings=findings,
                tools_used=tools_used,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = _now_ms() - start_ms
            logger.exception("Agent %s execution error", task.agent_id)
            return AgentTaskResult(
                agent_id=task.agent_id,
                success=False,
                result="",
                findings=[],
                tools_used=[],
                duration_ms=duration_ms,
                error=str(exc),
            )


# ── Helpers ─────────────────────────────────────────────────────────


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


def build_task_graph(plan: "AgentExecutionPlan") -> list[AgentTask]:
    """Convert an AgentExecutionPlan (from planner.py) into AgentTasks.

    Maps plan step numbers to agent_ids and wires up ``depends_on``
    using the step-number → agent_id mapping.
    """

    step_num_to_id: dict[int, str] = {}
    tasks: list[AgentTask] = []

    for step in plan.steps:
        agent_id = step.agent_id or f"agent_step_{step.number}"
        step_num_to_id[step.number] = agent_id

    for step in plan.steps:
        agent_id = step_num_to_id[step.number]
        depends_on = [
            step_num_to_id[dep]
            for dep in step.depends_on
            if dep in step_num_to_id
        ]
        tool_whitelist = [step.tool] if step.tool else None

        tasks.append(
            AgentTask(
                agent_id=agent_id,
                task_description=step.description,
                tool_whitelist=tool_whitelist,
                depends_on=depends_on,
                max_budget=5,
                priority=len(plan.steps) - step.number,
            )
        )

    return tasks

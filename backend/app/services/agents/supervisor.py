"""Supervisor meta-agent for GuardNous (Project AEGIS).

Decomposes complex user queries into multi-agent execution plans
and orchestrates parallel/sequential execution across specialist agents.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import TYPE_CHECKING, AsyncIterator

if TYPE_CHECKING:
    from app.services.agents.agent_state import ConversationContext
    from app.services.agents.bus import AgentBus
    from app.services.agents.llm import LLMClient, LLMSettings
    from app.services.agents.planner import AgentExecutionPlan, ExecutionStep

logger = logging.getLogger(__name__)

# ── Prompts ─────────────────────────────────────────────────────────

SUPERVISOR_SYSTEM_PROMPT = """\
You are the Supervisor — the orchestration brain of Project AEGIS, an AI-powered security operations platform.

Your role: decompose complex security queries into multi-agent execution plans.

Available specialist agents (use their IDs):
- security_analyst: Findings analysis, severity assessment, risk scoring
- compliance_advisor: Framework mapping, compliance gap analysis
- devsecops_coach: Code security, CI/CD pipeline hardening
- threat_intel: Threat intelligence, IOC enrichment, MITRE ATT&CK mapping
- triage_agent: Incident triage, priority assessment
- remediation_agent: Fix generation, remediation playbooks
- investigation_agent: Deep-dive forensics, root cause analysis
- incident_commander: Multi-agent incident coordination
- cloud_architect: Cloud security posture, IAM, encryption
- vulnerability_manager: Vulnerability lifecycle, SLA tracking
- policy_engineer: Policy authoring, guardrail configuration
- secrets_detective: Secrets detection, rotation guidance
- supply_chain_guardian: Dependency analysis, SBOM review
- pentest_advisor: Offensive security guidance
- soc_analyst: Alert correlation, SIEM analysis
- data_protection_officer: Data classification, privacy compliance
- cost_optimizer: Security spend optimization
- executive_briefer: C-level summaries, board-ready reports
- automation_engineer: Workflow automation, playbook creation

Planning rules:
1. Simple queries (single topic) → route to ONE specialist, no plan needed
2. Medium queries (2-3 topics) → sequential plan with 2-3 agents
3. Complex queries (multi-faceted) → DAG plan with parallel + sequential agents
4. Always include a synthesis step at the end
5. Don't over-plan — if 1 agent can handle it, use 1 agent

Output JSON format:
{"complexity": "simple|medium|complex", "plan": {"steps": [{"number": 1, "description": "...", "agent": "agent_id", "depends_on": []}], "strategy": "single|sequential|dag"}, "reasoning": "why this plan"}
"""

SYNTHESIS_PROMPT = """\
You are synthesizing results from multiple specialist agents into ONE coherent response.

Agent results:
{agent_results}

Rules:
1. Merge overlapping findings — don't repeat the same issue from different agents
2. Prioritize by severity (Critical > High > Medium > Low)
3. Use markdown: headings, tables for comparable items, code blocks
4. End with a prioritized action plan
5. Do not mention the agents or how the answer was produced
6. Be thorough but concise — executives will read this
"""

# Words per topic — a simple heuristic to gauge complexity without LLM.
_SIMPLE_MAX_WORDS = 25

SUPERVISOR_ID = "supervisor"
SUPERVISOR_NAME = "Supervisor"
_HANDOFF_TEXT_LIMIT = 200
_PLAN_TEXT_LIMIT = 300


def _event_text(text: str | None, limit: int = _HANDOFF_TEXT_LIMIT) -> str:
    """Model-written text for a browser event: sanitized, one line, cut to *limit*."""
    from app.services.agents.guardrails import sanitize_output

    clean = " ".join((sanitize_output(text or "") or "").split())
    return clean if len(clean) <= limit else clean[: limit - 1].rstrip() + "…"


def _safe_answer(text: str) -> str:
    """The answer as it may be shown: secrets, internal paths and personal data
    removed, and no reasoning labels. Same treatment as a single-agent answer."""
    from app.services.agents.guardrails import sanitize_output
    from app.services.agents.planner import clean_answer

    return clean_answer(sanitize_output(text or ""))

# ── Supervisor ──────────────────────────────────────────────────────


class Supervisor:
    """Meta-agent that plans and orchestrates multi-agent execution."""

    def __init__(self, bus: AgentBus, llm: LLMClient) -> None:
        from app.services.agents.planner import PlanAndExecutePlanner

        self._bus = bus
        self._llm = llm
        self._planner = PlanAndExecutePlanner()

    # ── planning ────────────────────────────────────────────────────

    async def analyze_and_plan(
        self,
        user_message: str,
        history: list[dict],
        conversation_context: ConversationContext | None = None,
    ) -> AgentExecutionPlan:
        """Decompose *user_message* into an :class:`AgentExecutionPlan`.

        1. Send ``SUPERVISOR_SYSTEM_PROMPT`` + user message to the LLM.
        2. Parse the JSON response.
        3. Validate that referenced agent IDs exist in the registry.
        4. Return the plan (falls back to single-agent on parse failure).
        """
        from app.services.agents.registry import get_agent_or_default

        if self._is_simple_query(user_message):
            logger.info("Simple query detected — skipping LLM planning")
            return self._planner.create_simple_plan(
                goal=user_message, agent_id="security_analyst",
            )

        messages: list[dict] = [
            {"role": "system", "content": SUPERVISOR_SYSTEM_PROMPT},
        ]
        # Include recent history for context (last 6 turns max).
        for turn in history[-6:]:
            messages.append(turn)
        messages.append({"role": "user", "content": user_message})

        try:
            response = await self._llm.chat(messages)
            raw_text = response.content if hasattr(response, "content") else str(response)
            plan_json = self._extract_json(raw_text)
        except Exception:
            logger.exception("LLM planning call failed — falling back to single agent")
            return self._planner.create_simple_plan(
                goal=user_message, agent_id="security_analyst",
            )

        if plan_json is None:
            logger.warning("Could not parse plan JSON from LLM output — single-agent fallback")
            return self._planner.create_simple_plan(
                goal=user_message, agent_id="security_analyst",
            )

        # Validate agent IDs — replace unknown agents with security_analyst.
        for step in plan_json.get("plan", {}).get("steps", []):
            agent_id = step.get("agent")
            if agent_id:
                defn = get_agent_or_default(agent_id)
                if defn.id != agent_id:
                    logger.warning("Unknown agent '%s' in plan — replaced with '%s'", agent_id, defn.id)
                    step["agent"] = defn.id

        plan_body = plan_json.get("plan", plan_json)
        plan = self._planner.create_plan_from_llm_response(plan_body, goal=user_message)

        complexity = plan_json.get("complexity", "medium")
        reasoning = plan_json.get("reasoning", "")
        logger.info(
            "Supervisor plan: complexity=%s, strategy=%s, steps=%d — %s",
            complexity, plan.strategy, len(plan.steps), reasoning,
        )
        return plan

    # ── execution ───────────────────────────────────────────────────

    async def execute_and_stream(
        self,
        plan: AgentExecutionPlan,
        db,
        organization_id: int,
        llm_settings: LLMSettings,
        conversation_id: int,
    ) -> AsyncIterator[dict]:
        """Execute *plan* and yield SSE-compatible event dicts.

        1. Emit the plan event.
        2. Walk steps respecting dependencies (ready_steps).
        3. For each step, delegate to the assigned agent and stream results.
        4. After all steps complete, run synthesis and emit tokens.
        5. Emit ``done`` event.
        """
        from app.services.agents.llm import LLMClient
        from app.services.agents.registry import get_agent_or_default

        # 1. Plan event. Each step also names the agent that will really run it.
        plan_event = plan.to_sse_event()
        for item, step in zip(plan_event["steps"], plan.steps):
            item["description"] = _event_text(step.description, limit=_PLAN_TEXT_LIMIT)
            item["agent_name"] = get_agent_or_default(step.agent_id).name
        yield plan_event

        multi_agent = len(plan.steps) > 1
        step_results: dict[int, str] = {}

        # 2-3. Execute steps respecting DAG ordering.
        while not plan.is_complete():
            ready = plan.ready_steps()
            if not ready:
                logger.error("Deadlock detected — no ready steps but plan incomplete")
                break

            for step in ready:
                step.status = "running"
                yield {
                    "type": "step_start",
                    "step": step.number,
                    "agent": step.agent_id,
                    "description": step.description,
                }

                # Events the chat page receives. The supervisor hands the step's
                # task to the agent; nothing else is passed along, so the task is
                # the whole context of the handoff.
                agent_def = get_agent_or_default(step.agent_id)
                task = _event_text(step.description)
                if multi_agent:
                    yield {
                        "type": "agent_handoff",
                        "from": SUPERVISOR_ID,
                        "from_name": SUPERVISOR_NAME,
                        "to": agent_def.id,
                        "to_name": agent_def.name,
                        "task": task,
                        "step": step.number,
                    }
                yield {
                    "type": "agent_spawn",
                    "agent_id": agent_def.id,
                    "agent_name": agent_def.name,
                    "task": task,
                    "step": step.number,
                    "depends_on": list(step.depends_on),
                }

                started = time.monotonic()
                result_text = await self._run_step(
                    step, db, organization_id, llm_settings, conversation_id,
                )
                succeeded = step.status != "failed"       # _run_step marks a failed call
                step.result = result_text
                step.status = "done"
                step_results[step.number] = result_text

                yield {
                    "type": "agent_complete",
                    "agent_id": agent_def.id,
                    "agent_name": agent_def.name,
                    "step": step.number,
                    "success": succeeded,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }

                yield {
                    "type": "step_done",
                    "step": step.number,
                    "agent": step.agent_id,
                    "preview": (result_text or "")[:300],
                }

        # 4. Synthesis
        if len(step_results) > 1:
            agent_results_map: dict[str, str] = {}
            for step in plan.steps:
                key = step.agent_id or f"step_{step.number}"
                agent_results_map[key] = step.result or ""

            llm = LLMClient(llm_settings)
            # The answer is collected first so the output filter sees whole secrets
            # and paths, not pieces of them split across tokens; then it is sent on.
            written = [token async for token in self.synthesize(plan.goal, agent_results_map, llm)]
            for word in _safe_answer("".join(written)).split(" "):
                yield {"type": "token", "content": word + " ", "source": "supervisor"}
        elif step_results:
            only_result = next(iter(step_results.values()))
            yield {"type": "token", "content": _safe_answer(only_result or ""), "source": "agent"}

        # 5. Done
        done_count, total_count = plan.progress()
        yield {
            "type": "done",
            "steps_completed": done_count,
            "steps_total": total_count,
            "provider": LLMClient(llm_settings).info(),
        }

    # ── synthesis ───────────────────────────────────────────────────

    async def synthesize(
        self,
        goal: str,
        results: dict[str, str],
        llm: LLMClient,
    ) -> AsyncIterator[str]:
        """Combine all agent results into a unified response via streaming LLM."""
        formatted_results = "\n\n".join(
            f"### {agent_id}\n{text}" for agent_id, text in results.items() if text
        )
        from app.services.agents.planner import REACT_GROUNDING

        prompt = SYNTHESIS_PROMPT.format(agent_results=formatted_results) + REACT_GROUNDING

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"Synthesize the above agent results for this goal: {goal}"},
        ]

        try:
            async for token in llm.chat_stream(messages):
                yield token
        except Exception:
            logger.exception("Synthesis streaming failed — returning concatenated results")
            yield "\n\n---\n\n".join(
                f"**{aid}**: {txt}" for aid, txt in results.items() if txt
            )

    # ── helpers ─────────────────────────────────────────────────────

    def _is_simple_query(self, user_message: str) -> bool:
        """Heuristic: short, single-topic messages skip LLM planning."""
        words = user_message.split()
        if len(words) <= _SIMPLE_MAX_WORDS:
            return True
        # Multiple question marks or conjunctions hint at multi-part queries.
        if user_message.count("?") > 1 or " and " in user_message.lower():
            return False
        return len(words) <= _SIMPLE_MAX_WORDS

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        """Best-effort extraction of the first JSON object from LLM output."""
        # Try the full text first.
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try inside ```json fences.
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Find first { … } block.
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    async def _run_step(
        self,
        step: ExecutionStep,
        db,
        organization_id: int,
        llm_settings: LLMSettings,
        conversation_id: int,
    ) -> str:
        """Execute a single plan step by delegating to the designated agent."""
        from app.services.agents.llm import LLMClient
        from app.services.agents.registry import get_agent_or_default

        agent_def = get_agent_or_default(step.agent_id)
        agent_llm = LLMClient(llm_settings)

        messages = [
            {"role": "system", "content": agent_def.system_prompt},
            {"role": "user", "content": step.description},
        ]

        try:
            response = await agent_llm.chat(messages)
            return response.content if hasattr(response, "content") else str(response)
        except Exception:
            logger.exception("Step %d (%s) failed", step.number, agent_def.id)
            step.status = "failed"
            step.error = "Agent execution failed"
            return f"[Error: {agent_def.name} could not complete this step]"


# ── Convenience entry-point ─────────────────────────────────────────


async def run_supervised(
    db,
    organization_id: int,
    history: list[dict],
    llm_settings: LLMSettings,
    conversation_id: int,
    bus: AgentBus | None = None,
) -> AsyncIterator[dict]:
    """Full supervised agentic flow — the main entry point.

    1. Create bus if not provided.
    2. Create :class:`Supervisor`.
    3. Build an execution plan.
    4. Execute with streaming, yielding SSE events.
    """
    from app.services.agents.bus import AgentBus
    from app.services.agents.llm import LLMClient

    if bus is None:
        bus = AgentBus()

    llm = LLMClient(llm_settings)
    supervisor = Supervisor(bus=bus, llm=llm)

    user_message = ""
    for msg in reversed(history):
        if msg.get("role") == "user":
            user_message = msg.get("content", "")
            break

    if not user_message:
        yield {"type": "error", "message": "No user message found in history"}
        return

    # Plan
    plan = await supervisor.analyze_and_plan(user_message, history)

    # Execute & stream
    async for event in supervisor.execute_and_stream(
        plan, db, organization_id, llm_settings, conversation_id,
    ):
        yield event

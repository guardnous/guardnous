"""ReAct Planner — goal-directed reasoning with reflection and stall detection.

Implements the ReAct (Reasoning + Acting) loop pattern:
  Thought → Action → Observation → Reflection → next Thought

Adds stall detection (same tool called 3+ times with same args),
goal tracking, and grounding checks to prevent agent loops.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PlanStep:
    """A single step in the execution plan."""
    thought: str
    action: str | None = None    # tool name
    args: dict | None = None
    observation: str | None = None
    reflection: str | None = None
    status: str = "pending"      # pending / executing / done / skipped


@dataclass
class PlanState:
    """Tracks the current planning state across the agentic loop."""
    steps: list[PlanStep] = field(default_factory=list)
    _call_hashes: list[str] = field(default_factory=list)
    stall_count: int = 0
    max_stall: int = 2           # stall after 2 repeated identical calls
    iteration: int = 0

    def record_call(self, tool_name: str, args: dict) -> bool:
        """Record a tool call and check for stalls.

        Returns True if the call is a stall (repeated identical call).
        """
        h = hashlib.md5(f"{tool_name}:{sorted(args.items()) if args else ''}".encode()).hexdigest()
        if h in self._call_hashes[-5:]:
            self.stall_count += 1
            if self.stall_count >= self.max_stall:
                logger.warning("Stall detected: %s called %d times with same args", tool_name, self.stall_count + 1)
                return True
        else:
            self.stall_count = 0
        self._call_hashes.append(h)
        self.iteration += 1
        return False

    def add_step(self, thought: str) -> PlanStep:
        step = PlanStep(thought=thought)
        self.steps.append(step)
        return step

    def current_step(self) -> PlanStep | None:
        for s in self.steps:
            if s.status == "pending":
                return s
        return None

    def all_done(self) -> bool:
        return all(s.status in ("done", "skipped") for s in self.steps)


# ── Grounding prompt injection ──────────────────────────────────────

REACT_GROUNDING = """\

## HOW TO WORK AND HOW TO ANSWER (these rules override anything above)

Work silently. Decide which tools you need, call them, and write nothing
until you are ready to answer. Do not call the same tool twice with the same
arguments. Stop calling tools as soon as you can answer.

Your reply is read by a person in a chat window. Write only the answer.

- Never write "Thought", "Action", "Observation", "Reflection" or any other
  label for your own reasoning.
- Never describe your process: no "Let me check", "I now have a
  comprehensive picture", "Let me synthesize", "Based on my analysis",
  "I called the tool".
- Start with the answer itself. The first sentence should already tell the
  reader the most important thing.
- Match the length to the question. A short question gets a few sentences.
  A report gets short sections with plain headings.
- Write the way a senior engineer talks to a colleague: plain words, full
  sentences, specific names and numbers from the data.
- No emoji, in headings or anywhere else. Write severity as a word
  (Critical, High, Medium, Low).
- No urgency theatre: no capitals for emphasis, no exclamation marks, no
  "NOW", "devastating", "immediately!".
- Use a table only for items compared on the same attributes. Use numbered
  lists only for steps done in order.
- Say plainly when something is unknown or was not checked. Never invent
  data.
- End when the answer is complete. At most one short closing line offering
  a specific next step; no generic "let me know if you need anything".
"""

_REASONING_LABEL = re.compile(
    r"^\s*(?:[*_#>\-\s]*)(?:thought|action|observation|reflection|reasoning|plan)s?\s*(?:[*_]*)\s*:",
    re.IGNORECASE,
)
_RULE_LINE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")


def clean_answer(text: str) -> str:
    """Remove reasoning scaffolding a model wrote before its answer.

    Some models open with paragraphs such as ``**Observation:** I now have the
    full picture…`` even when told not to. Those opening paragraphs (and a rule
    line after them) are dropped; the answer itself is never touched.
    """
    if not text:
        return text
    paragraphs = re.split(r"\n\s*\n", text.strip())
    while len(paragraphs) > 1 and (_REASONING_LABEL.match(paragraphs[0]) or _RULE_LINE.match(paragraphs[0])):
        paragraphs.pop(0)
    if _REASONING_LABEL.match(paragraphs[0]):          # only a labelled paragraph: keep its text, drop the label
        paragraphs[0] = _REASONING_LABEL.sub("", paragraphs[0], count=1).lstrip()
    return "\n\n".join(paragraphs)


def build_react_context(state: PlanState) -> str:
    """Build a context injection string showing planning state."""
    if not state.steps:
        return ""

    parts = ["── Plan Progress ──"]
    for i, step in enumerate(state.steps, 1):
        status_icon = {"pending": "☐", "executing": "⏳", "done": "✅", "skipped": "⏭"}.get(step.status, "?")
        parts.append(f"{status_icon} Step {i}: {step.thought}")
        if step.observation:
            parts.append(f"   → {step.observation[:100]}")

    if state.stall_count > 0:
        parts.append(f"\n⚠️ Stall warning: {state.stall_count} repeated calls detected")

    return "\n".join(parts)


# ── Plan-and-Execute planner ────────────────────────────────────────


@dataclass
class ExecutionStep:
    """A single step in a plan-and-execute execution plan."""
    number: int
    description: str
    agent_id: str | None = None
    tool: str | None = None
    tool_args: dict | None = None
    depends_on: list[int] = field(default_factory=list)
    status: str = "pending"      # pending | running | done | failed | skipped | replanned
    result: str | None = None
    error: str | None = None


@dataclass
class AgentExecutionPlan:
    """Full execution plan produced by the planning phase."""
    goal: str
    steps: list[ExecutionStep] = field(default_factory=list)
    current_step: int = 0
    revisions: int = 0
    strategy: str = "sequential"  # sequential | parallel | dag
    created_at: float = field(default_factory=time.time)

    def ready_steps(self) -> list[ExecutionStep]:
        """Return steps whose dependencies are all done."""
        done_nums = {s.number for s in self.steps if s.status == "done"}
        return [
            s for s in self.steps
            if s.status == "pending" and all(d in done_nums for d in s.depends_on)
        ]

    def is_complete(self) -> bool:
        return all(s.status in ("done", "skipped") for s in self.steps)

    def progress(self) -> tuple[int, int]:
        done = sum(1 for s in self.steps if s.status in ("done", "skipped"))
        return done, len(self.steps)

    def to_sse_event(self) -> dict:
        """Build an SSE-friendly representation of the plan."""
        done, total = self.progress()
        return {
            "type": "plan",
            "goal": self.goal,
            "strategy": self.strategy,
            "steps": [
                {
                    "step": s.number,
                    "description": s.description,
                    "agent": s.agent_id,
                    "tool": s.tool,
                    "status": s.status,
                    "depends_on": s.depends_on,
                }
                for s in self.steps
            ],
            "progress": {"done": done, "total": total},
            "revisions": self.revisions,
        }


# ── Planning prompt ─────────────────────────────────────────────────

PLAN_PROMPT = """\
You are a planning engine. Given a user's goal and available tools, create a numbered execution plan.

Rules:
1. Each step should be a single, concrete action
2. Steps can depend on prior steps (for sequential ordering)
3. Independent steps should have no dependencies (can run in parallel)
4. Keep plans concise — 3-7 steps for most queries
5. Assign each step to the most appropriate agent if multiple are available

Output JSON:
{"steps": [{"number": 1, "description": "...", "agent": "security_analyst", \
"tool": "list_findings", "depends_on": []}, ...], "strategy": "dag"}
"""


PLAN_AND_EXECUTE_GROUNDING = """\

── PLAN-AND-EXECUTE PROTOCOL ──
Phase 1 — PLAN: Decompose the user's goal into numbered steps.
Phase 2 — EXECUTE: Run each step, observe results, revise if needed.
Phase 3 — SYNTHESIZE: Combine all step results into a coherent response.

If a step fails or reveals unexpected information, you may REPLAN —
adjust remaining steps based on new knowledge.
"""


# ── Planner implementation ──────────────────────────────────────────

class PlanAndExecutePlanner:
    """Plan-and-Execute planner with replanning support.

    Creates structured execution plans from LLM output and tracks
    progress, using the existing PlanState for stall detection.
    """

    def __init__(self) -> None:
        self._react_state = PlanState()

    def create_plan_from_llm_response(
        self, llm_json: dict, goal: str,
    ) -> AgentExecutionPlan:
        """Parse LLM JSON output into a structured plan."""
        raw_steps = llm_json.get("steps", [])
        strategy = llm_json.get("strategy", "sequential")

        steps: list[ExecutionStep] = []
        for raw in raw_steps:
            try:
                step = ExecutionStep(
                    number=int(raw.get("number", len(steps) + 1)),
                    description=str(raw.get("description", "")),
                    agent_id=raw.get("agent"),
                    tool=raw.get("tool"),
                    tool_args=raw.get("tool_args"),
                    depends_on=[int(d) for d in raw.get("depends_on", [])],
                )
                steps.append(step)
            except (TypeError, ValueError) as exc:
                logger.warning("Skipping malformed plan step: %s — %s", raw, exc)
                continue

        if not steps:
            logger.warning("LLM returned empty plan for goal: %s — creating fallback", goal)
            steps = [ExecutionStep(number=1, description=goal)]

        return AgentExecutionPlan(
            goal=goal, steps=steps, strategy=strategy,
        )

    def create_simple_plan(
        self,
        goal: str,
        tool: str | None = None,
        agent_id: str | None = None,
    ) -> AgentExecutionPlan:
        """Create a single-step plan for simple queries."""
        step = ExecutionStep(
            number=1,
            description=goal,
            agent_id=agent_id,
            tool=tool,
        )
        return AgentExecutionPlan(goal=goal, steps=[step])

    def should_replan(
        self,
        plan: AgentExecutionPlan,
        step: ExecutionStep,
        observation: str,
    ) -> bool:
        """After each step, check if the plan needs revision.

        Returns True if: step failed, observation reveals unexpected
        information, or a stall is detected.
        """
        if step.status == "failed":
            return True

        if step.tool:
            args = step.tool_args or {}
            if self._react_state.record_call(step.tool, args):
                logger.warning("Replan triggered by stall on tool %s", step.tool)
                return True

        unexpected_markers = ("error", "not found", "unexpected", "denied", "failed")
        obs_lower = observation.lower()
        if any(marker in obs_lower for marker in unexpected_markers):
            logger.info(
                "Replan considered: observation for step %d contains '%s'",
                step.number,
                next(m for m in unexpected_markers if m in obs_lower),
            )
            return True

        return False

    def mark_step_done(
        self, plan: AgentExecutionPlan, step_number: int, result: str,
    ) -> None:
        """Mark a step as done with its result."""
        for step in plan.steps:
            if step.number == step_number:
                step.status = "done"
                step.result = result
                plan.current_step = step_number + 1
                return
        logger.warning("mark_step_done: step %d not found in plan", step_number)

    def mark_step_failed(
        self, plan: AgentExecutionPlan, step_number: int, error: str,
    ) -> None:
        """Mark a step as failed."""
        for step in plan.steps:
            if step.number == step_number:
                step.status = "failed"
                step.error = error
                return
        logger.warning("mark_step_failed: step %d not found in plan", step_number)

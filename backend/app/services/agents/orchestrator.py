"""Agent orchestrator — enterprise-grade agentic design.

The LLM is ALWAYS in the loop. For greetings and simple queries, we provide
rich LIVE_CONTEXT so the LLM can respond without tool calls. For analytical
queries, the LLM drives tool-calling to fetch specific data, then synthesizes
a polished response.

Key design decisions:
- LIVE_CONTEXT is pre-formatted as readable narrative (not raw JSON)
- Greetings skip tool injection — LLM responds from context alone
- Tool calls are available for deep-dive / filtered queries
- Mock mode uses REAL skill dispatch (not canned responses) for genuine
  agentic behavior without requiring an LLM API key
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

from app.core.config import settings
from app.services.agents.config import resolve_llm_settings
from app.services.agents.guardrails import (
    run_guardrails,
    sanitize_output,
)
from app.services.agents.llm import LLMClient, LLMSettings
from app.services.agents.prompts import (
    build_system_prompt,
    detect_mode,
    is_greeting,
)
from app.services.agents.tools import TOOL_SCHEMAS, ToolContext, execute_tool

logger = logging.getLogger(__name__)


# ── Multi-agent delegation protocol ────────────────────────────────

@dataclass
class DelegationRequest:
    """Request from one agent to delegate a sub-task to another."""
    from_agent: str
    to_agent: str
    task: str
    context: str
    depth: int = 0
    max_depth: int = 2


@dataclass
class DelegationResult:
    """Result of a delegated sub-task."""
    agent_id: str
    agent_name: str
    result: str
    tool_trace: list[dict]
    success: bool = True


async def delegate_to_agent(
    delegation: DelegationRequest,
    db,
    organization_id: int,
    llm_settings=None,
) -> DelegationResult:
    """Execute a delegated sub-task on a target agent.

    Enforces max_depth to prevent infinite delegation loops.
    """
    from app.services.agents.registry import get_agent_or_default

    if delegation.depth >= delegation.max_depth:
        return DelegationResult(
            agent_id=delegation.to_agent,
            agent_name=delegation.to_agent,
            result="Delegation depth limit reached. Returning control to parent agent.",
            tool_trace=[],
            success=False,
        )

    target = get_agent_or_default(delegation.to_agent)
    if not target.can_delegate and delegation.depth > 0:
        pass  # non-delegatable agents can still be delegated TO

    sub_message = (
        f"[Delegated from {delegation.from_agent}]\n"
        f"Task: {delegation.task}\n"
        f"Context: {delegation.context}"
    )

    result = await run_agent(
        db=db,
        organization_id=organization_id,
        history=[{"role": "user", "content": sub_message}],
        agent_id=delegation.to_agent,
        llm_settings=llm_settings,
    )
    return DelegationResult(
        agent_id=target.id,
        agent_name=target.name,
        result=result.get("content", ""),
        tool_trace=result.get("tool_trace", []),
    )

async def _apply_rbac_tool_filter(
    db, organization_id: int, agent_def, tools: list[dict], user_id: int | None = None,
) -> list[dict]:
    """Limit tools to what the user's roles allow.

    A role with an empty ``allowed_agents`` / ``allowed_tools`` list does not
    restrict. With several roles the user gets the union; one unrestricted role
    means unrestricted. Without a user (internal calls) nothing is filtered.
    """
    if user_id is None:
        return tools
    from sqlalchemy import select

    from app.models.rbac import Role, UserRole

    roles = (await db.execute(
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )).scalars().all()
    if not roles:
        return tools

    if agent_def and all(r.allowed_agents for r in roles):
        if not any(agent_def.id in r.allowed_agents for r in roles):
            logger.warning("RBAC: agent %s blocked for user %s", agent_def.id, user_id)
            return []
    if all(r.allowed_tools for r in roles):
        allowed = {name for r in roles for name in r.allowed_tools}
        tools = [t for t in tools if t.get("function", {}).get("name") in allowed]
    return tools


async def _record_audit(db, organization_id: int, **kwargs):
    """Persist an agent audit entry. Non-fatal — logs errors but never raises."""
    try:
        from app.models.agent_audit import AgentAuditEntry
        import hashlib
        args_raw = kwargs.pop("tool_args", None)
        args_hash = hashlib.sha256(json.dumps(args_raw, sort_keys=True, default=str).encode()).hexdigest()[:16] if args_raw else None
        entry = AgentAuditEntry(
            organization_id=organization_id,
            tool_args_hash=args_hash,
            **kwargs,
        )
        db.add(entry)
        await db.commit()
    except Exception as exc:
        logger.debug("audit write skipped: %s", exc)


# Severity emoji mapping for formatted context
_SEV_EMOJI = {
    "CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535", "INFO": "\u26aa",
}


def _risk_label(score: int) -> str:
    """Human-readable risk label from numeric score."""
    if score >= 80:
        return "Critical Risk"
    if score >= 60:
        return "High Risk"
    if score >= 40:
        return "Moderate Risk"
    if score >= 20:
        return "Low Risk"
    return "Minimal Risk"


def _format_context_narrative(pack: dict) -> str:
    """Convert raw context dict into a readable narrative for the LLM.

    This is the KEY difference from dumping JSON -- the LLM gets a pre-
    formatted briefing it can directly incorporate into responses.
    """
    score = pack.get("risk_score", 0)
    if isinstance(score, dict):
        score = score.get("overall_score", 0) or score.get("score", 0)
    score = int(score) if score else 0
    label = _risk_label(score)

    sev = pack.get("severity_breakdown", {})
    total = pack.get("total_findings", sum(sev.values()))
    scans = pack.get("total_scans", 0)

    lines = [
        "\u2550\u2550\u2550 LIVE SECURITY POSTURE (use this data directly \u2014 do NOT call tools to get it again) \u2550\u2550\u2550",
        "",
        f"Risk Score: {score}/100 ({label})",
        f"Total Open Findings: {total} across {scans} scans",
        "",
        "Severity Breakdown:",
    ]
    for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = sev.get(sev_name, 0) or sev.get(sev_name.lower(), 0)
        if count:
            lines.append(f"  {_SEV_EMOJI.get(sev_name, chr(8226))} {sev_name}: {count}")

    cloud = pack.get("cloud_breakdown", {})
    if cloud:
        lines.append("")
        lines.append("Cloud Distribution:")
        for provider, count in cloud.items():
            lines.append(f"  \u2022 {provider}: {count} findings")

    top_risks = pack.get("top_risks", [])
    if top_risks:
        lines.append("")
        lines.append("Top Risk Items:")
        for i, risk in enumerate(top_risks[:5], 1):
            title = risk.get("title", "Unknown")
            rsev = risk.get("severity", "?")
            emoji = _SEV_EMOJI.get(rsev.upper(), "\u2022")
            rid = risk.get("id", "")
            resource = risk.get("resource_name", "")
            lines.append(f"  {i}. {emoji} {rsev} \u2014 {title} (#{rid}) \u2192 {resource}")

    # Org-specific knowledge base context
    org_knowledge = pack.get("org_knowledge", [])
    if org_knowledge:
        lines.append("")
        lines.append("═══ ORGANIZATION KNOWLEDGE BASE ═══")
        lines.append(f"({len(org_knowledge)} entries loaded — use these for org-specific triage)")
        for kb in org_knowledge[:10]:
            lines.append(f"  📘 [{kb.get('category', 'general')}] {kb.get('title', 'Untitled')}")

    lines.append("")
    lines.append("═══ END LIVE CONTEXT ═══")
    return "\n".join(lines)


# ---- Mock skill dispatch (genuine agentic behavior without LLM API) ----

# Map conversation modes to tool invocations
_MODE_TOOL_MAP: dict[str | None, list[tuple[str, dict]]] = {
    None: [
        ("get_risk_score", {}),
        ("get_severity_breakdown", {}),
    ],
    "triage": [
        ("get_severity_breakdown", {}),
        ("list_findings", {"severity": "CRITICAL", "limit": 5}),
        ("list_findings", {"severity": "HIGH", "limit": 5}),
    ],
    "explain": [
        ("get_risk_score", {}),
        ("get_severity_breakdown", {}),
    ],
    "remediate": [
        ("list_findings", {"severity": "CRITICAL", "limit": 3}),
    ],
    "compliance": [
        ("get_severity_breakdown", {}),
        ("check_compliance", {}),
    ],
    "compare": [
        ("list_recent_scans", {"limit": 10}),
        ("get_posture_trend", {}),
    ],
    "attack_surface": [
        ("analyze_attack_surface", {}),
        ("list_findings", {"severity": "CRITICAL", "limit": 5}),
    ],
    "autofix": [
        ("list_findings", {"severity": "CRITICAL", "limit": 5}),
        ("auto_fix_finding", {}),
    ],
    "auto_triage": [
        ("get_severity_breakdown", {}),
        ("list_findings", {"severity": "CRITICAL", "limit": 10}),
        ("list_findings", {"severity": "HIGH", "limit": 10}),
        ("triage_finding", {}),
    ],
    "investigation": [
        ("get_severity_breakdown", {}),
        ("list_findings", {"severity": "CRITICAL", "limit": 10}),
        ("list_findings", {"severity": "HIGH", "limit": 10}),
        ("investigate_aws_iam", {}),
        ("investigate_aws_network", {}),
        ("investigate_azure_security", {}),
        ("investigate_gcp_security", {}),
        ("analyze_kubernetes", {}),
        ("analyze_terraform", {}),
        ("deep_compliance", {}),
    ],
    "container_security": [
        ("investigate_containers", {}),
        ("analyze_kubernetes", {}),
        ("list_findings", {"severity": "CRITICAL", "limit": 10}),
    ],
    "cicd_security": [
        ("investigate_cicd", {}),
        ("analyze_supply_chain", {}),
        ("investigate_secrets", {}),
    ],
    "api_security": [
        ("investigate_api", {}),
        ("list_findings", {"severity": "CRITICAL", "limit": 10}),
    ],
    "network_security": [
        ("analyze_network_segmentation", {}),
        ("investigate_aws_network", {}),
        ("investigate_dns", {}),
        ("investigate_tls", {}),
    ],
    "identity_security": [
        ("assess_identity_governance", {}),
        ("assess_zero_trust", {}),
        ("investigate_aws_iam", {}),
    ],
    "threat_assessment": [
        ("threat_modeling", {}),
        ("assess_endpoint_security", {}),
        ("get_severity_breakdown", {}),
    ],
    "data_protection": [
        ("assess_dlp", {}),
        ("investigate_secrets", {}),
        ("deep_compliance", {"framework": "all"}),
    ],
    "cost_security": [
        ("detect_cost_anomalies", {}),
        ("get_risk_score", {}),
    ],
}


# ── Simulated tool calling for non-tool-calling LLMs ────────────


def _build_tool_menu(tools: list[dict]) -> str:
    """Build a numbered tool menu for non-tool-calling LLMs."""
    lines = []
    for i, tool in enumerate(tools, 1):
        fn = tool.get("function", tool)
        name = fn.get("name", "unknown")
        desc = fn.get("description", "")
        params = fn.get("parameters", {}).get("properties", {})
        param_str = ", ".join(
            f'{k}: {v.get("description", v.get("type", ""))}' for k, v in params.items()
        )
        lines.append(f"  {i}. {name}({param_str}) — {desc}")
    return "\n".join(lines)


def _parse_tool_calls(content: str) -> list[tuple[str, dict]]:
    """Parse ``TOOL_CALL: tool_name(arg="val")`` directives from LLM output."""
    import re

    calls: list[tuple[str, dict]] = []
    pattern = r'TOOL_CALL:\s*(\w+)\(([^)]*)\)'
    for match in re.finditer(pattern, content):
        tool_name = match.group(1)
        args_str = match.group(2)
        args: dict = {}
        # Parse key="value" pairs (quoted)
        for arg_match in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', args_str):
            args[arg_match.group(1)] = arg_match.group(2)
        # Parse key=value without quotes (numbers / booleans)
        for arg_match in re.finditer(r'(\w+)\s*=\s*([^",\s]+)', args_str):
            key = arg_match.group(1)
            if key not in args:
                val = arg_match.group(2)
                if val.lower() in ("true", "false"):
                    args[key] = val.lower() == "true"
                else:
                    try:
                        args[key] = int(val)
                    except ValueError:
                        args[key] = val
        calls.append((tool_name, args))
    return calls


async def _simulate_tool_calling(
    llm: LLMClient,
    messages: list[dict],
    available_tools: list[dict],
    tool_ctx: ToolContext,
    max_rounds: int = 5,
):
    """Simulated tool calling for non-tool-calling LLMs.

    Presents tools as a numbered menu in the system prompt.
    The LLM responds with ``TOOL_CALL: tool_name(arg1="val1", arg2="val2")``.
    We parse, execute, and inject the result back — same agentic loop as
    native tool calling, just using text conventions instead of API schema.
    """
    tool_menu = _build_tool_menu(available_tools)

    sim_messages = list(messages)
    tool_instruction = (
        "You have access to the following tools. To use a tool, write EXACTLY "
        "this format on its own line:\n"
        'TOOL_CALL: tool_name(arg1="value1", arg2="value2")\n\n'
        "After I execute the tool, I'll show you the result. Then continue "
        "your analysis.\n"
        "If you don't need any tools, just respond normally.\n\n"
        f"Available tools:\n{tool_menu}"
    )
    sim_messages.insert(0, {"role": "system", "content": tool_instruction})

    for round_num in range(max_rounds):
        from app.services.agents.llm import LLMResponse  # noqa: E402

        resp: LLMResponse = await llm.chat(sim_messages)
        content = resp.content or ""

        tool_calls = _parse_tool_calls(content)

        if not tool_calls:
            # No tool call — LLM is done, stream the final response.
            # Preserve newlines: split into lines, then words within each line,
            # so markdown structure (\n for tables, headings, lists) survives.
            for i, line in enumerate(content.split("\n")):
                if line:
                    for word in line.split(" "):
                        if word:
                            yield {"type": "token", "content": word + " "}
                if i < content.count("\n"):
                    yield {"type": "token", "content": "\n"}
            return

        for tool_name, tool_args in tool_calls:
            yield {"type": "tool_start", "tool": tool_name, "args": tool_args, "step": round_num}
            try:
                result = await execute_tool(tool_ctx, tool_name, tool_args)
                yield {
                    "type": "tool_result",
                    "tool": tool_name,
                    "step": round_num,
                    "preview": result[:200],
                }
            except Exception as e:
                result = f"Error: {e}"
                yield {
                    "type": "tool_result",
                    "tool": tool_name,
                    "step": round_num,
                    "preview": result,
                }

            sim_messages.append({"role": "assistant", "content": content})
            sim_messages.append({
                "role": "user",
                "content": (
                    f"Tool result for {tool_name}:\n{result}\n\n"
                    "Continue your analysis."
                ),
            })

    # Max rounds reached
    yield {"type": "token", "content": "I've completed my analysis with the available tools."}


# DEPRECATED: Replaced by _simulate_tool_calling(). Kept for backward compatibility.
async def _mock_skill_dispatch(
    ctx: ToolContext,
    mode: str | None,
    user_message: str,
) -> tuple[list[dict], dict]:
    """Invoke real skill functions to ground mock responses in actual data.

    Returns (tool_trace, aggregated_results) so the mock LLM can build
    its response from real data AND the UI shows tool invocation badges.
    """
    tool_invocations = _MODE_TOOL_MAP.get(mode, _MODE_TOOL_MAP[None])
    tool_trace: list[dict] = []
    aggregated: dict = {}

    # Simulate agent reasoning delay (makes it feel like actual AI thinking)
    await asyncio.sleep(1.2)

    for tool_name, tool_args in tool_invocations:
        try:
            result_str = await execute_tool(ctx, tool_name, tool_args)
            result = json.loads(result_str)
            # Skip error results silently
            if "error" not in result:
                tool_trace.append({"tool": tool_name, "arguments": tool_args})
                aggregated[tool_name] = result
        except Exception:
            logger.debug("Mock skill dispatch: %s failed, skipping", tool_name)

    # For remediation mode: fetch detail of first critical finding
    if mode == "remediate" and "list_findings" in aggregated:
        findings = aggregated["list_findings"].get("findings", [])
        if findings:
            fid = findings[0].get("id")
            if fid:
                try:
                    detail_str = await execute_tool(ctx, "get_finding", {"finding_id": fid})
                    detail = json.loads(detail_str)
                    if "error" not in detail:
                        tool_trace.append({"tool": "get_finding", "arguments": {"finding_id": fid}})
                        aggregated["finding_detail"] = detail
                except Exception:
                    pass

    return tool_trace, aggregated


async def build_context_pack(db, organization_id: int) -> dict:
    """Compact snapshot injected so even tool-less providers stay grounded."""
    from sqlalchemy import func, select

    from app.models.scan import Scan
    from app.services.risk.scorer import RiskScorer

    scorer = RiskScorer(db)
    severity = await scorer.get_severity_breakdown(organization_id)
    total_scans = (await db.execute(
        select(func.count(Scan.id)).where(Scan.organization_id == organization_id)
    )).scalar() or 0

    # Load org-specific knowledge base entries for agent context
    org_knowledge = await _load_org_knowledge(db, organization_id)

    return {
        "risk_score": await scorer.get_organization_score(organization_id),
        "severity_breakdown": severity,
        "cloud_breakdown": await scorer.get_cloud_breakdown(organization_id),
        "top_risks": await scorer.get_top_risks(organization_id, limit=8),
        "total_findings": sum(severity.values()),
        "total_scans": total_scans,
        "org_knowledge": org_knowledge,
    }


async def _load_org_knowledge(db, organization_id: int) -> list[dict]:
    """Load active knowledge base entries for injection into agent context."""
    from sqlalchemy import select
    try:
        from app.models.knowledge_base import KnowledgeEntry
        stmt = (
            select(KnowledgeEntry)
            .where(
                KnowledgeEntry.organization_id == organization_id,
                KnowledgeEntry.is_active == True,
            )
            .order_by(KnowledgeEntry.priority.desc())
            .limit(20)
        )
        rows = (await db.execute(stmt)).scalars().all()
        return [
            {"title": r.title, "category": r.category, "content": r.content[:2000]}
            for r in rows
        ]
    except Exception:
        logger.debug("Knowledge base table not yet created, skipping")
        return []


async def run_agent(
    db,
    organization_id: int,
    history: list[dict],
    *,
    system_prompt: str | None = None,
    llm_settings: LLMSettings | None = None,
    agent_id: str | None = None,
    user_id: int | None = None,
) -> dict:
    """Execute one assistant turn -- enterprise agentic flow.

    For greetings, the LLM responds using pre-formatted LIVE_CONTEXT
    (no tool calls needed). For analytical queries:
      - Live LLM: drives tool-calling to fetch specific data
      - Mock mode: invokes real skills directly (genuine agentic behavior)

    ``history`` is a list of {role, content} messages (user/assistant).
    Returns {"content": str, "tool_trace": [...], "provider": {...}}.
    """
    user_message = next(
        (msg.get("content", "") for msg in reversed(history) if msg.get("role") == "user"),
        "",
    )

    # ── Guardrails: input sanitization, rate limiting, budget check ──
    guardrail_result = run_guardrails(
        message=user_message,
        org_id=organization_id,
        total_tokens_used=sum(len(m.get("content", "")) // 4 for m in history),
        turn_count=len([m for m in history if m.get("role") == "user"]),
    )
    if not guardrail_result.allowed:
        logger.warning("Guardrail blocked request for org=%d: %s", organization_id, guardrail_result.blocked_reason)
        warnings_text = ""
        if guardrail_result.warnings:
            warnings_text = "\n\n" + "\n".join(f"⚠️ {w}" for w in guardrail_result.warnings)
        return {
            "content": f"🛡️ {guardrail_result.blocked_reason}{warnings_text}",
            "tool_trace": [],
            "provider": {"model": "guardrail", "live": False},
            "guardrail_blocked": True,
        }

    # Use sanitized input (PII redacted) for LLM
    if guardrail_result.sanitized_input and guardrail_result.pii_detected:
        for i in range(len(history) - 1, -1, -1):
            if history[i].get("role") == "user":
                history[i] = {**history[i], "content": guardrail_result.sanitized_input}
                break

    # Detect conversation mode and build a context-aware system prompt
    mode = detect_mode(user_message) if user_message else None
    greeting = is_greeting(user_message) if user_message else False
    effective_prompt = system_prompt or build_system_prompt(mode=mode)

    # Resolve LLM settings (from DB first, then env fallback)
    if llm_settings is None:
        llm_settings = await resolve_llm_settings(db, organization_id)
    llm = LLMClient(llm_settings)
    ctx = ToolContext(db=db, organization_id=organization_id)

    # ── Agent routing ──
    from app.services.agents.router import route_to_agent
    from app.services.agents.registry import get_agent, filter_tools_for_agent

    if agent_id:
        agent_def = get_agent(agent_id)
    else:
        agent_def, _conf, _reason = await route_to_agent(llm, user_message, history, db=db, organization_id=organization_id)

    if agent_def:
        # Fetch agent prompt from registry (org-customizable), fall back to hardcoded
        registry_prompt = None
        try:
            from app.services.prompt_registry import PromptRegistryService
            pr = PromptRegistryService(db, organization_id)
            registry_prompt = await pr.get_prompt(f"{agent_def.id}_system")
        except Exception:
            pass
        effective_prompt = registry_prompt or agent_def.system_prompt or effective_prompt
        agent_tools = filter_tools_for_agent(agent_def, TOOL_SCHEMAS)
    else:
        agent_tools = TOOL_SCHEMAS

    # ── RBAC: filter agents/tools by role permissions ──
    agent_tools = await _apply_rbac_tool_filter(db, organization_id, agent_def, agent_tools, user_id)

    # Build the full context: system prompt + formatted live org snapshot
    pack = await build_context_pack(db, organization_id)
    context_narrative = _format_context_narrative(pack)

    messages: list[dict] = [
        {"role": "system", "content": effective_prompt},
        {"role": "system", "content": context_narrative},
        *history,
    ]

    tool_trace: list[dict] = []

    # ── Greeting path: respond from context alone (no tools) ──
    if greeting:
        logger.info("Greeting detected -- responding from context, no tools")
        # Add small delay even for greetings so it feels like thinking
        if not llm.is_live:
            await asyncio.sleep(0.8)
        resp = await llm.chat(messages)
        return {"content": resp.content, "tool_trace": tool_trace, "provider": llm.info()}

    # ── Non-tool-calling provider: simulated tool calling ──
    if not llm.supports_tools:
        logger.info("Simulated tool-calling for non-tool-calling provider, mode=%s", mode)
        collected_content: list[str] = []
        async for event in _simulate_tool_calling(llm, messages, agent_tools, ctx):
            if event["type"] == "token":
                collected_content.append(event["content"])
            elif event["type"] in ("tool_start", "tool_result"):
                tool_trace.append({"tool": event["tool"], "arguments": event.get("args", {})})

        return {
            "content": "".join(collected_content).strip(),
            "tool_trace": tool_trace,
            "provider": llm.info(),
        }

    # ── Live LLM: agentic tool-calling loop ──
    for step in range(settings.AGENT_MAX_STEPS):
        resp = await llm.chat(messages, tools=agent_tools)

        # No tool calls -- LLM is done reasoning, return its response
        if not resp.tool_calls:
            return {"content": resp.content, "tool_trace": tool_trace, "provider": llm.info()}

        # Append assistant message with tool calls
        messages.append({
            "role": "assistant",
            "content": resp.content or None,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                }
                for tc in resp.tool_calls
            ],
        })

        # Execute each tool and append results
        for tc in resp.tool_calls:
            logger.info("Agent step %d: calling tool %s(%s)", step, tc.name, tc.arguments)
            # Handle multi-agent delegation
            if tc.name == "delegate_to_agent" and agent_def and agent_def.can_delegate:
                deleg = DelegationRequest(
                    from_agent=agent_def.id,
                    to_agent=tc.arguments.get("target_agent", "general"),
                    task=tc.arguments.get("task", ""),
                    context=tc.arguments.get("context", ""),
                )
                deleg_result = await delegate_to_agent(deleg, db, organization_id, llm_settings)
                output = json.dumps({"delegated_to": deleg_result.agent_name, "result": deleg_result.result})
                tool_trace.append({"tool": "delegate_to_agent", "delegated_to": deleg_result.agent_id})
            else:
                import time as _time
                _t0 = _time.monotonic()
                output = await execute_tool(ctx, tc.name, tc.arguments)
                _dur = int((_time.monotonic() - _t0) * 1000)
                tool_trace.append({"tool": tc.name, "arguments": tc.arguments})
                await _record_audit(
                    db, organization_id,
                    entry_type="tool_call",
                    agent_id=agent_def.id if agent_def else None,
                    tool_name=tc.name,
                    tool_args=tc.arguments,
                    tool_result_preview=output[:500] if output else None,
                    duration_ms=_dur,
                )
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "name": tc.name,
                "content": output,
            })

    # Final synthesis after max steps
    resp = await llm.chat(messages)
    final_content = sanitize_output(resp.content or "")
    return {"content": final_content, "tool_trace": tool_trace, "provider": llm.info()}


# ═══════════════════════════════════════════════════════════════════
# Streaming agentic loop — yields SSE events with tool calls + tokens
# ═══════════════════════════════════════════════════════════════════

async def run_agent_stream(
    db,
    organization_id: int,
    history: list[dict],
    *,
    agent_id: str | None = None,
    system_prompt: str | None = None,
    llm_settings: LLMSettings | None = None,
    user_id: int | None = None,
    chat: dict | None = None,
):
    """Async generator that yields SSE-ready dicts through the full agentic loop.

    ``chat`` identifies the reply being written (``conversation_id``,
    ``message_id``) so tools can attach files to it.


    Unlike ``run_agent()`` this streams tokens AND exposes tool-call events,
    so the frontend can show live reasoning, tool badges, and progressive
    text — all in a single SSE connection.

    Yields dicts with ``type`` key:
      - ``{"type": "routing", "agent_id": ..., "agent_name": ..., "confidence": ...}``
      - ``{"type": "tool_start", "tool": "...", "args": {...}, "step": N}``
      - ``{"type": "tool_result", "tool": "...", "preview": "...", "step": N}``
      - ``{"type": "token", "content": "..."}``
      - ``{"type": "done", "tool_trace": [...], "provider": {...}}``
      - ``{"type": "error", "message": "..."}``
    """
    from app.services.agents.notebook import Notebook
    from app.services.agents.planner import PlanState, REACT_GROUNDING, clean_answer
    from app.services.agents.registry import get_agent_or_default, filter_tools_for_agent
    from app.services.agents.router import route_to_agent

    from app.services.agents.attachments import is_attachment_block

    # What the user typed. Attached files travel as their own turns and are
    # neither routed on nor counted against the limits for typed text.
    typed = [m for m in history if m.get("role") == "user" and not is_attachment_block(m.get("content"))]
    user_message = typed[-1].get("content", "") if typed else ""

    # ── Guardrails ──
    guardrail_result = run_guardrails(
        message=user_message,
        org_id=organization_id,
        total_tokens_used=sum(len(m.get("content") or "") // 4 for m in history if not is_attachment_block(m.get("content"))),
        turn_count=len(typed),
    )
    if not guardrail_result.allowed:
        yield {"type": "token", "content": f"🛡️ {guardrail_result.blocked_reason}"}
        yield {"type": "done", "tool_trace": [], "provider": {"model": "guardrail", "live": False}}
        return

    if guardrail_result.sanitized_input and guardrail_result.pii_detected:
        for i in range(len(history) - 1, -1, -1):
            if history[i].get("role") == "user":
                history[i] = {**history[i], "content": guardrail_result.sanitized_input}
                break

    # ── Resolve LLM ──
    if llm_settings is None:
        llm_settings = await resolve_llm_settings(db, organization_id)
    llm = LLMClient(llm_settings)
    ctx = ToolContext(db=db, organization_id=organization_id, meta={**(chat or {}), "user_id": user_id})
    notebook = Notebook()
    plan_state = PlanState()

    # ── Route to agent ──
    if agent_id:
        agent_def = get_agent_or_default(agent_id)
        confidence = 1.0
        reasoning = "explicit selection"
    else:
        agent_def, confidence, reasoning = await route_to_agent(llm, user_message, history, db=db, organization_id=organization_id)

    yield {
        "type": "routing",
        "agent_id": agent_def.id,
        "agent_name": agent_def.name,
        "confidence": confidence,
        "reasoning": reasoning,
    }

    # ── Greeting fast path — skip heavy context building entirely ──
    greeting = is_greeting(user_message) if user_message else False
    if greeting:
        effective_prompt = system_prompt or agent_def.system_prompt or build_system_prompt(mode=detect_mode(user_message))
        greeting_messages = [
            {"role": "system", "content": effective_prompt},
            {"role": "user", "content": "The user just greeted you. Respond naturally in 1-2 sentences. "
                                        "Do NOT show data, tables, posture snapshots, or capability lists. "
                                        "Just greet them back like a friendly colleague."},
        ]
        async for token in llm.chat_stream(greeting_messages):
            yield {"type": "token", "content": token}
        yield {"type": "done", "tool_trace": [], "provider": llm.info()}
        return

    # ── Build context (non-greeting path only) ──
    # Fetch agent prompt from registry (org-customizable), fall back to hardcoded
    registry_prompt = None
    try:
        from app.services.prompt_registry import PromptRegistryService
        pr = PromptRegistryService(db, organization_id)
        registry_prompt = await pr.get_prompt(f"{agent_def.id}_system")
    except Exception:
        pass
    effective_prompt = system_prompt or registry_prompt or agent_def.system_prompt or build_system_prompt(mode=detect_mode(user_message))
    effective_prompt += REACT_GROUNDING

    pack = await build_context_pack(db, organization_id)
    context_narrative = _format_context_narrative(pack)

    # Filter tools for this agent + RBAC
    agent_tools = filter_tools_for_agent(agent_def, TOOL_SCHEMAS, chat=bool(chat and chat.get("message_id")))
    if agent_tools:
        agent_tools = await _apply_rbac_tool_filter(db, organization_id, agent_def, agent_tools, user_id)
    max_steps = agent_def.max_steps or settings.AGENT_MAX_STEPS

    tool_trace: list[dict] = []

    def _logged(arguments: dict) -> dict:
        """Arguments as kept in the trace and audit log: long text is shortened."""
        return {k: (v[:200] + "…" if isinstance(v, str) and len(v) > 200 else v) for k, v in (arguments or {}).items()}

    messages: list[dict] = [
        {"role": "system", "content": effective_prompt},
        {"role": "system", "content": context_narrative},
        *history,
    ]

    # ── Non-tool-calling provider: simulated tool calling (unified path) ──
    if not llm.supports_tools:
        async for event in _simulate_tool_calling(llm, messages, agent_tools or TOOL_SCHEMAS, ctx):
            if event["type"] in ("tool_start", "tool_result"):
                tool_trace.append({"tool": event["tool"], "arguments": event.get("args", {})})
            yield event
        yield {"type": "done", "tool_trace": tool_trace, "provider": llm.info()}
        return

    # ── Live LLM: agentic tool-calling loop with streaming final response ──
    for step in range(max_steps):
        resp = await llm.chat(messages, tools=agent_tools)

        if not resp.tool_calls:
            # No tool calls — stream the final answer token-by-token
            if resp.content:
                # The model already gave the whole answer; send it on word by word
                # Secrets, internal paths and personal data are removed before anything is sent.
                for word in clean_answer(sanitize_output(resp.content)).split(" "):
                    yield {"type": "token", "content": word + " "}
                    await asyncio.sleep(0.01)
            yield {"type": "done", "tool_trace": tool_trace, "provider": llm.info()}
            return

        # Append assistant message with tool calls
        messages.append({
            "role": "assistant",
            "content": resp.content or None,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                }
                for tc in resp.tool_calls
            ],
        })

        # Execute each tool call and stream events
        for tc in resp.tool_calls:
            # Stall detection
            if plan_state.record_call(tc.name, tc.arguments):
                yield {"type": "token", "content": "⚠️ Investigation stalled — synthesizing from available data.\n\n"}
                break

            yield {"type": "tool_start", "tool": tc.name, "args": tc.arguments, "step": step}

            # Handle multi-agent delegation
            if tc.name == "delegate_to_agent" and agent_def and agent_def.can_delegate:
                deleg = DelegationRequest(
                    from_agent=agent_def.id,
                    to_agent=tc.arguments.get("target_agent", "general"),
                    task=tc.arguments.get("task", ""),
                    context=tc.arguments.get("context", ""),
                )
                deleg_result = await delegate_to_agent(deleg, db, organization_id, llm_settings)
                output = json.dumps({"delegated_to": deleg_result.agent_name, "result": deleg_result.result})
                tool_trace.append({"tool": "delegate_to_agent", "delegated_to": deleg_result.agent_id})
            else:
                import time as _time
                _t0 = _time.monotonic()
                output = await execute_tool(ctx, tc.name, tc.arguments)
                _dur = int((_time.monotonic() - _t0) * 1000)
                tool_trace.append({"tool": tc.name, "arguments": _logged(tc.arguments)})
                await _record_audit(
                    db, organization_id,
                    entry_type="tool_call",
                    agent_id=agent_def.id if agent_def else None,
                    tool_name=tc.name,
                    tool_args=_logged(tc.arguments),
                    tool_result_preview=output[:500] if output else None,
                    duration_ms=_dur,
                )

            notebook.write(key=tc.name, value=output[:500], source=f"tool:{tc.name}", tags=["tool_result"])

            yield {"type": "tool_result", "tool": tc.name, "preview": output[:200], "step": step}

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "name": tc.name,
                "content": output,
            })

    # Max steps reached — stream final synthesis
    async for token in llm.chat_stream(messages):
        yield {"type": "token", "content": token}
    yield {"type": "done", "tool_trace": tool_trace, "provider": llm.info()}

"""Agent Router — LLM-powered intent classification and agent selection.

Replaces the keyword-based ``detect_mode()`` with an LLM classifier that
analyzes the user's query and routes it to the best specialized agent.

Falls back to keyword heuristics when no LLM is available (mock mode).
Uses the prompt registry for the system prompt (with built-in fallback).
"""
from __future__ import annotations

import json
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.agents.llm import LLMClient, LLMResponse
from app.services.agents.registry import AGENTS, AgentDefinition, get_agent_or_default

logger = logging.getLogger(__name__)

# Hardcoded fallback — used only when prompt registry is unavailable
_ROUTER_FALLBACK_PROMPT = """\
You are an intent classifier for a cloud security platform called GuardNous.
Your job is to analyze the user's message and determine which specialized
security agent should handle it.

Available agents:
{agent_list}

RULES:
1. Return ONLY a JSON object: {{"agent_id": "<id>", "confidence": <0.0-1.0>, "reasoning": "<brief>"}}
2. Choose the MOST specialized agent that fits the query
3. If the query is a greeting or casual chat, use "general"
4. If multiple agents could handle it, pick the one whose expertise is the closest match
5. confidence should be 0.9+ for clear matches, 0.5-0.8 for ambiguous ones
6. Do NOT include any other text — just the JSON object
"""

# Keyword fallback for when LLM is unavailable
_KEYWORD_ROUTES: list[tuple[list[str], str]] = [
    # Compliance
    (["compliance", "cis", "soc", "pci", "hipaa", "nist", "framework", "audit",
      "regulation", "iso 27001", "gdpr", "ccpa"], "compliance_advisor"),
    # Triage
    (["triage", "prioritize", "classify", "urgent", "critical first",
      "what should i fix", "top priority", "noise reduction", "false positive",
      "bulk triage", "auto triage", "auto-triage"], "triage_agent"),
    # Remediation
    (["fix", "remediate", "patch", "resolve", "autofix", "auto-fix", "auto fix",
      "create pr", "open pr", "generate fix", "how to fix", "steps to fix",
      "remediation", "playbook"], "remediation_agent"),
    # DevSecOps
    (["terraform", "iac", "infrastructure as code", "cicd", "ci/cd", "pipeline",
      "docker", "container", "kubernetes", "k8s", "supply chain", "sbom",
      "dependency", "shift left", "pre-commit", "policy as code"], "devsecops_coach"),
    # Threat Intel
    (["threat model", "mitre", "att&ck", "stride", "kill chain", "attack tree",
      "attack path", "adversary", "ttp", "ioc", "threat actor", "edr",
      "endpoint security"], "threat_intel"),
    # Investigation
    (["investigate", "deep dive", "root cause", "forensic", "incident",
      "incident response", "ransomware", "data breach", "credential exposure",
      "unauthorized access", "aws iam", "privilege escalation", "vpc",
      "security group", "azure defender", "entra", "gcp security",
      "lateral movement"], "investigation_agent"),
    # Security Analysis (broad)
    (["risk score", "posture", "severity", "findings", "vulnerability",
      "attack surface", "exposure", "scan result", "security status",
      "dashboard", "overview", "summary", "trend"], "security_analyst"),
]


def _build_agent_list() -> str:
    lines = []
    for agent in AGENTS.values():
        lines.append(f"- **{agent.id}**: {agent.name} — {agent.description}")
    return "\n".join(lines)


def _keyword_route(message: str) -> str:
    """Fallback keyword-based routing when LLM is unavailable."""
    msg = message.lower()
    for keywords, agent_id in _KEYWORD_ROUTES:
        if any(kw in msg for kw in keywords):
            return agent_id
    return "general"


async def _get_router_prompt(db: AsyncSession | None, org_id: int | None) -> str:
    """Retrieve router prompt from registry, falling back to hardcoded default."""
    if db and org_id:
        try:
            from app.services.prompt_registry import PromptRegistryService
            svc = PromptRegistryService(db, org_id)
            prompt = await svc.get_prompt("router_classify", agent_list=_build_agent_list())
            if prompt:
                return prompt
        except Exception as e:
            logger.debug("Prompt registry unavailable for router: %s", e)
    return _ROUTER_FALLBACK_PROMPT.format(agent_list=_build_agent_list())


async def route_to_agent(
    llm: LLMClient,
    user_message: str,
    history: list[dict] | None = None,
    *,
    db: AsyncSession | None = None,
    organization_id: int | None = None,
) -> tuple[AgentDefinition, float, str]:
    """Classify user intent and return the best agent.

    Returns (agent_definition, confidence, reasoning).
    """
    # Fast path for greetings
    from app.services.agents.prompts import is_greeting
    if is_greeting(user_message):
        agent = get_agent_or_default("general")
        return agent, 1.0, "Greeting detected"

    # If LLM doesn't support tool calling, use keyword fallback
    if not llm.supports_tools:
        agent_id = _keyword_route(user_message)
        agent = get_agent_or_default(agent_id)
        return agent, 0.7, f"Keyword match → {agent_id}"

    # LLM-powered classification
    try:
        system = await _get_router_prompt(db, organization_id)

        # Include last 2 user messages for context continuity
        context_msgs: list[dict] = []
        if history:
            recent_user = [m for m in history if m.get("role") == "user"][-2:]
            context_msgs = recent_user

        messages = [
            {"role": "system", "content": system},
            *context_msgs,
            {"role": "user", "content": user_message},
        ]

        resp: LLMResponse = await llm.chat(messages)
        content = (resp.content or "").strip()

        # Parse the JSON response
        # Handle markdown code blocks
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()

        result = json.loads(content)
        agent_id = result.get("agent_id", "general")
        confidence = float(result.get("confidence", 0.5))
        reasoning = result.get("reasoning", "")

        agent = get_agent_or_default(agent_id)
        logger.info("Router: %s → %s (%.0f%%) — %s", user_message[:50], agent_id, confidence * 100, reasoning)
        return agent, confidence, reasoning

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Router LLM parse failed: %s — falling back to keywords", e)
        agent_id = _keyword_route(user_message)
        agent = get_agent_or_default(agent_id)
        return agent, 0.6, f"LLM parse failed, keyword fallback → {agent_id}"

    except Exception as e:
        logger.error("Router error: %s — falling back to keywords", e)
        agent_id = _keyword_route(user_message)
        agent = get_agent_or_default(agent_id)
        return agent, 0.5, f"Router error, keyword fallback → {agent_id}"

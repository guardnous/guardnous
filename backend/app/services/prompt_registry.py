"""Prompt Registry service — DB-backed prompt versioning with caching.

Replaces hardcoded prompt strings with versioned, editable templates.
Prompts can be updated without code deploys. Includes:
  - In-memory LRU cache (avoids DB round-trip on every LLM call)
  - Version management (activate/deactivate, rollback)
  - Variable interpolation with validation
  - Usage metrics tracking
"""
from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.prompt_registry import PromptTemplate

logger = logging.getLogger(__name__)

# In-memory cache: (org_id, slug) → (content, timestamp)
_CACHE: dict[tuple[int, str], tuple[str, float]] = {}
_CACHE_TTL = 300  # 5 minutes


class PromptRegistryService:
    """Async service for prompt template CRUD + rendering."""

    def __init__(self, db: AsyncSession, organization_id: int):
        self.db = db
        self.org_id = organization_id

    # ── Core retrieval ───────────────────────────────────────

    async def get_prompt(self, slug: str, **variables: Any) -> str:
        """Get the active prompt for a slug, with variable interpolation.

        Falls back to built-in defaults if no DB entry exists.
        """
        cache_key = (self.org_id, slug)

        # Check cache
        if cache_key in _CACHE:
            content, ts = _CACHE[cache_key]
            if time.time() - ts < _CACHE_TTL:
                return self._interpolate(content, variables)

        # DB lookup
        result = await self.db.execute(
            select(PromptTemplate).where(
                PromptTemplate.organization_id == self.org_id,
                PromptTemplate.slug == slug,
                PromptTemplate.is_active == True,
            ).order_by(PromptTemplate.version.desc()).limit(1)
        )
        template = result.scalar_one_or_none()

        if template:
            _CACHE[cache_key] = (template.content, time.time())
            # Update usage metrics (fire-and-forget)
            await self._bump_metrics(template.id)
            return self._interpolate(template.content, variables)

        # Fallback to built-in defaults
        default = _BUILTIN_DEFAULTS.get(slug)
        if default:
            return self._interpolate(default, variables)

        logger.warning("No prompt found for slug=%s org=%d", slug, self.org_id)
        return f"[Missing prompt: {slug}]"

    # ── CRUD ─────────────────────────────────────────────────

    async def create_prompt(
        self,
        slug: str,
        content: str,
        description: str | None = None,
        variables: list[str] | None = None,
        tags: list[str] | None = None,
        created_by: str | None = None,
    ) -> PromptTemplate:
        """Create a new prompt template (auto-increments version)."""
        # Find highest version
        result = await self.db.execute(
            select(PromptTemplate.version)
            .where(
                PromptTemplate.organization_id == self.org_id,
                PromptTemplate.slug == slug,
            )
            .order_by(PromptTemplate.version.desc())
            .limit(1)
        )
        max_ver = result.scalar_one_or_none() or 0

        # Deactivate previous versions
        await self.db.execute(
            update(PromptTemplate)
            .where(
                PromptTemplate.organization_id == self.org_id,
                PromptTemplate.slug == slug,
            )
            .values(is_active=False)
        )

        template = PromptTemplate(
            organization_id=self.org_id,
            slug=slug,
            version=max_ver + 1,
            content=content,
            description=description,
            variables=variables or [],
            is_active=True,
            tags=tags or [],
            created_by=created_by,
        )
        self.db.add(template)
        await self.db.flush()

        # Invalidate cache
        _CACHE.pop((self.org_id, slug), None)
        logger.info("Created prompt %s v%d for org %d", slug, template.version, self.org_id)
        return template

    async def list_prompts(self, active_only: bool = True) -> list[PromptTemplate]:
        q = select(PromptTemplate).where(PromptTemplate.organization_id == self.org_id)
        if active_only:
            q = q.where(PromptTemplate.is_active == True)
        q = q.order_by(PromptTemplate.slug, PromptTemplate.version.desc())
        result = await self.db.execute(q)
        return list(result.scalars().all())

    async def get_versions(self, slug: str) -> list[PromptTemplate]:
        result = await self.db.execute(
            select(PromptTemplate)
            .where(
                PromptTemplate.organization_id == self.org_id,
                PromptTemplate.slug == slug,
            )
            .order_by(PromptTemplate.version.desc())
        )
        return list(result.scalars().all())

    async def activate_version(self, slug: str, version: int) -> bool:
        """Activate a specific version (deactivates all others for this slug)."""
        # Deactivate all
        await self.db.execute(
            update(PromptTemplate)
            .where(
                PromptTemplate.organization_id == self.org_id,
                PromptTemplate.slug == slug,
            )
            .values(is_active=False)
        )
        # Activate target
        result = await self.db.execute(
            update(PromptTemplate)
            .where(
                PromptTemplate.organization_id == self.org_id,
                PromptTemplate.slug == slug,
                PromptTemplate.version == version,
            )
            .values(is_active=True)
        )
        _CACHE.pop((self.org_id, slug), None)
        return result.rowcount > 0

    # ── Helpers ──────────────────────────────────────────────

    def _interpolate(self, content: str, variables: dict[str, Any]) -> str:
        """Safe variable interpolation using str.format_map with defaults."""
        if not variables:
            return content
        try:
            return content.format_map(_SafeDict(variables))
        except (KeyError, ValueError):
            return content

    async def _bump_metrics(self, template_id: int) -> None:
        """Increment usage counter (best-effort)."""
        try:
            tmpl = await self.db.get(PromptTemplate, template_id)
            if tmpl:
                metrics = tmpl.metrics or {}
                metrics["calls"] = metrics.get("calls", 0) + 1
                tmpl.metrics = metrics
                await self.db.flush()
        except Exception:
            pass  # metrics are best-effort


class _SafeDict(dict):
    """Dict that returns {key} for missing keys instead of raising KeyError."""
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


# ── Built-in defaults (fallback when no DB entry) ────────────

_BUILTIN_DEFAULTS: dict[str, str] = {
    "triage_system": (
        "You are a senior cloud-security triage engineer performing contextual risk analysis.\n\n"
        "For each finding, assess:\n"
        "1. **Real-world exploitability** — Can this actually be exploited? Is it internet-facing?\n"
        "2. **Blast radius** — What data/systems are at risk if exploited?\n"
        "3. **False positive likelihood** — Is this a test file, example code, or known benign pattern?\n"
        "4. **Scanner reliability** — Consider the scanner's known false-positive rate for this rule type.\n"
        "5. **Contextual risk** — File path, resource name, cloud provider context.\n\n"
        "Return STRICT JSON only, no markdown, no prose."
    ),
    "router_classify": (
        "You are an intent classifier for a cloud security platform. "
        "Given a user message, determine which specialist agent should handle it. "
        "Available agents: {agent_list}\n"
        "Return JSON: {{\"agent_id\": \"...\", \"confidence\": 0.0-1.0, \"reasoning\": \"...\"}}"
    ),
    "remediation_explain": (
        "You are a DevSecOps remediation expert. "
        "Explain the security issue in plain language, then provide a concrete fix. "
        "Finding: {finding_title}\nSeverity: {severity}\nResource: {resource}"
    ),
    "investigation_system": (
        "You are a security investigation analyst. "
        "Use available tools to gather evidence, correlate findings, and build a timeline. "
        "Always cite specific evidence for your conclusions."
    ),
    "compliance_system": (
        "You are a compliance advisor specializing in cloud security frameworks. "
        "Map findings to specific controls in {framework}. "
        "Provide actionable remediation steps with priority."
    ),
    # ── Per-agent system prompts (fetched by orchestrator) ──
    "security_analyst_system": (
        "You are **Security Analyst** — a senior cloud security engineer specializing in "
        "vulnerability assessment, risk analysis, and security posture evaluation.\n\n"
        "YOUR EXPERTISE:\n"
        "- Analyzing vulnerability findings across AWS, Azure, GCP\n"
        "- Risk scoring and severity assessment\n"
        "- Attack surface analysis and exposure mapping\n"
        "- Security posture trending and benchmarking\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Always start with the big picture (risk score, severity breakdown) before drilling down\n"
        "2. Write severity as a word (Critical, High, Medium, Low, Info). No emoji.\n"
        "3. Structure responses: executive summary → details → recommended action\n"
        "4. When findings exceed 5, use markdown tables\n"
        "5. Proactively suggest related investigations\n"
        "6. Never dump raw data — synthesize and interpret\n\n"
        "You have access to real-time organizational security data via LIVE_CONTEXT."
    ),
    "compliance_advisor_system": (
        "You are **Compliance Advisor** — an expert in regulatory compliance frameworks "
        "and their mapping to cloud security controls.\n\n"
        "YOUR EXPERTISE:\n"
        "- CIS Benchmarks, SOC 2 Type II, PCI-DSS v4.0, HIPAA, NIST 800-53/CSF, ISO 27001, GDPR/CCPA\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Always cite specific control IDs (e.g., CIS 2.1.1, SOC2 CC6.1)\n"
        "2. Map findings to framework controls with gap analysis\n"
        "3. Provide audit-ready language for compliance reports\n"
        "4. Distinguish blocking gaps from improvement opportunities\n"
        "5. Recommend priority based on regulatory risk\n"
        "6. Include estimated effort: Quick Win / Sprint / Quarter"
    ),
    "devsecops_coach_system": (
        "You are **DevSecOps Coach** — a shift-left security expert helping developers "
        "build secure code and infrastructure from the start.\n\n"
        "YOUR EXPERTISE:\n"
        "- IaC security (Terraform, CloudFormation, Pulumi)\n"
        "- CI/CD pipeline hardening, secret management\n"
        "- Container & Kubernetes security, supply chain (SBOMs)\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Explain vulnerabilities in developer-friendly language\n"
        "2. Always provide code-level fixes with before/after snippets\n"
        "3. Suggest preventive guardrails (pre-commit, policy-as-code)\n"
        "4. Reference OWASP, CWE, CVE IDs\n"
        "5. Prioritize fixes that prevent entire classes of vulnerabilities"
    ),
    "threat_intel_system": (
        "You are **Threat Intelligence Analyst** — specializing in threat modeling, "
        "attack path analysis, and adversary simulation.\n\n"
        "YOUR EXPERTISE:\n"
        "- MITRE ATT&CK framework mapping, STRIDE, kill chain analysis\n"
        "- Attack surface enumeration, adversary TTP mapping, IOC detection\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Map every finding to MITRE ATT&CK techniques\n"
        "2. Build attack chains showing how vulnerabilities can be chained\n"
        "3. Assess blast radius for each exposure\n"
        "4. Provide attacker perspective\n"
        "5. Recommend detection rules alongside prevention\n"
        "6. Use threat severity based on exploitability, not just CVSS"
    ),
    "triage_agent_system": (
        "You are **Triage Agent** — an expert at rapid classification, prioritization, "
        "and noise reduction for security findings.\n\n"
        "YOUR EXPERTISE:\n"
        "- Rapid severity assessment with business context\n"
        "- False positive identification and suppression\n"
        "- Chronic/recurring issue detection, deduplication\n"
        "- SLA-aware prioritization, bulk classification\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Classify every finding: Actionable / False Positive / Accepted Risk / Needs Context\n"
        "2. Provide confidence score (0-100%)\n"
        "3. Group related findings by root cause\n"
        "4. Highlight quick wins — low-effort, high-impact fixes\n"
        "5. Detect chronic issues recurring across scans\n"
        "6. Output structured triage results"
    ),
    "remediation_agent_system": (
        "You are **Remediation Agent** — specializing in generating, validating, and "
        "tracking security fixes across cloud and IaC configurations.\n\n"
        "YOUR EXPERTISE:\n"
        "- IaC fix patches (Terraform, CloudFormation)\n"
        "- Step-by-step remediation playbooks\n"
        "- Verification command generation, rollback planning\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Every fix: Root Cause → Fix Steps → Verify → Prevent\n"
        "2. Generate copy-pasteable code/commands\n"
        "3. Include rollback instructions\n"
        "4. Estimate effort: Quick (< 30 min) / Medium (1-4h) / Large (> 1d)\n"
        "5. Group fixes sharing common remediation patterns\n"
        "6. Track status: Planned → In Progress → Verified → Closed"
    ),
    "investigation_agent_system": (
        "You are **Investigation Agent** — a deep-dive forensic analyst for cloud "
        "security incidents and complex multi-signal investigations.\n\n"
        "YOUR EXPERTISE:\n"
        "- Multi-cloud incident investigation, IAM privilege escalation\n"
        "- Network exposure, lateral movement, container/K8s security\n"
        "- Secret sprawl, credential exposure, cross-service correlation\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Start broad (surface scan), then narrow (deep dive)\n"
        "2. Correlate across multiple signals (IAM + Network + Secrets)\n"
        "3. Build evidence chains with timestamps and resource IDs\n"
        "4. Classify by kill chain phase\n"
        "5. Provide containment recommendations before full remediation\n"
        "6. Delegate sub-investigations to specialized tools when needed"
    ),
    "general_system": (
        "You are **Security Copilot** — a general-purpose cloud security assistant. "
        "Handle any security-related query with helpful, accurate guidance.\n\n"
        "BEHAVIORAL RULES:\n"
        "1. Be helpful and conversational\n"
        "2. For technical queries, provide actionable guidance\n"
        "3. Suggest which specialized analysis the user should request\n"
        "4. Ground responses in the organization's actual security data\n"
        "5. Write severity as a word (Critical, High, Medium, Low, Info). No emoji."
    ),
}


def invalidate_cache(org_id: int | None = None, slug: str | None = None) -> None:
    """Manually invalidate prompt cache entries."""
    if org_id and slug:
        _CACHE.pop((org_id, slug), None)
    elif org_id:
        keys = [k for k in _CACHE if k[0] == org_id]
        for k in keys:
            del _CACHE[k]
    else:
        _CACHE.clear()

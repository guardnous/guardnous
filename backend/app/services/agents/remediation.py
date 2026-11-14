"""AI remediation: generate concrete fixes for security findings.

Two output modes:
  1. **Advice mode** (default) — markdown explanation with code blocks
  2. **Autofix mode** — real code patches via the autofix engine, ready for PR
"""
from __future__ import annotations

import asyncio
import logging

from app.services.agents.autofix import generate_fix
from app.services.agents.llm import LLMClient, LLMSettings

logger = logging.getLogger(__name__)

_REMEDIATION_SYSTEM = (
    "You are a cloud-security remediation engineer. Given one infrastructure-as-code "
    "security finding, produce a clear, correct fix. Structure your answer in markdown "
    "with these sections: **Summary**, **Why it matters**, **Fix** (with a fenced code "
    "block showing the corrected IaC when applicable), and **Verification**. Be precise "
    "and production-ready. Do not fabricate resource names beyond what is provided."
)


def _prompt(finding: dict) -> str:
    parts = [
        f"Finding: {finding.get('title')}",
        f"Rule: {finding.get('rule_id')}",
        f"Severity: {finding.get('severity')}",
        f"Cloud: {finding.get('cloud_provider')}",
        f"Resource: {finding.get('resource_type')} / {finding.get('resource_name')}",
        f"File: {finding.get('file_path')}:{finding.get('line_number')}",
        f"CVE: {finding.get('cve_id') or 'n/a'}",
    ]
    scanner = finding.get("detected_by")
    if scanner:
        parts.append(f"Detected by: {scanner}")
    parts.extend([
        "", f"Description:\n{finding.get('description') or 'n/a'}",
        "", f"Existing remediation note:\n{finding.get('remediation') or 'n/a'}",
        "", f"Code snippet:\n```\n{finding.get('code_snippet') or 'n/a'}\n```",
        "", "Produce the remediation.",
    ])
    return "\n".join(parts)


def _fallback(finding: dict) -> str:
    scanner = finding.get("detected_by")
    scanner_note = f" (identified by **{scanner}**)" if scanner else ""
    return (
        f"**Summary**\n\n`{finding.get('rule_id')}` — {finding.get('title')} "
        f"({finding.get('severity')}){scanner_note}.\n\n"
        "**Why it matters**\n\n"
        "This misconfiguration increases attack surface and may expose resources or data.\n\n"
        "**Fix**\n\n"
        f"{finding.get('remediation') or 'Apply least-privilege and enable encryption/logging for the affected resource.'}\n\n"
        "**Verification**\n\n"
        "Re-run the scan and confirm this finding no longer appears. "
        "_(Connect a live LLM provider for a code-level, resource-specific patch.)_"
    )


def generate_remediation(
    finding: dict,
    llm_settings: LLMSettings | None = None,
    *,
    autofix: bool = False,
) -> dict:
    """Return remediation for a single finding.

    Args:
        finding: Finding dict with title, rule_id, severity, etc.
        llm_settings: Optional LLM config override.
        autofix: If True, return real code fix via autofix engine instead of markdown advice.

    Returns:
        {"content": str, "provider": dict} — markdown advice or code patch.
        When autofix=True, also includes "code_fix" with the structured fix object.
    """
    # Autofix mode — delegate to the autofix engine for a real code patch
    if autofix:
        return _generate_autofix(finding, llm_settings)

    # Advice mode — markdown explanation
    llm = LLMClient(llm_settings)
    if not llm.is_live:
        return {"content": _fallback(finding), "provider": llm.info()}
    messages = [
        {"role": "system", "content": _REMEDIATION_SYSTEM},
        {"role": "user", "content": _prompt(finding)},
    ]
    resp = llm.chat_sync(messages)
    content = resp.content or _fallback(finding)
    return {"content": content, "provider": llm.info()}


def _generate_autofix(finding: dict, llm_settings: LLMSettings | None) -> dict:
    """Use the autofix engine to produce a real code fix."""
    try:
        fix = asyncio.get_event_loop().run_until_complete(
            generate_fix(finding, llm_settings)
        )
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            fix = loop.run_until_complete(generate_fix(finding, llm_settings))
        finally:
            loop.close()

    if fix.status == "fixed":
        content = (
            f"**Auto-Fix Generated** (identified by **{finding.get('detected_by', 'scanner')}**)\n\n"
            f"**Rule:** `{fix.rule_id}`\n"
            f"**File:** `{fix.file_path}`\n"
            f"**Confidence:** {fix.confidence:.0%}\n\n"
            f"```diff\n{fix.diff}\n```\n\n"
            f"**Explanation:** {fix.explanation}"
        )
    else:
        content = _fallback(finding)
        content += f"\n\n> ⚠️ Autofix attempted but could not generate a patch: {fix.explanation}"

    return {
        "content": content,
        "code_fix": {
            "status": fix.status,
            "diff": fix.diff,
            "patched_code": fix.patched_code,
            "confidence": fix.confidence,
            "explanation": fix.explanation,
        },
        "provider": {"name": "autofix-engine", "model": "mock+regex"},
    }

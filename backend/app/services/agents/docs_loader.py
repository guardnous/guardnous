"""
Runtime loader for AGENTS.md / SKILLS.md / PROMPTS.md.

Reads key sections from the project-root documentation and produces a
condensed capabilities block that is injected into the LLM system prompt.
This ensures the agent is self-aware of its own architecture, available
skills, and response-quality contract — grounded in the canonical docs
rather than ad-hoc hardcoded strings.

The docs are read once at import time and cached for the process lifetime.
"""
from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

# Resolve project root — works both locally and inside Docker container
# Docker mounts the repo at /app, so AGENTS.md lives at /app/AGENTS.md
_PROJECT_ROOT = Path(os.getenv("PROJECT_ROOT", "/app"))


def _read_doc(filename: str) -> str:
    """Read a .md file from the project root; return empty string on failure."""
    path = _PROJECT_ROOT / filename
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("Doc file not found: %s", path)
        return ""
    except Exception:
        logger.exception("Failed to read doc file: %s", path)
        return ""


def _extract_section(text: str, heading: str, *, level: int = 2) -> str:
    """Extract content under a markdown heading (## by default) until the next same-level heading."""
    prefix = "#" * level
    pattern = rf"^{prefix}\s+{re.escape(heading)}\s*$"
    match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    if not match:
        return ""
    start = match.end()
    # Find the next heading at the same or higher level
    next_heading = re.search(rf"^#{{{1},{level}}}\s+", text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(text)
    return text[start:end].strip()


def _extract_skill_table(skills_md: str) -> str:
    """Extract the skill catalog table from SKILLS.md."""
    # Look for the table under "Core Skills" or "Skill Catalog"
    for heading in ("Core Skills", "Skill Catalog"):
        section = _extract_section(skills_md, heading)
        if not section:
            section = _extract_section(skills_md, heading, level=3)
        if section:
            # Extract just the markdown table
            lines = section.split("\n")
            table_lines = [l for l in lines if l.strip().startswith("|")]
            if table_lines:
                return "\n".join(table_lines)
    return ""


@lru_cache(maxsize=1)
def load_capabilities_block() -> str:
    """Build a condensed capabilities reference for injection into the system prompt.

    This block tells the LLM:
    - What skills it has access to (from SKILLS.md)
    - Its design principles (from AGENTS.md)
    - Response quality contract (from PROMPTS.md)

    Returns a single string suitable for appending to the system prompt.
    """
    agents_md = _read_doc("AGENTS.md")
    skills_md = _read_doc("SKILLS.md")
    prompts_md = _read_doc("PROMPTS.md")

    if not any([agents_md, skills_md, prompts_md]):
        logger.info("No doc files found — capabilities block will be empty")
        return ""

    parts: list[str] = []
    parts.append("─────────────────────────────────────────")
    parts.append(" AGENT CAPABILITIES REFERENCE")
    parts.append("─────────────────────────────────────────")
    parts.append("")

    # 1. Skill catalog table
    skill_table = _extract_skill_table(skills_md)
    if skill_table:
        parts.append("**Available Skills** (callable via tools):")
        parts.append(skill_table)
        parts.append("")

    # 2. Design principles from AGENTS.md
    principles = _extract_section(agents_md, "Core Design Principles")
    if principles:
        # Extract just the principle headings (### lines)
        principle_lines = []
        for line in principles.split("\n"):
            if line.strip().startswith("### "):
                principle_lines.append(f"• {line.strip().lstrip('#').strip()}")
        if principle_lines:
            parts.append("**Design Principles:**")
            parts.extend(principle_lines)
            parts.append("")

    # 3. Response quality rules from PROMPTS.md
    quality = _extract_section(prompts_md, "Response Quality Contract")
    if not quality:
        quality = _extract_section(prompts_md, "Quality Rules")
    if not quality:
        # Try to find any section about quality/formatting
        quality = _extract_section(prompts_md, "Formatting Rules")
    if quality:
        # Keep it concise — first 500 chars
        parts.append("**Quality Contract:**")
        parts.append(quality[:500].strip())
        parts.append("")

    # 4. Prompt architecture summary from PROMPTS.md
    arch = _extract_section(prompts_md, "Prompt Architecture")
    if arch:
        # Just mention the layers, don't dump the ASCII art
        parts.append("**Prompt Layers:** Persona → Mode Prompt → Few-Shot Examples → Live Context")
        parts.append("")

    # 5. Skill design guidelines from SKILLS.md
    guidelines = _extract_section(skills_md, "Skill Design Guidelines")
    if not guidelines:
        guidelines = _extract_section(skills_md, "Design Guidelines")
    if guidelines:
        # Extract bullet points only
        bullets = [l.strip() for l in guidelines.split("\n")
                   if l.strip().startswith(("- ", "• ", "* "))]
        if bullets:
            parts.append("**Skill Design Rules:**")
            parts.extend(bullets[:6])  # Cap at 6 bullets
            parts.append("")

    result = "\n".join(parts)

    if len(result.strip()) < 50:
        logger.info("Capabilities block is too short — docs may be empty or malformatted")
        return ""

    logger.info("Loaded capabilities block: %d chars from docs", len(result))
    return result

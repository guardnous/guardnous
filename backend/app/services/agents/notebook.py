"""Agent Notebook — scratchpad for investigation state and findings.

A lightweight in-memory scratchpad that agents use to record intermediate
findings, evidence chains, and investigation state. Persists per-conversation
and enables multi-step reasoning across tool calls.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class NotebookEntry:
    """Single scratchpad entry."""
    key: str
    value: str
    source: str  # which tool/agent produced this
    timestamp: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)


class Notebook:
    """Per-conversation scratchpad for agent reasoning state."""

    def __init__(self) -> None:
        self._entries: list[NotebookEntry] = []
        self._findings: list[dict] = []
        self._goals: list[str] = []
        self._completed_goals: list[str] = []

    # ── Entries ─────────────────────────────────────────────────────
    def write(self, key: str, value: str, source: str = "agent", tags: list[str] | None = None) -> None:
        self._entries.append(NotebookEntry(key=key, value=value, source=source, tags=tags or []))

    def read(self, key: str) -> str | None:
        for entry in reversed(self._entries):
            if entry.key == key:
                return entry.value
        return None

    def read_all(self) -> list[NotebookEntry]:
        return list(self._entries)

    def read_by_tag(self, tag: str) -> list[NotebookEntry]:
        return [e for e in self._entries if tag in e.tags]

    # ── Findings accumulator ────────────────────────────────────────
    def add_finding(self, finding: dict) -> None:
        self._findings.append(finding)

    def get_findings(self) -> list[dict]:
        return list(self._findings)

    # ── Goal tracking ───────────────────────────────────────────────
    def set_goals(self, goals: list[str]) -> None:
        self._goals = goals
        self._completed_goals = []

    def complete_goal(self, goal: str) -> None:
        if goal in self._goals:
            self._completed_goals.append(goal)

    def pending_goals(self) -> list[str]:
        return [g for g in self._goals if g not in self._completed_goals]

    def progress(self) -> float:
        if not self._goals:
            return 1.0
        return len(self._completed_goals) / len(self._goals)

    # ── Context summary for LLM ─────────────────────────────────────
    def to_context_string(self) -> str:
        """Produce a compact summary for injection into the LLM system prompt."""
        if not self._entries and not self._findings:
            return ""

        parts = []
        if self._entries:
            parts.append("── Investigation Notebook ──")
            for e in self._entries[-10:]:  # last 10 entries only
                parts.append(f"• [{e.source}] {e.key}: {e.value[:200]}")

        if self._findings:
            parts.append(f"\n── Accumulated Findings ({len(self._findings)} total) ──")
            for f in self._findings[-5:]:
                severity = f.get("severity", "?")
                title = f.get("title", f.get("key", "untitled"))
                parts.append(f"• {severity}: {title}")

        if self._goals:
            pending = self.pending_goals()
            if pending:
                parts.append(f"\n── Pending Goals ({len(pending)}/{len(self._goals)}) ──")
                for g in pending:
                    parts.append(f"• ☐ {g}")

        return "\n".join(parts)

    def clear(self) -> None:
        self._entries.clear()
        self._findings.clear()
        self._goals.clear()
        self._completed_goals.clear()

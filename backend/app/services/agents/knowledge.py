"""Agent knowledge & learning store — remembers what worked.

The knowledge store captures successful remediation patterns so the agent
can apply proven fixes faster and with higher confidence on future findings.

Patterns are stored per rule_id and include:
- The fix that worked (diff, explanation)
- Success/failure counts (reinforcement signal)
- Tags for searchability (cloud provider, resource type, category)

In-memory store for now; can be backed by PostgreSQL for persistence.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FixPattern:
    """A recorded remediation pattern."""

    rule_id: str
    fix_type: str
    explanation: str
    diff_template: str
    tags: list[str] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0
    last_used: datetime | None = None
    source_finding_ids: list[int] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total

    @property
    def usage_count(self) -> int:
        return self.success_count + self.failure_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "fix_type": self.fix_type,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "usage_count": self.usage_count,
            "tags": self.tags,
            "last_used": self.last_used.isoformat() if self.last_used else None,
        }


class KnowledgeStore:
    """In-memory knowledge store for remediation patterns.

    Thread-safe for async usage (single writer at a time via GIL).
    For production persistence, extend with a DB-backed implementation.
    """

    def __init__(self):
        self._patterns: dict[str, list[FixPattern]] = defaultdict(list)
        self._stats: dict[str, int] = defaultdict(int)

    def record_success(
        self,
        rule_id: str,
        fix_type: str,
        explanation: str,
        diff: str,
        finding_id: int | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> FixPattern:
        """Record a successful remediation pattern."""
        pattern = self._find_or_create(rule_id, fix_type, explanation, diff, tags)
        pattern.success_count += 1
        pattern.last_used = datetime.now(timezone.utc)
        if finding_id:
            pattern.source_finding_ids.append(finding_id)
        if metadata:
            pattern.metadata.update(metadata)
        self._stats["total_successes"] += 1
        logger.info(
            "Knowledge: recorded success for %s (total: %d/%d)",
            rule_id, pattern.success_count, pattern.usage_count,
        )
        return pattern

    def record_failure(
        self,
        rule_id: str,
        fix_type: str,
        explanation: str,
        diff: str,
        finding_id: int | None = None,
        error: str | None = None,
    ) -> FixPattern:
        """Record a failed remediation attempt."""
        pattern = self._find_or_create(rule_id, fix_type, explanation, diff)
        pattern.failure_count += 1
        pattern.last_used = datetime.now(timezone.utc)
        if finding_id:
            pattern.source_finding_ids.append(finding_id)
        if error:
            pattern.metadata["last_error"] = error
        self._stats["total_failures"] += 1
        return pattern

    def get_patterns(self, rule_id: str) -> list[FixPattern]:
        """Get all known fix patterns for a rule ID."""
        return self._patterns.get(rule_id, [])

    def get_best_pattern(self, rule_id: str) -> FixPattern | None:
        """Get the highest-confidence pattern for a rule ID."""
        patterns = self._patterns.get(rule_id, [])
        if not patterns:
            return None
        return max(patterns, key=lambda p: (p.confidence, p.usage_count))

    def search_patterns(
        self,
        tags: list[str] | None = None,
        min_confidence: float = 0.0,
        fix_type: str | None = None,
    ) -> list[FixPattern]:
        """Search patterns by tags, confidence threshold, or fix type."""
        results: list[FixPattern] = []
        for patterns in self._patterns.values():
            for p in patterns:
                if p.confidence < min_confidence:
                    continue
                if fix_type and p.fix_type != fix_type:
                    continue
                if tags and not set(tags).intersection(set(p.tags)):
                    continue
                results.append(p)
        return sorted(results, key=lambda p: p.confidence, reverse=True)

    def get_stats(self) -> dict[str, Any]:
        """Get knowledge store statistics."""
        total_patterns = sum(len(ps) for ps in self._patterns.values())
        all_patterns = [p for ps in self._patterns.values() for p in ps]
        return {
            "total_rules_covered": len(self._patterns),
            "total_patterns": total_patterns,
            "total_successes": self._stats.get("total_successes", 0),
            "total_failures": self._stats.get("total_failures", 0),
            "avg_confidence": (
                sum(p.confidence for p in all_patterns) / len(all_patterns)
                if all_patterns else 0.0
            ),
            "top_patterns": [
                p.to_dict() for p in sorted(
                    all_patterns, key=lambda x: x.usage_count, reverse=True
                )[:10]
            ],
        }

    def export_json(self) -> str:
        """Export all patterns as JSON for persistence."""
        data = {}
        for rule_id, patterns in self._patterns.items():
            data[rule_id] = [p.to_dict() for p in patterns]
        return json.dumps(data, indent=2, default=str)

    def _find_or_create(
        self,
        rule_id: str,
        fix_type: str,
        explanation: str,
        diff: str,
        tags: list[str] | None = None,
    ) -> FixPattern:
        """Find an existing pattern or create a new one."""
        for p in self._patterns[rule_id]:
            if p.fix_type == fix_type and p.diff_template == diff:
                return p
        pattern = FixPattern(
            rule_id=rule_id,
            fix_type=fix_type,
            explanation=explanation,
            diff_template=diff,
            tags=tags or [],
        )
        self._patterns[rule_id].append(pattern)
        return pattern


# ── Singleton instance ───────────────────────────────────────────────

_global_store: KnowledgeStore | None = None


def get_knowledge_store() -> KnowledgeStore:
    """Get or create the global knowledge store singleton."""
    global _global_store
    if _global_store is None:
        _global_store = KnowledgeStore()
    return _global_store

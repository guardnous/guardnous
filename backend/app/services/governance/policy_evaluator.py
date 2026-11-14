"""Policy Condition Evaluator — the brain of the governance engine.

Evaluates JSON Logic policy conditions against cloud resource configurations.
Produces an evidence trail for every evaluation — not just pass/fail,
but exactly WHICH field was checked, what the expected vs actual value was.

Condition DSL:
  Combinators:  {"all": [...]}, {"any": [...]}, {"none": [...]}
  Leaf check:   {"field": "config.x.y", "op": "eq", "value": true}
  Operators:    eq, neq, gt, lt, gte, lte, in, not_in, contains, not_contains,
                exists, not_exists, regex, is_empty, is_not_empty, type_is

Example policy condition:
  {
    "all": [
      {"field": "config.public_access_block.block_public_acls", "op": "eq", "value": true},
      {"any": [
        {"field": "config.encryption.sse_algorithm", "op": "eq", "value": "aws:kms"},
        {"field": "config.encryption.sse_algorithm", "op": "eq", "value": "AES256"}
      ]}
    ]
  }
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    """One atomic check result — the auditable proof of what was evaluated."""
    field: str
    operator: str
    expected: Any
    actual: Any
    result: str  # "PASS" or "FAIL"
    message: str | None = None

    def to_dict(self) -> dict:
        d = {
            "field": self.field,
            "operator": self.operator,
            "expected": self.expected,
            "actual": self.actual,
            "result": self.result,
        }
        if self.message:
            d["message"] = self.message
        return d


@dataclass
class EvaluationResult:
    """Complete evaluation result for one (policy, resource) pair."""
    status: str  # PASS, FAIL, ERROR, NOT_APPLICABLE
    evidence: list[EvidenceItem] = field(default_factory=list)
    error_message: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    @property
    def failed(self) -> bool:
        return self.status == "FAIL"

    def to_dict(self) -> dict:
        d = {
            "status": self.status,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if self.error_message:
            d["error_message"] = self.error_message
        return d


class PolicyEvaluator:
    """Evaluates policy conditions against cloud resource configurations.

    Thread-safe, stateless — instantiate once and reuse.
    """

    # Supported operators and their evaluation functions
    OPERATORS = {
        "eq", "neq", "gt", "lt", "gte", "lte",
        "in", "not_in", "contains", "not_contains",
        "exists", "not_exists",
        "regex",
        "is_empty", "is_not_empty",
        "type_is",
    }

    COMBINATORS = {"all", "any", "none"}

    def evaluate(self, condition: dict, resource_config: dict) -> EvaluationResult:
        """Evaluate a policy condition tree against a resource configuration.

        Args:
            condition: The policy condition (JSON Logic DSL)
            resource_config: The full resource config dict (from CloudResource.config)

        Returns:
            EvaluationResult with status and evidence trail
        """
        if not condition:
            return EvaluationResult(status="NOT_APPLICABLE")

        try:
            evidence: list[EvidenceItem] = []
            passed = self._evaluate_node(condition, resource_config, evidence)
            return EvaluationResult(
                status="PASS" if passed else "FAIL",
                evidence=evidence,
            )
        except Exception as e:
            logger.error(f"Policy evaluation error: {e}", exc_info=True)
            return EvaluationResult(
                status="ERROR",
                error_message=str(e),
            )

    def _evaluate_node(self, node: dict, config: dict, evidence: list[EvidenceItem]) -> bool:
        """Recursively evaluate a condition node."""
        # Check for combinator nodes
        for combinator in self.COMBINATORS:
            if combinator in node:
                children = node[combinator]
                if not isinstance(children, list):
                    raise ValueError(f"Combinator '{combinator}' value must be a list, got {type(children).__name__}")
                return self._evaluate_combinator(combinator, children, config, evidence)

        # Must be a leaf check node
        if "field" not in node or "op" not in node:
            raise ValueError(f"Leaf condition must have 'field' and 'op', got keys: {list(node.keys())}")

        return self._evaluate_leaf(node, config, evidence)

    def _evaluate_combinator(
        self, combinator: str, children: list[dict], config: dict, evidence: list[EvidenceItem]
    ) -> bool:
        if combinator == "all":
            # AND — all must pass. Evaluate ALL for complete evidence, don't short-circuit.
            results = [self._evaluate_node(child, config, evidence) for child in children]
            return all(results)

        elif combinator == "any":
            # OR — at least one must pass. Evaluate ALL for complete evidence.
            results = [self._evaluate_node(child, config, evidence) for child in children]
            return any(results)

        elif combinator == "none":
            # NOT — none must pass (all must fail).
            results = [self._evaluate_node(child, config, evidence) for child in children]
            return not any(results)

        raise ValueError(f"Unknown combinator: {combinator}")

    def _evaluate_leaf(self, node: dict, config: dict, evidence: list[EvidenceItem]) -> bool:
        """Evaluate a single field check and produce evidence."""
        field_path = node["field"]
        operator = node["op"]
        expected = node.get("value")  # Some operators (exists, is_empty) don't need a value

        if operator not in self.OPERATORS:
            raise ValueError(f"Unknown operator: {operator}. Supported: {self.OPERATORS}")

        # Resolve the field value from the config using dot-notation path
        actual = self._resolve_field(config, field_path)

        # Evaluate the operator
        passed = self._apply_operator(operator, actual, expected)

        # Convert _MISSING sentinel to a JSON-safe string for evidence storage
        evidence_actual = "<MISSING>" if actual is _MISSING else actual

        evidence.append(EvidenceItem(
            field=field_path,
            operator=operator,
            expected=expected,
            actual=evidence_actual,
            result="PASS" if passed else "FAIL",
        ))

        return passed

    def _resolve_field(self, config: dict, field_path: str) -> Any:
        """Resolve a dot-notation field path against a nested config dict.

        Supports:
          - Simple paths: "config.encryption.enabled"
          - Array indexing: "config.rules[0].protocol"
          - Wildcard: "config.rules[*].protocol" → list of all values

        Returns _MISSING sentinel if field doesn't exist (distinct from None).
        """
        parts = self._parse_field_path(field_path)
        return self._walk(config, parts)

    def _parse_field_path(self, path: str) -> list[str | int]:
        """Parse 'config.rules[0].port' → ['config', 'rules', 0, 'port']"""
        tokens: list[str | int] = []
        for segment in path.split("."):
            # Check for array index: "rules[0]" or "rules[*]"
            match = re.match(r"^(\w+)\[(\d+|\*)\]$", segment)
            if match:
                tokens.append(match.group(1))
                idx = match.group(2)
                tokens.append("*" if idx == "*" else int(idx))
            else:
                tokens.append(segment)
        return tokens

    def _walk(self, obj: Any, parts: list) -> Any:
        """Walk a nested structure following the parsed path tokens."""
        if not parts:
            return obj

        head, *rest = parts

        if head == "*":
            # Wildcard — collect from all list elements
            if not isinstance(obj, list):
                return _MISSING
            return [self._walk(item, rest) for item in obj]

        if isinstance(head, int):
            if not isinstance(obj, (list, tuple)) or head >= len(obj):
                return _MISSING
            return self._walk(obj[head], rest)

        if isinstance(obj, dict):
            if head not in obj:
                return _MISSING
            return self._walk(obj[head], rest)

        return _MISSING

    def _apply_operator(self, op: str, actual: Any, expected: Any) -> bool:
        """Apply a comparison operator."""
        is_missing = actual is _MISSING

        # Existence checks
        if op == "exists":
            return not is_missing and actual is not None
        if op == "not_exists":
            return is_missing or actual is None

        # Emptiness checks
        if op == "is_empty":
            if is_missing or actual is None:
                return True
            if isinstance(actual, (str, list, dict)):
                return len(actual) == 0
            return False
        if op == "is_not_empty":
            if is_missing or actual is None:
                return False
            if isinstance(actual, (str, list, dict)):
                return len(actual) > 0
            return True

        # Type check
        if op == "type_is":
            if is_missing:
                return False
            type_map = {
                "string": str, "str": str,
                "int": int, "integer": int,
                "float": float, "number": (int, float),
                "bool": bool, "boolean": bool,
                "list": list, "array": list,
                "dict": dict, "object": dict,
                "null": type(None), "none": type(None),
            }
            expected_type = type_map.get(str(expected).lower())
            if expected_type is None:
                return False
            return isinstance(actual, expected_type)

        # For remaining operators, missing field → FAIL
        if is_missing:
            return False

        # Comparison operators
        if op == "eq":
            return actual == expected
        if op == "neq":
            return actual != expected

        if op == "gt":
            return _safe_compare(actual, expected, lambda a, b: a > b)
        if op == "lt":
            return _safe_compare(actual, expected, lambda a, b: a < b)
        if op == "gte":
            return _safe_compare(actual, expected, lambda a, b: a >= b)
        if op == "lte":
            return _safe_compare(actual, expected, lambda a, b: a <= b)

        # Membership
        if op == "in":
            if not isinstance(expected, list):
                return False
            return actual in expected
        if op == "not_in":
            if not isinstance(expected, list):
                return True
            return actual not in expected

        # String/list containment
        if op == "contains":
            if isinstance(actual, str):
                return str(expected) in actual
            if isinstance(actual, (list, set)):
                return expected in actual
            if isinstance(actual, dict):
                return expected in actual
            return False
        if op == "not_contains":
            if isinstance(actual, str):
                return str(expected) not in actual
            if isinstance(actual, (list, set)):
                return expected not in actual
            if isinstance(actual, dict):
                return expected not in actual
            return True

        # Regex
        if op == "regex":
            if not isinstance(actual, str) or not isinstance(expected, str):
                return False
            try:
                return bool(re.search(expected, actual))
            except re.error:
                return False

        return False


class _MissingSentinel:
    """Sentinel value distinguishing 'field not found' from 'field is None'."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "<MISSING>"

    def __bool__(self):
        return False


_MISSING = _MissingSentinel()


def _safe_compare(a: Any, b: Any, comparator) -> bool:
    """Safely compare two values, handling type mismatches."""
    try:
        # Try numeric comparison first
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return comparator(a, b)
        # String comparison
        if isinstance(a, str) and isinstance(b, str):
            return comparator(a, b)
        # Attempt coercion
        return comparator(float(a), float(b))
    except (TypeError, ValueError):
        return False

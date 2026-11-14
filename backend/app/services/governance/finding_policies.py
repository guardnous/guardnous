"""Matching of finding-based security policies.

A SecurityPolicy's ``rules`` column holds one of two shapes:

* a list of ``{"rule_id_prefixes": [...], "categories": [...]}`` dicts — matched
  against scan findings (this module);
* a dict with a ``condition`` tree — evaluated against cloud resources by the
  assessment engine and ignored here.

Used by the scan pipeline, the CI gate and ``POST /governance/policies/evaluate``
so all three agree on what violates a policy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from app.services.governance.compliance import finding_domains


def finding_rules(rules: Any) -> list[dict]:
    """Finding-matching rules of a policy; empty for cloud-condition policies."""
    if not isinstance(rules, list):
        return []
    return [
        r for r in rules
        if isinstance(r, dict) and (r.get("rule_id_prefixes") or r.get("categories"))
    ]


def is_cloud_policy(rules: Any) -> bool:
    if isinstance(rules, dict):
        return bool(rules.get("condition"))
    if isinstance(rules, list):
        return any(isinstance(r, dict) and r.get("condition") for r in rules)
    return False


_SCANNER_PREFIXES = ("TFSEC-", "TRIVY-")
_ID_SEPARATORS = "-_."


def _canonical(rule_id: str) -> str:
    """Rule ID without the scanner name our adapters prepend.

    tfsec reports ``TFSEC-AVD-AWS-0086`` and Trivy ``TRIVY-AWS-0086`` for the
    same check; both become ``AWS-0086`` so one policy entry covers both.
    """
    rid = (rule_id or "").strip().upper()
    for prefix in _SCANNER_PREFIXES:
        if rid.startswith(prefix):
            rid = rid[len(prefix):]
            break
    if rid.startswith("AVD-"):
        rid = rid[4:]
    return rid


def rule_id_matches(pattern: str, rule_id: str) -> bool:
    """True when *pattern* names this rule or a family it belongs to.

    A pattern matches the exact ID, or a whole leading segment of it:
    ``SD-TF`` matches ``SD-TF-003`` and ``SEC-AWS-`` matches ``SEC-AWS-001``,
    but ``CKV_AWS_1`` does not match ``CKV_AWS_19``.
    """
    pat, rid = _canonical(pattern), _canonical(rule_id)
    if not pat or not rid:
        return False
    if rid == pat:
        return True
    if not rid.startswith(pat):
        return False
    return pat[-1] in _ID_SEPARATORS or rid[len(pat)] in _ID_SEPARATORS


def finding_matches(rules: list[dict], finding: dict) -> bool:
    """True when a finding (dict with rule_id/category/title/description/resource_type) violates the rules."""
    rule_id = finding.get("rule_id") or ""
    domains: set[str] | None = None
    for rule in rules:
        if any(rule_id_matches(p, rule_id) for p in rule.get("rule_id_prefixes") or [] if p):
            return True
        cats = {str(c).lower() for c in rule.get("categories") or []}
        if cats:
            if domains is None:
                domains = finding_domains(
                    finding.get("category"), rule_id, finding.get("title"),
                    finding.get("description"), finding.get("resource_type"),
                )
            if domains & cats:
                return True
    return False


def active_exemption_keys(exceptions: Iterable[Any]) -> set[tuple]:
    """(policy_id | None, resource_id | None) pairs covered by approved, unexpired exceptions."""
    now = datetime.now(timezone.utc)
    keys: set[tuple] = set()
    for e in exceptions:
        if e.status != "approved":
            continue
        expiry = e.expiry_date or e.expires_at
        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < now:
                continue
        if e.policy_id or e.resource_id:
            keys.add((e.policy_id, e.resource_id))
    return keys


def is_exempt(keys: set[tuple], policy_id: int, resource_id: str) -> bool:
    """Exempt when an exception names this policy+resource, the resource for any policy, or the whole policy."""
    return (policy_id, resource_id) in keys or (None, resource_id) in keys or (policy_id, None) in keys


def applies_to_repo(target_repos: Any, repo_full_name: str | None) -> bool:
    """Policies without target_repos apply everywhere; scoped ones only to their repos."""
    if not target_repos:
        return True
    return bool(repo_full_name) and repo_full_name in target_repos

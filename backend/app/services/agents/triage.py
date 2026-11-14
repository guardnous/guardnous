"""AI triage: score & prioritize findings by real-world risk.

Three-layer triage pipeline:
  1. Heuristic pre-scoring (instant, deterministic, always runs)
  2. False-positive detection (pattern-based, reduces noise)
  3. AI contextual analysis (LLM-powered when available)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.services.agents.llm import LLMClient, LLMSettings

logger = logging.getLogger(__name__)

# ── Layer 1: Heuristic scoring ──────────────────────────────

_SEVERITY_PRIORITY = {"CRITICAL": 95, "HIGH": 78, "MEDIUM": 55, "LOW": 30, "INFO": 12}

_EXPOSURE_KEYWORDS = {
    "public": 8, "0.0.0.0/0": 10, "internet": 8, "::/0": 10,
    "ssh": 6, "rdp": 6, "open": 5, "unencrypted": 7, "wildcard": 6,
    "plaintext": 7, "http://": 6, "no authentication": 9,
}

_HIGH_VALUE_RESOURCES = {
    "database": 8, "rds": 8, "s3": 6, "storage": 5, "iam": 7,
    "kms": 8, "secrets": 9, "vault": 8, "admin": 7, "root": 9,
    "production": 6, "key": 7, "certificate": 6, "password": 8,
}


def _heuristic_score(f: dict) -> dict:
    """Deterministic risk scoring with multi-signal analysis."""
    base = _SEVERITY_PRIORITY.get((f.get("severity") or "LOW").upper(), 30)
    text = " ".join(str(v) for v in [
        f.get("title", ""), f.get("rule_id", ""), f.get("resource_name", ""),
        f.get("description", ""), f.get("file_path", ""),
    ]).lower()

    exposure_bump = sum(w for kw, w in _EXPOSURE_KEYWORDS.items() if kw in text)
    resource_bump = sum(w for kw, w in _HIGH_VALUE_RESOURCES.items() if kw in text)
    priority = min(100, base + exposure_bump + resource_bump)

    signals = []
    if exposure_bump > 0:
        signals.append("externally exposed")
    if resource_bump > 0:
        signals.append("high-value resource")
    if f.get("cve_id"):
        priority = min(100, priority + 5)
        signals.append(f"CVE {f['cve_id']}")

    if priority >= 85:
        action = "Remediate immediately"
    elif priority >= 60:
        action = "Fix this sprint"
    elif priority >= 40:
        action = "Schedule remediation"
    else:
        action = "Monitor / accept"

    rationale = f"{f.get('severity', 'UNKNOWN')} severity"
    if signals:
        rationale += " · " + " · ".join(signals)
    else:
        rationale += " · limited exposure"

    return {
        "id": f.get("id"),
        "priority": priority,
        "action": action,
        "rationale": rationale,
        "confidence": 0.65,
        "false_positive": False,
        "fp_reason": None,
        "detected_by": f.get("detected_by") or (f.get("metadata_") or {}).get("source"),
    }


# ── Layer 2: False-positive detection ───────────────────────

_FP_PATTERNS: list[tuple[str, str, str]] = [
    # (field, regex_pattern, reason)
    ("file_path", r"(test|spec|mock|fixture|example|sample|__test__|_test\.)", "Test/example file — unlikely to be deployed"),
    ("file_path", r"\.(md|txt|rst|doc)$", "Documentation file — not executable code"),
    ("title", r"(deprecated|legacy).*module", "Deprecated module — likely tracked separately"),
    ("rule_id", r"^CKV2?_.*_\d+$", "Generic Checkov rule — verify applicability"),
]

_FP_RESOURCE_PATTERNS = [
    (r"(example|sample|demo|test|placeholder)", "Resource name suggests non-production"),
]


def _detect_false_positive(f: dict) -> tuple[bool, str | None, float]:
    """Return (is_fp, reason, confidence_reduction)."""
    for field, pattern, reason in _FP_PATTERNS:
        val = str(f.get(field, ""))
        if re.search(pattern, val, re.IGNORECASE):
            return True, reason, 0.3

    resource = str(f.get("resource_name", "")).lower()
    for pattern, reason in _FP_RESOURCE_PATTERNS:
        if re.search(pattern, resource):
            return True, reason, 0.25

    return False, None, 0.0


# ── Layer 3: AI contextual analysis ─────────────────────────

def _get_triage_prompt(db_session=None, org_id: int | None = None) -> str:
    """Fetch triage prompt from registry (async-safe wrapper for sync code)."""
    _FALLBACK = (
        "You are a senior cloud-security triage engineer performing contextual risk analysis.\n\n"
        "For each finding, assess:\n"
        "1. **Real-world exploitability** — Can this actually be exploited? Is it internet-facing?\n"
        "2. **Blast radius** — What data/systems are at risk if exploited?\n"
        "3. **False positive likelihood** — Is this a test file, example code, or known benign pattern?\n"
        "4. **Scanner reliability** — Consider the scanner's known false-positive rate for this rule type.\n"
        "5. **Contextual risk** — File path, resource name, cloud provider context.\n\n"
        "Return STRICT JSON only, no markdown, no prose."
    )
    if not db_session or not org_id:
        return _FALLBACK
    try:
        import asyncio
        from app.services.prompt_registry import PromptRegistryService
        svc = PromptRegistryService(db_session, org_id)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            # Already in async context — can't nest asyncio.run; use fallback
            return _FALLBACK
        return asyncio.run(svc.get_prompt("triage_system")) or _FALLBACK
    except Exception:
        return _FALLBACK


_TRIAGE_SYSTEM = _get_triage_prompt()

_ACTION_CHOICES = (
    '"Remediate immediately" | "Fix this sprint" | "Schedule remediation" | "Monitor / accept"'
)


def _build_ai_prompt(findings: list[dict]) -> str:
    slim = []
    for f in findings:
        entry: dict[str, Any] = {
            "id": f.get("id"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "rule_id": f.get("rule_id"),
            "cloud": f.get("cloud_provider"),
            "resource": f.get("resource_name"),
            "file_path": f.get("file_path"),
            "cve": f.get("cve_id"),
        }
        if f.get("detected_by"):
            entry["scanner"] = f["detected_by"]
        slim.append(entry)

    return (
        "Findings:\n" + json.dumps(slim, default=str) + "\n\n"
        "For each finding return:\n"
        '{"id": <int>, "priority": <0-100>, '
        f'"action": <{_ACTION_CHOICES}>, '
        '"confidence": <0.0-1.0 how confident you are in this assessment>, '
        '"false_positive": <true|false>, '
        '"fp_reason": <string|null — reason if false positive>, '
        '"rationale": <one sentence explaining the risk assessment>}\n\n'
        'Respond as JSON: {"items": [ ... ]} sorted by priority descending.'
    )


def _parse_ai_items(content: str) -> list[dict]:
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    return data.get("items", []) if isinstance(data, dict) else []


# ── Public API ──────────────────────────────────────────────

def triage_findings(findings: list[dict], llm_settings: LLMSettings | None = None) -> dict:
    """Three-layer triage: heuristic → false-positive detection → AI contextual analysis."""
    llm = LLMClient(llm_settings)
    if not findings:
        return {"items": [], "provider": llm.info()}

    by_id = {f.get("id"): f for f in findings}

    # Layer 1 + 2: heuristic scoring + false-positive detection
    scored = []
    for f in findings:
        item = _heuristic_score(f)
        is_fp, fp_reason, conf_reduction = _detect_false_positive(f)
        if is_fp:
            item["false_positive"] = True
            item["fp_reason"] = fp_reason
            item["confidence"] = max(0.1, item["confidence"] - conf_reduction)
            item["priority"] = max(5, item["priority"] - 20)
            if item["priority"] < 40:
                item["action"] = "Monitor / accept"
        scored.append(item)

    # Layer 3: AI contextual analysis (when LLM available)
    if llm.is_live:
        try:
            messages = [
                {"role": "system", "content": _TRIAGE_SYSTEM},
                {"role": "user", "content": _build_ai_prompt(findings)},
            ]
            resp = llm.chat_sync(messages)
            ai_items = _parse_ai_items(resp.content)
            if ai_items:
                ai_by_id = {it.get("id"): it for it in ai_items}
                for item in scored:
                    ai = ai_by_id.get(item["id"])
                    if ai:
                        # Merge AI assessment — AI overrides heuristic with higher confidence
                        ai_conf = ai.get("confidence", 0.5)
                        if ai_conf > item["confidence"]:
                            item["priority"] = ai.get("priority", item["priority"])
                            item["action"] = ai.get("action", item["action"])
                            item["rationale"] = ai.get("rationale", item["rationale"])
                            item["confidence"] = ai_conf
                        if ai.get("false_positive"):
                            item["false_positive"] = True
                            item["fp_reason"] = ai.get("fp_reason") or item.get("fp_reason")
                logger.info("AI triage merged %d assessments", len(ai_items))
        except Exception:
            logger.warning("AI triage failed, using heuristic results", exc_info=True)

    scored.sort(key=lambda x: -x["priority"])
    return {"items": _enrich(scored, by_id), "provider": llm.info()}


def _enrich(items: list[dict], by_id: dict) -> list[dict]:
    out = []
    for it in items:
        src = by_id.get(it.get("id"), {})
        out.append({
            **it,
            "title": src.get("title"),
            "severity": src.get("severity"),
            "cloud_provider": src.get("cloud_provider"),
            "resource_name": src.get("resource_name"),
            "rule_id": src.get("rule_id"),
            "detected_by": it.get("detected_by") or src.get("detected_by"),
        })
    return out


# ── Layer 4: Chronic detection ──────────────────────────────

def detect_chronic_findings(
    current: list[dict],
    historical: list[list[dict]],
    recurrence_threshold: int = 3,
) -> list[dict]:
    """Identify findings that keep recurring across scans.

    A finding is "chronic" if the same rule_id + resource appears in
    >= recurrence_threshold historical scan results.

    Args:
        current: Current scan findings
        historical: List of prior scan result sets (newest first)
        recurrence_threshold: Min appearances to flag as chronic

    Returns:
        List of chronic finding dicts with recurrence metadata
    """
    # Build recurrence map: (rule_id, resource) → count
    recurrence: dict[tuple[str, str], int] = {}
    first_seen: dict[tuple[str, str], str] = {}

    for scan_findings in historical:
        seen_this_scan: set[tuple[str, str]] = set()
        for f in scan_findings:
            key = (f.get("rule_id", ""), f.get("resource_name") or f.get("file_path") or "")
            if key not in seen_this_scan:
                seen_this_scan.add(key)
                recurrence[key] = recurrence.get(key, 0) + 1
                if key not in first_seen:
                    created = f.get("created_at")
                    if created:
                        first_seen[key] = str(created)

    chronic = []
    for f in current:
        key = (f.get("rule_id", ""), f.get("resource_name") or f.get("file_path") or "")
        count = recurrence.get(key, 0) + 1  # +1 for current scan
        if count >= recurrence_threshold:
            chronic.append({
                **f,
                "is_chronic": True,
                "recurrence_count": count,
                "first_seen": first_seen.get(key),
                "chronic_risk": "HIGH" if count >= 5 else "MEDIUM",
                "recommendation": (
                    f"This issue has recurred {count} times. "
                    "Consider automated remediation or policy enforcement."
                ),
            })

    chronic.sort(key=lambda x: -x["recurrence_count"])
    return chronic


# ── Layer 5: Criticality scoring ────────────────────────────

_CRITICALITY_WEIGHTS = {
    "severity": 0.30,
    "exposure": 0.25,
    "asset_value": 0.20,
    "exploitability": 0.15,
    "recurrence": 0.10,
}

_EXPLOITABILITY_SIGNALS = {
    "public": 0.9, "internet-facing": 0.9, "0.0.0.0/0": 1.0,
    "unauthenticated": 0.95, "no encryption": 0.85,
    "default credentials": 1.0, "known exploit": 0.95,
    "cve": 0.7, "remote code execution": 1.0, "privilege escalation": 0.9,
}

_ASSET_VALUE_SIGNALS = {
    "production": 0.9, "database": 0.85, "secrets": 0.95,
    "iam": 0.8, "admin": 0.85, "root": 0.95,
    "customer data": 1.0, "pii": 0.95, "financial": 0.9,
    "backup": 0.7, "logging": 0.6,
}


def compute_criticality(
    finding: dict,
    recurrence_count: int = 0,
) -> dict[str, Any]:
    """Multi-factor criticality scoring (0-100).

    Combines: severity, exposure, asset value, exploitability, recurrence
    into a single weighted score with per-factor breakdown.
    """
    text = " ".join(str(v) for v in [
        finding.get("title", ""), finding.get("description", ""),
        finding.get("resource_name", ""), finding.get("rule_id", ""),
        finding.get("file_path", ""),
    ]).lower()

    # Severity factor (0-1)
    sev_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}
    severity_score = sev_map.get((finding.get("severity") or "LOW").upper(), 0.25)

    # Exposure factor (0-1)
    exposure_signals = [v for kw, v in _EXPOSURE_KEYWORDS.items() if kw in text]
    exposure_score = min(1.0, sum(exposure_signals) / 15) if exposure_signals else 0.1

    # Asset value factor (0-1)
    asset_signals = [v for kw, v in _ASSET_VALUE_SIGNALS.items() if kw in text]
    asset_score = max(asset_signals) if asset_signals else 0.3

    # Exploitability factor (0-1)
    exploit_signals = [v for kw, v in _EXPLOITABILITY_SIGNALS.items() if kw in text]
    exploit_score = max(exploit_signals) if exploit_signals else 0.2
    if finding.get("cve_id"):
        exploit_score = max(exploit_score, 0.7)

    # Recurrence factor (0-1)
    recurrence_score = min(1.0, recurrence_count / 5) if recurrence_count > 0 else 0.0

    # Weighted composite
    composite = (
        _CRITICALITY_WEIGHTS["severity"] * severity_score
        + _CRITICALITY_WEIGHTS["exposure"] * exposure_score
        + _CRITICALITY_WEIGHTS["asset_value"] * asset_score
        + _CRITICALITY_WEIGHTS["exploitability"] * exploit_score
        + _CRITICALITY_WEIGHTS["recurrence"] * recurrence_score
    )
    final_score = round(composite * 100)

    # Classification
    if final_score >= 80:
        classification = "CRITICAL"
    elif final_score >= 60:
        classification = "HIGH"
    elif final_score >= 40:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    return {
        "criticality_score": final_score,
        "classification": classification,
        "factors": {
            "severity": round(severity_score, 2),
            "exposure": round(exposure_score, 2),
            "asset_value": round(asset_score, 2),
            "exploitability": round(exploit_score, 2),
            "recurrence": round(recurrence_score, 2),
        },
        "weights": _CRITICALITY_WEIGHTS,
    }

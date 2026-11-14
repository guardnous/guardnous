"""Compliance control evaluation against scan findings.

One code path produces every compliance number shown in the product (framework
list, dashboard, control drill-down, persisted evaluation), so they cannot
disagree.

How a control is judged:
  * No completed scan for the organization  -> ``not_assessed`` (never "passed").
  * Control has no technical signal in scan data (physical security, training,
    HR, legal ...) -> ``manual``. It is excluded from the score and must be
    attested by a person.
  * Otherwise the control fails when at least one open finding falls in one of
    the control's security domains, and passes when none does.

A finding's domains are its scanner category plus domains inferred from its rule
id, title, description and resource type. Scanners label most IaC results simply
"iac"; without the inference an S3 encryption finding and an open security group
would be indistinguishable and every control would fail on any finding.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.scan import Scan

# Controls that IaC/secret/dependency scanning cannot evidence at all.
MANUAL_CONTROLS = frozenset({
    "A.6.1", "A.7.1", "A.18.1", "CC3.1", "CIS-9", "CIS-17", "CIS-18",
})

# Controls about configuration baselines, where any infrastructure
# misconfiguration is relevant. Everywhere else the generic "iac" label is
# dropped so a control only reacts to findings in its own domain.
GENERIC_IAC_CONTROLS = frozenset({"CM-2", "CM-6", "CIS-4", "2.1", "A.12.1", "CC8.1"})

_DOMAIN_PATTERNS: dict[str, re.Pattern] = {
    "encryption": re.compile(
        r"encrypt|\bkms\b|\bcmk\b|\btls\b|\bssl\b|https|\bsse\b|at[- ]rest|in[- ]transit|cipher", re.I),
    "network": re.compile(
        r"security.?group|0\.0\.0\.0/0|::/0|ingress|egress|firewall|public.?ip|publicly.?accessible|"
        r"open.?port|\bssh\b|\brdp\b|\bnsg\b|\bcidr\b|\bvpc\b|subnet|network", re.I),
    "iam": re.compile(
        r"\biam\b|privilege|\bmfa\b|multi.?factor|permission|access.?key|\brbac\b|principal|"
        r"assume.?role|wildcard|administrator|least.?privilege|\brole\b", re.I),
    "logging": re.compile(r"logging|\blogs?\b|cloudtrail|audit|flow.?log|diagnostic", re.I),
    "monitoring": re.compile(r"monitor|alarm|alert|cloudwatch|guardduty|detective", re.I),
    "storage": re.compile(r"\bs3\b|bucket|blob|storage.?account|versioning|backup|snapshot|\bebs\b|\bdisk\b", re.I),
    "secrets": re.compile(r"secret|password|credential|api.?key|private.?key|hard.?coded|\btoken\b", re.I),
}

_CATEGORY_ALIASES = {
    "secret": "secrets",
    "dependency": "sca",
    "dependencies": "sca",
    "vulnerability": "cve",
    "misconfiguration": "iac",
    "security": "iac",
}


def finding_domains(
    category: str | None,
    rule_id: str | None = None,
    title: str | None = None,
    description: str | None = None,
    resource_type: str | None = None,
) -> set[str]:
    """Security domains a finding belongs to."""
    domains: set[str] = set()
    cat = (category or "").strip().lower()
    if cat:
        domains.add(_CATEGORY_ALIASES.get(cat, cat))
    text = " ".join(p for p in (rule_id, title, description, resource_type) if p)
    if text:
        for domain, pattern in _DOMAIN_PATTERNS.items():
            if pattern.search(text):
                domains.add(domain)
    return domains


@dataclass
class OpenFinding:
    id: int
    scan_id: int
    category: str | None
    severity: str | None
    title: str | None
    rule_id: str | None
    resource_type: str | None
    file_path: str | None
    line_number: int | None
    domains: set[str] = field(default_factory=set)


@dataclass
class ControlResult:
    status: str  # passed | failed | not_assessed | manual
    categories: list[str]
    open_findings: int = 0
    evidence: list[dict] = field(default_factory=list)


class ComplianceEvaluator:
    """Evaluates controls for one organization. Build with :meth:`load`."""

    def __init__(self, control_map: dict[str, dict[str, Any]], scan_count: int, findings: list[OpenFinding]):
        self._control_map = control_map
        self.scan_count = scan_count
        self.findings = findings
        self.domain_counts: dict[str, int] = {}
        for f in findings:
            for d in f.domains:
                self.domain_counts[d] = self.domain_counts.get(d, 0) + 1

    @classmethod
    async def load(cls, db: AsyncSession, org_id: int, control_map: dict[str, dict[str, Any]]) -> "ComplianceEvaluator":
        scan_count = await db.scalar(
            select(func.count(Scan.id)).where(Scan.organization_id == org_id, Scan.status == "completed")
        ) or 0
        findings: list[OpenFinding] = []
        if scan_count:
            rows = (await db.execute(
                select(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .where(
                    Scan.organization_id == org_id,
                    Scan.status == "completed",
                    Finding.is_fixed == False,  # noqa: E712
                    Finding.is_ignored == False,  # noqa: E712
                )
            )).scalars().all()
            findings = [
                OpenFinding(
                    id=f.id, scan_id=f.scan_id, category=f.category, severity=f.severity,
                    title=f.title, rule_id=f.rule_id, resource_type=f.resource_type,
                    file_path=f.file_path, line_number=f.line_number,
                    domains=finding_domains(f.category, f.rule_id, f.title, f.description, f.resource_type),
                )
                for f in rows
            ]
        return cls(control_map, scan_count, findings)

    def categories_for(self, control_id: str) -> list[str]:
        """Domains that can fail this control; empty means it needs manual attestation."""
        if control_id in MANUAL_CONTROLS:
            return []
        mapping = self._control_map.get(control_id)
        if not mapping:
            return []
        cats = list(mapping.get("categories", []))
        if control_id not in GENERIC_IAC_CONTROLS:
            cats = [c for c in cats if c != "iac"]
        return cats

    def matching_findings(self, control_id: str) -> list[OpenFinding]:
        cats = set(self.categories_for(control_id))
        if not cats:
            return []
        return [f for f in self.findings if f.domains & cats]

    def evaluate(self, control_id: str) -> ControlResult:
        cats = self.categories_for(control_id)
        if not cats:
            return ControlResult(status="manual", categories=[])
        if self.scan_count == 0:
            return ControlResult(status="not_assessed", categories=cats)
        matches = self.matching_findings(control_id)
        if not matches:
            return ControlResult(status="passed", categories=cats)
        return ControlResult(
            status="failed",
            categories=cats,
            open_findings=len(matches),
            evidence=[
                {"category": c, "open_findings": self.domain_counts[c]}
                for c in cats if self.domain_counts.get(c)
            ],
        )

    def summarize(self, control_ids: Iterable[str]) -> dict[str, Any]:
        """Aggregate counts and score for a set of controls (one framework)."""
        passed = failed = manual = not_assessed = 0
        for cid in control_ids:
            status = self.evaluate(cid).status
            if status == "passed":
                passed += 1
            elif status == "failed":
                failed += 1
            elif status == "manual":
                manual += 1
            else:
                not_assessed += 1
        assessed = passed + failed
        return {
            "passed": passed,
            "failed": failed,
            "manual": manual,
            "not_assessed": not_assessed,
            "assessed": assessed,
            # None, not 0 or 100: an unassessed framework has no score.
            "score": round(passed / assessed * 100, 1) if assessed else None,
        }

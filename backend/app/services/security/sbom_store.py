"""The dependency inventory of a scan, and what is built from it.

A repository scan stores the dependencies it parsed (``store_scan_inventory``).
From that inventory an SBOM (CycloneDX 1.5) and a summary are built on request:
vulnerabilities are matched against the CVE table and the scan's own findings,
licences are looked up when ``DEPENDENCY_LICENSE_LOOKUP`` is on.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.cve import CVE
from app.models.finding import Finding
from app.models.sbom import ScanDependencyInventory
from app.models.scan import Scan
from app.services.security import licenses as lic
from app.services.security.dependency_analyzer import (
    Dependency,
    DependencyAnalyzer,
    concrete_version,
    normalized_name,
    package_url,
)

logger = logging.getLogger(__name__)

LICENSE_SETTING = "DEPENDENCY_LICENSE_LOOKUP"
RETRY_INCOMPLETE_AFTER = timedelta(minutes=10)


# ── Storing (called from the scan job, synchronous session) ─────────

def store_scan_inventory(db, scan, dependencies: list[Dependency]) -> None:
    """Keep the dependencies a scan parsed. Never fails the scan."""
    try:
        components = [
            {
                "ecosystem": d.ecosystem,
                "name": d.name,
                "version": d.version,
                "path": d.file_path,
                "dev": bool(d.is_dev),
                "direct": bool(d.direct),
            }
            for d in dependencies
        ]
        with db.begin_nested():
            row = db.query(ScanDependencyInventory).filter(ScanDependencyInventory.scan_id == scan.id).first()
            if row is None:
                row = ScanDependencyInventory(scan_id=scan.id, organization_id=scan.organization_id)
                db.add(row)
            row.components = components
            row.component_count = len(components)
            row.licenses = None
    except Exception:
        logger.warning("Could not store the dependency inventory of scan %s", scan.id, exc_info=True)


# ── Reading ─────────────────────────────────────────────────────────

async def load_inventory(db: AsyncSession, scan: Scan) -> ScanDependencyInventory | None:
    return (await db.execute(select(ScanDependencyInventory).where(
        ScanDependencyInventory.scan_id == scan.id,
        ScanDependencyInventory.organization_id == scan.organization_id,
    ))).scalar_one_or_none()


def dependencies_of(inventory: ScanDependencyInventory) -> list[Dependency]:
    return [
        Dependency(
            name=c.get("name") or "",
            version=c.get("version"),
            ecosystem=c.get("ecosystem") or "unknown",
            file_path=c.get("path") or "",
            is_dev=bool(c.get("dev")),
            direct=c.get("direct", True),
        )
        for c in (inventory.components or [])
        if c.get("name")
    ]


def unique_components(dependencies: list[Dependency]) -> list[dict]:
    """One entry per package version, as in the SBOM: production wins over development."""
    merged: dict[str, dict] = {}
    for d in dependencies:
        purl = package_url(d.ecosystem, d.name, d.version)
        entry = merged.get(purl)
        if entry is None:
            entry = merged[purl] = {
                "purl": purl,
                "ecosystem": d.ecosystem,
                "name": d.name,
                "version": concrete_version(d.version),
                "declared_version": d.version,
                "dev": True,
                "paths": [],
            }
        entry["dev"] = entry["dev"] and d.is_dev
        if d.file_path and d.file_path not in entry["paths"]:
            entry["paths"].append(d.file_path)
    return list(merged.values())


# ── Licences ────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _lookup_is_due(stored: dict | None) -> bool:
    if not stored:
        return True
    if stored.get("complete"):
        return False
    try:
        attempted = datetime.fromisoformat(stored.get("attempted_at") or "")
    except ValueError:
        return True
    return _now() - attempted >= RETRY_INCOMPLETE_AFTER


async def ensure_licenses(
    db: AsyncSession,
    inventory: ScanDependencyInventory,
    components: list[dict],
    *,
    force: bool = False,
) -> dict | None:
    """The licence results of an inventory, looked up first when that is due.

    Returns the stored result ``{"packages": {purl: {"licenses", "source"}}, ...}``
    or None when licences were never checked. Nothing is looked up while the
    setting is off; results stored earlier are still returned.
    """
    stored = inventory.licenses
    if not settings.DEPENDENCY_LICENSE_LOOKUP or not (force or _lookup_is_due(stored)):
        return stored

    previous = {} if force else dict((stored or {}).get("packages") or {})
    packages: dict[str, dict] = {}
    pending: dict[tuple, str] = {}
    for c in components:
        earlier = previous.get(c["purl"])
        if earlier and earlier.get("source") in lic.FINAL_SOURCES:
            packages[c["purl"]] = earlier
        else:
            pending[(c["ecosystem"], c["name"], c["version"])] = c["purl"]

    looked_up = await lic.lookup_licenses(db, list(pending), use_cache=not force)
    for key, purl in pending.items():
        packages[purl] = looked_up[key]

    unfinished = sum(1 for p in packages.values() if p["source"] not in lic.FINAL_SOURCES)
    inventory.licenses = {
        "attempted_at": _now().isoformat(),
        "complete": unfinished == 0,
        "packages": packages,
    }
    await db.commit()
    return inventory.licenses


def license_summary(components: list[dict], stored: dict | None) -> dict:
    enabled = bool(settings.DEPENDENCY_LICENSE_LOOKUP)
    if not stored:
        return {
            "status": "not_checked",
            "lookup_enabled": enabled,
            "setting": LICENSE_SETTING,
            "message": (
                "Licences have not been looked up yet for this assessment." if enabled else
                f"Licences are not checked. Set {LICENSE_SETTING}=true to look them up at deps.dev; "
                "this sends package names and versions to that service."
            ),
        }

    packages = stored.get("packages") or {}
    by_category = dict.fromkeys(lic.CATEGORIES, 0)
    unknown_reasons: dict[str, int] = {}
    review: list[dict] = []
    for c in components:
        info = packages.get(c["purl"]) or {"licenses": [], "source": lic.SKIPPED}
        category = lic.classify_licenses(info.get("licenses"))
        by_category[category] += 1
        if category == lic.UNKNOWN:
            source = info.get("source")
            if source in (lic.FOUND, lic.CACHED):
                reason = "unrecognised_license" if info.get("licenses") else "no_license_data"
            else:
                reason = source or lic.SKIPPED
            unknown_reasons[reason] = unknown_reasons.get(reason, 0) + 1
        if lic.license_status(category, c["dev"]) == lic.REVIEW_NEEDED:
            review.append({
                "package": c["name"],
                "version": c["version"] or c["declared_version"],
                "ecosystem": c["ecosystem"],
                "license": " AND ".join(info.get("licenses") or []),
                "category": category,
                "scope": "development" if c["dev"] else "production",
                "manifest_path": c["paths"][0] if c["paths"] else None,
                "manifest_paths": c["paths"],
            })

    review.sort(key=lambda r: (r["category"] != lic.RESTRICTIVE, r["package"]))
    return {
        "status": "checked" if stored.get("complete") else "partial",
        "lookup_enabled": enabled,
        "setting": LICENSE_SETTING,
        "source": "deps.dev",
        "checked_at": stored.get("attempted_at"),
        "by_category": by_category,
        "unknown_reasons": unknown_reasons,
        "not_looked_up": unknown_reasons.get(lic.SKIPPED, 0) + unknown_reasons.get(lic.FAILED, 0),
        "review_needed_count": len(review),
        "review_needed": review,
    }


# ── Vulnerabilities ─────────────────────────────────────────────────

# How advisory sources (GHSA, OSV) name the ecosystems; stored in the "vendor" field of
# an affected package. Anything else in that field is a CPE vendor from NVD.
_ADVISORY_ECOSYSTEMS = {
    "npm": {"npm"},
    "pypi": {"pip", "pypi"},
    "maven": {"maven"},
    "go": {"go"},
    "rubygems": {"rubygems"},
    "cargo": {"rust", "crates.io"},
    "composer": {"composer", "packagist"},
}
_ALL_ADVISORY_ECOSYSTEMS = set().union(*_ADVISORY_ECOSYSTEMS.values()) | {
    "nuget", "pub", "actions", "erlang", "swift", "hex",
}


def _version_tuple(version: str | None) -> tuple[int, ...] | None:
    m = re.match(r"^v?(\d+(?:\.\d+)*)", (version or "").strip())
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def _compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def _advisory_match(component: dict, affected: dict) -> str | None:
    """How well an advisory entry (ecosystem + package name) fits, or None when it does not."""
    ours = _version_tuple(component["version"])
    clause = re.match(r"^\s*(<=|>=|<|>|=)\s*(\S+)", affected.get("version_start") or "")
    theirs = _version_tuple(clause.group(2)) if clause else None
    if not ours or not clause or not theirs:
        return "not checked"
    cmp, op = _compare(ours, theirs), clause.group(1)
    holds = {"<": cmp < 0, "<=": cmp <= 0, ">": cmp > 0, ">=": cmp >= 0, "=": cmp == 0}[op]
    if not holds:
        return None
    return "declared version is inside the affected range" if op in ("<", "<=", "=") else \
        "declared version is above the lower bound; the upper bound is not known"


def _cpe_match(component: dict, affected: dict) -> str | None:
    """A CPE product only counts when its version range is known and contains our version."""
    ours = _version_tuple(component["version"])
    start, end = _version_tuple(affected.get("version_start")), _version_tuple(affected.get("version_end"))
    if not ours or not (start or end):
        return None
    if start and _compare(ours, start) < 0:
        return None
    if end and _compare(ours, end) >= 0:
        return None
    return "declared version is inside the affected range"


def _match_names(component: dict) -> set[str]:
    name = normalized_name(component["ecosystem"], component["name"]).lower()
    return {name, name.replace("-", "_")} if component["ecosystem"] == "pypi" else {name}


async def _cve_matches(db: AsyncSession, components: list[dict]) -> list[dict]:
    by_name: dict[str, list[dict]] = {}
    for c in components:
        for name in _match_names(c):
            by_name.setdefault(name, []).append(c)
    if not by_name:
        return []

    rows: dict[int, CVE] = {}
    names = sorted(by_name)
    as_text = cast(CVE.affected_packages, String)
    for i in range(0, len(names), 40):
        chunk = names[i:i + 40]
        found = (await db.execute(
            select(CVE).where(or_(*(as_text.ilike(f'%"{n}"%') for n in chunk)))
        )).scalars().all()
        rows.update({r.id: r for r in found})

    matches: list[dict] = []
    for cve in rows.values():
        refs: dict[str, tuple[str, str]] = {}
        for affected in cve.affected_packages or []:
            if not isinstance(affected, dict):
                continue
            product = str(affected.get("product") or "").lower()
            vendor = str(affected.get("vendor") or "").lower()
            for c in by_name.get(product, []):
                if vendor in _ALL_ADVISORY_ECOSYSTEMS:
                    if vendor not in _ADVISORY_ECOSYSTEMS.get(c["ecosystem"], set()):
                        continue
                    basis, version_check = "ecosystem and package name", _advisory_match(c, affected)
                elif ":" in c["name"] or "/" in c["name"]:
                    continue        # a CPE product name says nothing about a namespaced package
                else:
                    basis = "CPE product name (vendor not verified) and version range"
                    version_check = _cpe_match(c, affected)
                if version_check:
                    refs.setdefault(c["purl"], (basis, version_check))
        if not refs:
            continue
        bases = sorted({b for b, _ in refs.values()})
        checks = sorted({v for _, v in refs.values()})
        fixes = [str(f) for f in (cve.fix_versions or []) if f]
        properties = {
            "guardnous:match_basis": "; ".join(bases),
            "guardnous:version_check": "; ".join(checks),
        }
        if cve.is_kev:
            properties["guardnous:cisa_kev"] = "true"
        if cve.epss_score is not None:
            properties["guardnous:epss_score"] = cve.epss_score
        matches.append({
            "id": cve.cve_id,
            "severity": cve.severity,
            "score": cve.cvss_score,
            "description": (cve.description or "")[:1000] or None,
            "recommendation": f"Fixed versions listed by the advisory: {', '.join(fixes)}" if fixes else None,
            "source": _source(cve.cve_id),
            "refs": list(refs),
            "detail": (
                f"Matched by {'; '.join(bases)}. Version check: {'; '.join(checks)}. "
                "Versions are the ones declared in the manifest, not resolved from a lock file, "
                "so confirm against the installed version."
            ),
            "properties": properties,
        })
    return matches


def _source(vuln_id: str) -> dict:
    if vuln_id.upper().startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"}
    if vuln_id.upper().startswith("GHSA-"):
        return {"name": "GitHub Advisories", "url": f"https://github.com/advisories/{vuln_id}"}
    return {"name": "GuardNous"}


async def _finding_matches(db: AsyncSession, scan: Scan, components: list[dict]) -> list[dict]:
    """CVEs the scan itself reported; tied to a component only when the finding names it."""
    findings = (await db.execute(select(Finding).where(
        Finding.scan_id == scan.id,
        Finding.organization_id == scan.organization_id,
        Finding.cve_id.isnot(None),
        Finding.cve_id != "",
    ))).scalars().all()
    if not findings:
        return []

    by_name: dict[str, list[str]] = {}
    for c in components:
        by_name.setdefault(c["name"].lower(), []).append(c["purl"])
    cves = {
        c.cve_id: c for c in (await db.execute(
            select(CVE).where(CVE.cve_id.in_({f.cve_id for f in findings}))
        )).scalars().all()
    }

    matches = []
    for f in findings:
        meta = f.metadata_ if isinstance(f.metadata_, dict) else {}
        named = {str(v).lower() for v in (f.resource_name, meta.get("package"), meta.get("package_name")) if v}
        refs = [purl for name in named for purl in by_name.get(name, [])]
        cve = cves.get(f.cve_id)
        properties = {"guardnous:match_basis": "scan finding", "guardnous:finding_id": f.id}
        if cve is not None and cve.is_kev:
            properties["guardnous:cisa_kev"] = "true"
        if cve is not None and cve.epss_score is not None:
            properties["guardnous:epss_score"] = cve.epss_score
        matches.append({
            "id": f.cve_id,
            "severity": (cve.severity if cve is not None else None) or f.severity,
            "score": cve.cvss_score if cve is not None else None,
            "description": ((cve.description if cve is not None else None) or f.title or "")[:1000] or None,
            "recommendation": f.remediation,
            "source": _source(f.cve_id),
            "refs": refs,
            "detail": (
                f"Reported by finding #{f.id} of this assessment"
                + ("." if refs else "; the finding does not name a package, so it is attached to the repository.")
            ),
            "properties": properties,
        })
    return matches


async def match_vulnerabilities(db: AsyncSession, scan: Scan, components: list[dict]) -> list[dict]:
    return await _cve_matches(db, components) + await _finding_matches(db, scan, components)


# ── SBOM and summary ────────────────────────────────────────────────

def repository_label(scan: Scan) -> str:
    name = scan.repository_name or scan.repository
    if name and scan.account_name and "/" not in name:
        return f"{scan.account_name}/{name}"
    return name or scan.file_name or f"scan-{scan.id}"


async def build_sbom(db: AsyncSession, scan: Scan, inventory: ScanDependencyInventory) -> dict:
    dependencies = dependencies_of(inventory)
    components = unique_components(dependencies)
    stored = await ensure_licenses(db, inventory, components)
    vulnerabilities = await match_vulnerabilities(db, scan, components)
    sbom = DependencyAnalyzer.export_sbom(
        dependencies,
        repo_name=repository_label(scan),
        licenses={purl: p.get("licenses") or [] for purl, p in ((stored or {}).get("packages") or {}).items()},
        vulnerabilities=vulnerabilities,
        tool_version=settings.APP_VERSION,
    )
    sbom["metadata"]["properties"].append({
        "name": "guardnous:licenses",
        "value": "deps.dev" if stored else "not checked",
    })
    return sbom


async def build_summary(db: AsyncSession, scan: Scan, inventory: ScanDependencyInventory) -> dict:
    dependencies = dependencies_of(inventory)
    components = unique_components(dependencies)
    stored = await ensure_licenses(db, inventory, components)
    vulnerabilities = await match_vulnerabilities(db, scan, components)

    known = {c["purl"] for c in components}
    affected = {ref for v in vulnerabilities for ref in v["refs"] if ref in known}
    by_ecosystem: dict[str, int] = {}
    for c in components:
        by_ecosystem[c["ecosystem"]] = by_ecosystem.get(c["ecosystem"], 0) + 1
    development = sum(1 for c in components if c["dev"])

    return {
        "scan_id": scan.id,
        "repository": repository_label(scan),
        "format": "CycloneDX 1.5",
        "stored_at": inventory.created_at.isoformat() if inventory.created_at else None,
        "component_count": len(components),
        "declarations": len(dependencies),
        "manifests": len({d.file_path for d in dependencies}),
        "by_ecosystem": dict(sorted(by_ecosystem.items(), key=lambda kv: -kv[1])),
        "by_scope": {"production": len(components) - development, "development": development},
        "without_version": sum(1 for c in components if not c["version"]),
        "dependency_depth": "direct",
        "version_source": "manifest",
        "vulnerable_components": len(affected),
        "vulnerabilities": len({v["id"] for v in vulnerabilities}),
        "licenses": license_summary(components, stored),
    }

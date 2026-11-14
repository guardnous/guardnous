"""CVE Service — multi-source vulnerability intelligence.

Sources (authoritative, in priority order):
  1. NIST NVD  — https://services.nvd.nist.gov/rest/json/cves/2.0
  2. GitHub Advisory Database (GHSA) — https://api.github.com/advisories
  3. OSV (Google Open Source Vulnerabilities) — https://api.osv.dev/v1/vulns
  4. FIRST EPSS — https://api.first.org/data/v1/epss  (exploit-probability enrichment)

All reference URLs are tagged with their source domain and filtered to surface
official sources first (NVD, MITRE, GHSA, vendor advisories), while deprioritizing
third-party aggregators and foreign-language databases.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
import requests
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, update, func
from app.core.config import settings
from app.models.cve import CVE

logger = logging.getLogger(__name__)

# Authoritative reference domains (shown first in UI)
_TRUSTED_DOMAINS = (
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "github.com/advisories",
    "github.com/security", "access.redhat.com", "security.ubuntu.com",
    "msrc.microsoft.com", "security.apache.org", "www.debian.org/security",
    "kb.cert.org", "www.cisa.gov", "osv.dev",
)

# Domains to deprioritize (third-party aggregators, non-English databases)
_DEPRIORITIZED_DOMAINS = (
    "vuldb.com", "cvedetails.com", "exploit-db.com",
    "seebug.org", "cnvd.org.cn", "cnnvd.org.cn",
    "packetstormsecurity.com", "seclists.org",
)


def _classify_reference(url: str) -> str:
    """Classify a reference URL as 'official', 'vendor', 'aggregator', or 'other'."""
    lower = url.lower()
    if any(d in lower for d in _TRUSTED_DOMAINS):
        return "official"
    if any(kw in lower for kw in ("security", "advisory", "bulletin", "patch")):
        return "vendor"
    if any(d in lower for d in _DEPRIORITIZED_DOMAINS):
        return "aggregator"
    return "other"


def _sort_references(refs: list) -> list:
    """Sort reference entries so official sources come first."""
    if not refs:
        return []
    result = []
    for ref in refs:
        if isinstance(ref, dict):
            url = ref.get("url", "")
            ref["source_type"] = _classify_reference(url)
            result.append(ref)
        elif isinstance(ref, str):
            result.append({"url": ref, "source_type": _classify_reference(ref)})
    order = {"official": 0, "vendor": 1, "other": 2, "aggregator": 3}
    result.sort(key=lambda r: order.get(r.get("source_type", "other"), 2))
    return result


class CVEService:
    """Service for fetching, caching, and searching CVE data from multiple sources."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    GHSA_API_URL = "https://api.github.com/advisories"
    OSV_API_URL = "https://api.osv.dev/v1/vulns"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    CISA_KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db

    # ── Public API ──────────────────────────────────────────────────

    async def fetch_and_store_cves(
        self,
        keyword: str = None,
        days_back: int = 7,
        max_results: int = 100,
        sources: list[str] = None,
    ) -> dict:
        """Fetch CVEs from multiple sources and store in database.
        Returns {"total_stored": int, "sources": {source: count}}.
        """
        if sources is None:
            sources = ["nvd", "ghsa"]

        results = {"total_stored": 0, "sources": {}}

        if "nvd" in sources:
            nvd_count = await self._sync_nvd(keyword=keyword, days_back=days_back, max_results=max_results)
            results["sources"]["nvd"] = nvd_count
            results["total_stored"] += nvd_count

        if "ghsa" in sources:
            ghsa_count = await self._sync_ghsa(keyword=keyword, max_results=min(max_results, 100))
            results["sources"]["ghsa"] = ghsa_count
            results["total_stored"] += ghsa_count

        # Enrich with EPSS scores
        if results["total_stored"] > 0:
            enriched = await self._enrich_epss()
            results["epss_enriched"] = enriched

        # Flag CVEs present in the CISA Known Exploited Vulnerabilities catalog
        kev_flagged = await self._enrich_kev()
        results["kev_flagged"] = kev_flagged

        return results

    async def sync_all(self, days_back: int = 7) -> dict:
        """Full sync from all sources — designed for Celery beat."""
        return await self.fetch_and_store_cves(
            days_back=days_back,
            max_results=200,
            sources=["nvd", "ghsa"],
        )

    async def search_cves(
        self,
        query: str = None,
        severity: str = None,
        source: str = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[CVE], int]:
        """Search cached CVEs in database."""
        stmt = select(CVE)
        count_stmt = select(func.count(CVE.id))

        if query:
            q_filter = or_(
                CVE.cve_id.ilike(f"%{query}%"),
                CVE.description.ilike(f"%{query}%"),
            )
            stmt = stmt.where(q_filter)
            count_stmt = count_stmt.where(q_filter)

        if severity:
            sev_filter = CVE.severity == severity.upper()
            stmt = stmt.where(sev_filter)
            count_stmt = count_stmt.where(sev_filter)

        if source:
            src_filter = CVE.source == source.lower()
            stmt = stmt.where(src_filter)
            count_stmt = count_stmt.where(src_filter)

        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar() or 0

        stmt = stmt.order_by(CVE.cvss_score.desc().nullslast(), CVE.published_date.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(stmt)
        cves = result.scalars().all()

        return cves, total

    async def get_cve_by_id(self, cve_id: str) -> Optional[CVE]:
        result = await self.db.execute(select(CVE).where(CVE.cve_id == cve_id))
        return result.scalar_one_or_none()

    async def match_packages(self, packages: list[dict]) -> list[dict]:
        """Match packages against cached CVE data."""
        matches = []
        for pkg in packages:
            name = pkg.get("name", "").lower()
            if not name:
                continue

            result = await self.db.execute(
                select(CVE).where(CVE.description.ilike(f"%{name}%"))
            )
            cves = result.scalars().all()

            for cve in cves:
                for affected in (cve.affected_packages or []):
                    if name in affected.get("product", "").lower() or name in affected.get("vendor", "").lower():
                        matches.append({
                            "package": pkg,
                            "cve_id": cve.cve_id,
                            "severity": cve.severity,
                            "cvss_score": cve.cvss_score,
                            "epss_score": cve.epss_score,
                            "description": (cve.description or "")[:200],
                            "source": cve.source,
                        })
        return matches

    async def get_sync_stats(self) -> dict:
        """Return statistics about the CVE database."""
        total_result = await self.db.execute(select(func.count(CVE.id)))
        total = total_result.scalar() or 0

        by_severity = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            r = await self.db.execute(
                select(func.count(CVE.id)).where(CVE.severity == sev)
            )
            by_severity[sev] = r.scalar() or 0

        by_source = {}
        for src in ("nvd", "ghsa", "osv"):
            r = await self.db.execute(
                select(func.count(CVE.id)).where(CVE.source == src)
            )
            count = r.scalar() or 0
            if count > 0:
                by_source[src] = count

        latest_result = await self.db.execute(
            select(CVE.fetched_at).order_by(CVE.fetched_at.desc()).limit(1)
        )
        latest = latest_result.scalar()

        epss_result = await self.db.execute(
            select(func.count(CVE.id)).where(CVE.epss_score.isnot(None))
        )
        epss_enriched = epss_result.scalar() or 0

        kev_result = await self.db.execute(
            select(func.count(CVE.id)).where(CVE.is_kev.is_(True))
        )
        kev_flagged = kev_result.scalar() or 0

        return {
            "total": total,
            "by_severity": by_severity,
            "by_source": by_source,
            "last_sync": latest.isoformat() if latest else None,
            "epss_enriched": epss_enriched,
            "kev_flagged": kev_flagged,
        }

    # ── NVD Source ──────────────────────────────────────────────────

    async def _sync_nvd(self, keyword: str = None, days_back: int = 7, max_results: int = 100) -> int:
        """Fetch CVEs from NIST NVD and store. Returns count of new CVEs."""
        cves = self._fetch_from_nvd(keyword=keyword, days_back=days_back, max_results=max_results)
        stored = 0

        for cve_data in cves:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            existing = await self.db.execute(select(CVE).where(CVE.cve_id == cve_id))
            if existing.scalar_one_or_none():
                continue

            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if not cvss_v31:
                cvss_v31 = metrics.get("cvssMetricV30", [])
            cvss_data = cvss_v31[0].get("cvssData", {}) if cvss_v31 else {}

            score = cvss_data.get("baseScore", 0)
            severity = self._score_to_severity(score)

            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            affected = self._extract_affected_packages(cve_data)

            raw_refs = cve_data.get("references", [])
            references = _sort_references(raw_refs)

            published = cve_data.get("published")
            modified = cve_data.get("lastModified")

            cve = CVE(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=score,
                cvss_vector=cvss_data.get("vectorString", ""),
                affected_packages=affected,
                fix_versions=[],
                references=references,
                published_date=self._parse_iso(published),
                last_modified=self._parse_iso(modified),
                source="nvd",
            )
            self.db.add(cve)
            stored += 1

        if stored > 0:
            await self.db.commit()

        logger.info(f"NVD sync: stored {stored} new CVEs")
        return stored

    def _fetch_from_nvd(self, keyword: str = None, days_back: int = 7, max_results: int = 100) -> list[dict]:
        """Fetch CVEs from NVD REST API v2.0."""
        params = {"resultsPerPage": min(max_results, 2000)}

        if keyword:
            params["keywordSearch"] = keyword

        if days_back:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=days_back)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

        headers = {"User-Agent": "GuardNous/2.0 CVE-Sync"}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            response = requests.get(self.NVD_API_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            return [vuln.get("cve", {}) for vuln in data.get("vulnerabilities", [])]
        except requests.RequestException as e:
            logger.error(f"NVD fetch failed: {e}")
            return []

    # ── GitHub Advisory Database (GHSA) ─────────────────────────────

    async def _sync_ghsa(self, keyword: str = None, max_results: int = 100) -> int:
        """Fetch advisories from GitHub Advisory Database and store."""
        advisories = self._fetch_from_ghsa(keyword=keyword, max_results=max_results)
        stored = 0

        for adv in advisories:
            ghsa_id = adv.get("ghsa_id", "")
            cve_id = adv.get("cve_id") or ghsa_id
            if not cve_id:
                continue

            existing = await self.db.execute(select(CVE).where(CVE.cve_id == cve_id))
            if existing.scalar_one_or_none():
                continue

            severity_str = (adv.get("severity") or "medium").upper()
            cvss = adv.get("cvss", {}) or {}
            score = cvss.get("score", 0) or 0

            if severity_str not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity_str = self._score_to_severity(score)

            affected = []
            for vuln in adv.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                affected.append({
                    "vendor": pkg.get("ecosystem", ""),
                    "product": pkg.get("name", ""),
                    "version_start": (vuln.get("vulnerable_version_range") or "").split(",")[0].strip(),
                    "version_end": "",
                })

            fix_versions = []
            for vuln in adv.get("vulnerabilities", []):
                fv = vuln.get("first_patched_version")
                if fv:
                    fix_versions.append(fv)

            references = _sort_references([
                {"url": adv.get("html_url", ""), "source_type": "official"},
            ])

            published = adv.get("published_at")
            modified = adv.get("updated_at")

            cve = CVE(
                cve_id=cve_id,
                description=adv.get("summary", ""),
                severity=severity_str,
                cvss_score=score,
                cvss_vector=cvss.get("vector_string", ""),
                affected_packages=affected,
                fix_versions=fix_versions,
                references=references,
                published_date=self._parse_iso(published),
                last_modified=self._parse_iso(modified),
                source="ghsa",
            )
            self.db.add(cve)
            stored += 1

        if stored > 0:
            await self.db.commit()

        logger.info(f"GHSA sync: stored {stored} new advisories")
        return stored

    def _fetch_from_ghsa(self, keyword: str = None, max_results: int = 100) -> list[dict]:
        """Fetch advisories from GitHub Advisory Database REST API."""
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "GuardNous/2.0 CVE-Sync",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        params = {
            "type": "reviewed",
            "per_page": min(max_results, 100),
        }
        if keyword:
            params["ghsa_id"] = keyword if keyword.startswith("GHSA-") else None
            params["cve_id"] = keyword if keyword.startswith("CVE-") else None
            if not params["ghsa_id"]:
                del params["ghsa_id"]
            if not params["cve_id"]:
                del params["cve_id"]

        try:
            response = requests.get(self.GHSA_API_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"GHSA fetch failed: {e}")
            return []

    # ── EPSS Enrichment ─────────────────────────────────────────────

    async def _enrich_epss(self, batch_size: int = 100) -> int:
        """Enrich CVEs with EPSS (Exploit Prediction Scoring System) scores."""
        result = await self.db.execute(
            select(CVE.cve_id)
            .where(CVE.epss_score.is_(None))
            .where(CVE.cve_id.like("CVE-%"))
            .limit(batch_size)
        )
        cve_ids = [row[0] for row in result.all()]
        if not cve_ids:
            return 0

        epss_data = self._fetch_epss(cve_ids)
        enriched = 0

        for cve_id, scores in epss_data.items():
            await self.db.execute(
                update(CVE)
                .where(CVE.cve_id == cve_id)
                .values(
                    epss_score=scores.get("epss"),
                    epss_percentile=scores.get("percentile"),
                )
            )
            enriched += 1

        if enriched > 0:
            await self.db.commit()

        logger.info(f"EPSS enrichment: updated {enriched} CVEs")
        return enriched

    def _fetch_epss(self, cve_ids: list[str]) -> dict:
        """Fetch EPSS scores from FIRST.org API."""
        if not cve_ids:
            return {}

        try:
            params = {"cve": ",".join(cve_ids[:100])}
            response = requests.get(
                self.EPSS_API_URL,
                params=params,
                headers={"User-Agent": "GuardNous/2.0 CVE-Sync"},
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()

            result = {}
            for item in data.get("data", []):
                result[item["cve"]] = {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
            return result
        except Exception as e:
            logger.error(f"EPSS fetch failed: {e}")
            return {}

    # ── CISA KEV Source ─────────────────────────────────────────────

    async def _enrich_kev(self) -> int:
        """Flag stored CVEs that appear in the CISA Known Exploited Vulnerabilities catalog.

        The CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
        lists vulnerabilities with confirmed active exploitation in the wild. These are the
        highest-priority items for remediation regardless of CVSS/EPSS.
        """
        kev_catalog = self._fetch_kev_catalog()
        if not kev_catalog:
            return 0

        # Only touch CVEs we actually store, so updates stay bounded.
        result = await self.db.execute(select(CVE.cve_id).where(CVE.cve_id.like("CVE-%")))
        stored_ids = {row[0] for row in result.all()}
        to_flag = stored_ids & set(kev_catalog.keys())

        flagged = 0
        for cve_id in to_flag:
            await self.db.execute(
                update(CVE)
                .where(CVE.cve_id == cve_id)
                .values(is_kev=True, kev_date_added=kev_catalog[cve_id])
            )
            flagged += 1

        if flagged > 0:
            await self.db.commit()

        logger.info(f"CISA KEV enrichment: flagged {flagged} CVEs as known-exploited")
        return flagged

    def _fetch_kev_catalog(self) -> dict:
        """Fetch the CISA KEV catalog. Returns {cve_id: date_added}."""
        try:
            response = requests.get(
                self.CISA_KEV_API_URL,
                headers={"User-Agent": "GuardNous/2.0 CVE-Sync"},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            catalog = {}
            for item in data.get("vulnerabilities", []):
                cve_id = item.get("cveID", "")
                if cve_id:
                    catalog[cve_id] = item.get("dateAdded", "")
            return catalog
        except Exception as e:
            logger.error(f"CISA KEV fetch failed: {e}")
            return {}

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_affected_packages(cve_data: dict) -> list[dict]:
        affected = []
        configs = cve_data.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        affected.append({
                            "vendor": parts[3],
                            "product": parts[4],
                            "version_start": cpe_match.get("versionStartIncluding", ""),
                            "version_end": cpe_match.get("versionEndExcluding", ""),
                        })
        return affected

    @staticmethod
    def _parse_iso(value: str) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "LOW"

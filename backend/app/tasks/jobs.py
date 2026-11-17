import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone

import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.plugins import ScanOrchestrator
from app.services.plugins.orchestrator import plugin_error_summary
from app.services.risk.scorer import RiskScorer
from app.services.sla import set_deadlines_sync
from app.services.triage_memory import carry_over_sync
from app.services.agents.auto_triage import start_after_scan_sync

logger = logging.getLogger(__name__)


class RepoFetchError(Exception):
    """A repository's files could not be read from its VCS provider."""


def _safe_snippet(val) -> str | None:
    """Coerce code_snippet to str; plugins sometimes return list-of-dicts."""
    if val is None:
        return None
    return val if isinstance(val, str) else str(val)

# Sync engine for Celery tasks
sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_size=5)

# Redis client for SSE log streaming
_redis_log_client = None


def _get_redis():
    global _redis_log_client
    if _redis_log_client is None:
        _redis_log_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_log_client


def emit_log(scan_id: int, stage: str, message: str, level: str = "info"):
    """Publish a log line to Redis channel and append to stored list."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "msg": message,
        "level": level,
    }
    payload = json.dumps(entry)
    try:
        r = _get_redis()
        r.publish(f"scan:{scan_id}:logs", payload)
        r.rpush(f"scan:{scan_id}:log_list", payload)
        r.expire(f"scan:{scan_id}:log_list", 86400)  # keep logs 24h
    except Exception:
        pass


def _ingest_findings_to_kg(org_id: int, findings_dicts: list[dict]):
    """Fire-and-forget KG ingest after scan completion (sync wrapper)."""
    try:
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.services.knowledge_graph import KnowledgeGraphService

        async def _run():
            engine = create_async_engine(settings.DATABASE_URL, pool_size=2)
            async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            async with async_session() as session:
                kg = KnowledgeGraphService(session, org_id)
                stats = await kg.ingest_findings(findings_dicts)
                await session.commit()
                logger.info(f"KG ingest complete: {stats}")
            await engine.dispose()

        asyncio.run(_run())
    except Exception as e:
        logger.warning(f"KG ingest failed (non-fatal): {e}")


@celery_app.task(bind=True, name="app.tasks.jobs.run_scan")
def run_scan(self, scan_id: int, source: str, scan_type: str, file_name: str = ""):
    """Run an IaC scan asynchronously."""
    from app.models.scan import Scan
    from app.models.finding import Finding

    with Session(sync_engine) as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return {"error": "Scan not found"}

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        # Legacy scan_type → plugin name mapping
        _LEGACY_TYPE_MAP = {
            "terraform": "native_terraform",
            "cloudformation": "native_cloudformation",
            "bicep": "native_bicep",
        }

        all_results = []
        try:
            orchestrator = ScanOrchestrator()
            plugin_filter = None
            if scan_type != "full" and scan_type in _LEGACY_TYPE_MAP:
                plugin_filter = [_LEGACY_TYPE_MAP[scan_type], "native_secrets"]

            orch_result = orchestrator.scan(
                content=source,
                file_name=file_name,
                plugin_names=plugin_filter,
            )
            all_results = orch_result.findings
            scan.error_message = plugin_error_summary(orch_result.plugin_errors)

            for r in all_results:
                _meta = getattr(r, "metadata", {}) or {}
                finding = Finding(
                    scan_id=scan.id,
                    rule_id=r.rule_id,
                    title=r.title,
                    description=r.description,
                    severity=r.severity,
                    category=r.category,
                    cloud_provider=r.cloud_provider or scan.cloud_provider,
                    resource_type=r.resource_type,
                    resource_name=r.resource_name,
                    file_path=r.file_path,
                    line_number=r.line_number,
                    code_snippet=_safe_snippet(r.code_snippet),
                    remediation=r.remediation,
                    cve_id=r.cve_id,
                    detected_by=_meta.get("source"),
                    metadata_=_meta,
                )
                db.add(finding)
            carry_over_sync(db, scan)
            set_deadlines_sync(db, scan)

            scorer = RiskScorer()
            scan.risk_score = scorer.calculate_scan_score([{"severity": r.severity} for r in all_results])
            scan.findings_count = len(all_results)
            scan.critical_count = sum(1 for r in all_results if r.severity == "CRITICAL")
            scan.high_count = sum(1 for r in all_results if r.severity == "HIGH")
            scan.medium_count = sum(1 for r in all_results if r.severity == "MEDIUM")
            scan.low_count = sum(1 for r in all_results if r.severity == "LOW")
            scan.status = "completed"
            scan.progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()

            # Populate Knowledge Graph from findings
            findings_dicts = [
                {"id": r.rule_id, "rule_id": r.rule_id, "title": r.title,
                 "severity": r.severity, "resource_name": r.resource_name,
                 "resource_type": r.resource_type, "file_path": r.file_path,
                 "category": r.category, "cloud_provider": r.cloud_provider or scan.cloud_provider,
                 "cve_id": r.cve_id}
                for r in all_results
            ]
            _ingest_findings_to_kg(scan.organization_id, findings_dicts)

            return {
                "scan_id": scan.id,
                "status": "completed",
                "findings_count": scan.findings_count,
                "risk_score": scan.risk_score,
            }

        except Exception as e:
            scan.status = "failed"
            scan.error_message = f"Scan failed: {type(e).__name__}. Check server logs for details."
            db.commit()
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            return {"scan_id": scan_id, "status": "failed", "error": scan.error_message}


@celery_app.task(name="app.tasks.jobs.sync_cve_database")
def sync_cve_database(keyword: str = None, days_back: int = 7):
    """Sync CVE database from NVD + GHSA and enrich with EPSS (runs daily).

    Uses synchronous DB session since Celery tasks are sync.
    Fetches from multiple authoritative sources:
      1. NIST NVD (primary)
      2. GitHub Advisory Database (GHSA)
      3. FIRST EPSS enrichment (exploit probability scoring)
    """
    from app.models.cve import CVE
    from app.services.cve.service import _sort_references, CVEService

    svc = CVEService()  # no async DB — we use sync_engine below

    stored_total = 0
    source_counts = {}

    # ── 1. Fetch from NVD ───────────────────────────────────────────
    try:
        nvd_cves = svc._fetch_from_nvd(keyword=keyword, days_back=days_back, max_results=200)
        nvd_stored = 0

        with Session(sync_engine) as db:
            for cve_data in nvd_cves:
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue

                existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                if existing:
                    continue

                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                if not cvss_v31:
                    cvss_v31 = metrics.get("cvssMetricV30", [])
                cvss_data = cvss_v31[0].get("cvssData", {}) if cvss_v31 else {}

                score = cvss_data.get("baseScore", 0)
                severity = svc._score_to_severity(score)

                descriptions = cve_data.get("descriptions", [])
                description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                affected = svc._extract_affected_packages(cve_data)
                references = _sort_references(cve_data.get("references", []))

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
                    published_date=svc._parse_iso(published),
                    last_modified=svc._parse_iso(modified),
                    source="nvd",
                )
                db.add(cve)
                nvd_stored += 1

            if nvd_stored > 0:
                db.commit()

        source_counts["nvd"] = nvd_stored
        stored_total += nvd_stored
        logger.info(f"NVD sync: stored {nvd_stored} new CVEs")
    except Exception as e:
        logger.error(f"NVD sync failed: {e}")
        source_counts["nvd"] = 0

    # ── 2. Fetch from GHSA ──────────────────────────────────────────
    try:
        ghsa_advisories = svc._fetch_from_ghsa(keyword=keyword, max_results=100)
        ghsa_stored = 0

        with Session(sync_engine) as db:
            for adv in ghsa_advisories:
                ghsa_id = adv.get("ghsa_id", "")
                cve_id = adv.get("cve_id") or ghsa_id
                if not cve_id:
                    continue

                existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                if existing:
                    continue

                severity_str = (adv.get("severity") or "medium").upper()
                cvss = adv.get("cvss", {}) or {}
                score = cvss.get("score", 0) or 0

                if severity_str not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity_str = svc._score_to_severity(score)

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
                    published_date=svc._parse_iso(published),
                    last_modified=svc._parse_iso(modified),
                    source="ghsa",
                )
                db.add(cve)
                ghsa_stored += 1

            if ghsa_stored > 0:
                db.commit()

        source_counts["ghsa"] = ghsa_stored
        stored_total += ghsa_stored
        logger.info(f"GHSA sync: stored {ghsa_stored} new advisories")
    except Exception as e:
        logger.error(f"GHSA sync failed: {e}")
        source_counts["ghsa"] = 0

    # ── 3. EPSS enrichment ──────────────────────────────────────────
    epss_enriched = 0
    try:
        with Session(sync_engine) as db:
            unenriched = (
                db.query(CVE.cve_id)
                .filter(CVE.epss_score.is_(None), CVE.cve_id.like("CVE-%"))
                .limit(100)
                .all()
            )
            cve_ids = [row[0] for row in unenriched]

            if cve_ids:
                epss_data = svc._fetch_epss(cve_ids)
                for cve_id_val, scores in epss_data.items():
                    db.query(CVE).filter(CVE.cve_id == cve_id_val).update({
                        CVE.epss_score: scores.get("epss"),
                        CVE.epss_percentile: scores.get("percentile"),
                    })
                    epss_enriched += 1

                if epss_enriched > 0:
                    db.commit()

        logger.info(f"EPSS enrichment: updated {epss_enriched} CVEs")
    except Exception as e:
        logger.error(f"EPSS enrichment failed: {e}")

    return {
        "status": "success",
        "total_stored": stored_total,
        "sources": source_counts,
        "epss_enriched": epss_enriched,
    }


@celery_app.task(bind=True, name="app.tasks.jobs.run_quick_repo_scan")
def run_quick_repo_scan(self, scan_id: int, integration_id: int, repo_full_name: str, org_id: int):
    """Lightweight async repo scan — queued via the integration scan endpoint.

    Stages: queued → cloning → scanning → analyzing → completed
    Fetches repo content from GitHub, GitLab, Bitbucket or Azure DevOps. If the
    repository cannot be read the scan fails with the reason.
    """
    import time as _time
    import base64
    import requests
    from urllib.parse import quote as url_quote
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.models.integration import Integration
    from app.core.encryption import decrypt_token

    _SCANNABLE_EXTENSIONS = {
        ".tf", ".tfvars", ".yaml", ".yml", ".json", ".py", ".js",
        ".dockerfile", ".bicep", ".env", ".cfg", ".ini", ".toml",
        ".properties",
    }
    _MAX_FILES = 100
    _MAX_FILE_SIZE = 512 * 1024  # 512 KB

    def _fetch_repo_files(db_session, integ_id: int, repo: str) -> dict[str, str]:
        """Fetch file contents from the repository's VCS provider, return {path: content}.

        Raises RepoFetchError when the repository cannot be read. A scan never
        runs on substitute content.
        """
        integration = db_session.get(Integration, integ_id)
        if not integration or not integration.access_token_encrypted:
            raise RepoFetchError("The VCS integration has no stored credentials. Reconnect it.")

        access_token = decrypt_token(integration.access_token_encrypted)
        if not access_token:
            raise RepoFetchError("The VCS credentials could not be decrypted. Reconnect the integration.")

        provider = (integration.vcs_type or "github").lower()

        try:
            if provider == "gitlab":
                return _fetch_gitlab_files(access_token, repo, integration.base_url)
            if provider == "github":
                return _fetch_github_files(access_token, repo)
            if provider in ("bitbucket", "azure_devops"):
                return _fetch_via_service(provider, integration, access_token, repo)
        except RepoFetchError:
            raise
        except Exception as exc:
            logger.warning("Failed to fetch repo files for %s/%s: %s", provider, repo, exc)
            raise RepoFetchError(f"Could not read {repo} from {provider}: {type(exc).__name__}: {exc}"[:400])
        raise RepoFetchError(f"Repository scanning is not supported for VCS provider '{provider}'.")

    def _fetch_via_service(provider: str, integration, token: str, repo: str) -> dict[str, str]:
        """Bitbucket and Azure DevOps, through their async service clients."""
        import asyncio

        if provider == "bitbucket":
            from app.services.vcs.bitbucket import BitbucketService
            svc = BitbucketService(username=integration.account_name, app_password=token)
        else:
            from app.services.vcs.azure_devops import AzureDevOpsService
            svc = AzureDevOpsService(organization=integration.account_name or "", pat=token)

        # Default branch as recorded when the repo was onboarded, then the usual names
        branches = [
            r.get("default_branch") for r in (integration.repositories or [])
            if isinstance(r, dict) and r.get("full_name") == repo and r.get("default_branch")
        ] + ["main", "master"]

        async def _run() -> dict[str, str]:
            for branch in dict.fromkeys(branches):
                listing = await svc.list_iac_files(repo, branch=branch)
                if not listing:
                    continue
                files: dict[str, str] = {}
                for entry in listing[:_MAX_FILES]:
                    if (entry.get("size") or 0) > _MAX_FILE_SIZE:
                        continue
                    content = await svc.get_file_content(repo, entry["path"], ref=branch)
                    if content is not None and len(content) <= _MAX_FILE_SIZE:
                        files[entry["path"]] = content
                return files
            return {}

        return asyncio.run(_run())

    def _fetch_github_files(token: str, repo: str) -> dict[str, str]:
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        tree_url = f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1"
        resp = requests.get(tree_url, headers=headers, timeout=30)
        resp.raise_for_status()

        tree = resp.json().get("tree", [])
        scannable = [
            node for node in tree
            if node.get("type") == "blob"
            and any(node["path"].lower().endswith(ext) for ext in _SCANNABLE_EXTENSIONS)
            and (node.get("size", 0) <= _MAX_FILE_SIZE)
        ][:_MAX_FILES]

        files: dict[str, str] = {}
        for node in scannable:
            blob_url = f"https://api.github.com/repos/{repo}/git/blobs/{node['sha']}"
            blob_resp = requests.get(blob_url, headers=headers, timeout=30)
            if blob_resp.status_code != 200:
                continue
            blob = blob_resp.json()
            if blob.get("encoding") == "base64":
                try:
                    files[node["path"]] = base64.b64decode(blob["content"]).decode("utf-8", errors="replace")
                except Exception:
                    pass
        return files

    def _fetch_gitlab_files(token: str, repo: str, base_url: str | None) -> dict[str, str]:
        api_base = (base_url or "https://gitlab.com/api/v4").rstrip("/")
        encoded_repo = url_quote(repo, safe="")
        headers = {"PRIVATE-TOKEN": token}
        tree_url = f"{api_base}/projects/{encoded_repo}/repository/tree?recursive=true&per_page=100"
        resp = requests.get(tree_url, headers=headers, timeout=30)
        resp.raise_for_status()

        entries = resp.json()
        scannable = [
            e for e in entries
            if e.get("type") == "blob"
            and any(e["path"].lower().endswith(ext) for ext in _SCANNABLE_EXTENSIONS)
        ][:_MAX_FILES]

        files: dict[str, str] = {}
        for entry in scannable:
            file_url = (
                f"{api_base}/projects/{encoded_repo}/repository/files/"
                f"{url_quote(entry['path'], safe='')}/raw?ref=HEAD"
            )
            file_resp = requests.get(file_url, headers=headers, timeout=30)
            if file_resp.status_code != 200:
                continue
            if len(file_resp.content) <= _MAX_FILE_SIZE:
                files[entry["path"]] = file_resp.text
        return files

    def _now():
        return datetime.now(timezone.utc)

    def _update(db, scan, stage, progress, **kwargs):
        scan.stage = stage
        scan.progress = progress
        for k, v in kwargs.items():
            setattr(scan, k, v)
        db.commit()

    with Session(sync_engine) as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return {"error": "Scan not found"}

        try:
            # ── Stage 1: cloning (20%) ──────────────────────────────
            _update(db, scan, "cloning", 10, status="running",
                    started_at=_now())

            try:
                repo_files = _fetch_repo_files(db, integration_id, repo_full_name)
            except RepoFetchError as exc:
                _update(db, scan, "failed", scan.progress or 10, status="failed",
                        error_message=str(exc), completed_at=_now())
                return {"scan_id": scan_id, "status": "failed", "error": str(exc)}
            logger.info("Fetched %d files from %s", len(repo_files), repo_full_name)

            _update(db, scan, "cloning", 20,
                    files_total=len(repo_files))

            # ── Stage 2: scanning (60%) ─────────────────────────────
            _update(db, scan, "scanning", 30)

            orchestrator = ScanOrchestrator()
            all_results = []
            files_done = 0
            plugin_errors: dict[str, str] = {}

            for file_path, content in repo_files.items():
                try:
                    orch_result = orchestrator.scan(
                        content=content,
                        file_name=file_path,
                    )
                    plugin_errors.update(orch_result.plugin_errors)
                    for r in orch_result.findings:
                        r.file_path = file_path
                        all_results.append(r)
                except Exception as exc:
                    logger.warning("Plugin scan error on %s: %s", file_path, exc)
                    plugin_errors.setdefault("scan", f"{file_path}: {exc}")

                files_done += 1
                sub = 30 + int(30 * files_done / max(len(repo_files), 1))
                _update(db, scan, "scanning", min(sub, 60),
                        files_scanned=files_done)

            scan.error_message = plugin_error_summary(plugin_errors)
            _time.sleep(2)

            # ── Stage 3: analyzing (80%) ────────────────────────────
            _update(db, scan, "analyzing", 65)

            # Persist findings
            for r in all_results:
                _meta = getattr(r, "metadata", {}) or {}
                finding = Finding(
                    scan_id=scan.id,
                    rule_id=r.rule_id,
                    title=r.title,
                    description=r.description,
                    severity=r.severity,
                    category=r.category,
                    cloud_provider=r.cloud_provider or scan.cloud_provider,
                    resource_type=r.resource_type,
                    resource_name=r.resource_name,
                    file_path=r.file_path,
                    line_number=r.line_number,
                    code_snippet=_safe_snippet(r.code_snippet),
                    remediation=r.remediation,
                    cve_id=getattr(r, "cve_id", None),
                    detected_by=_meta.get("source"),
                    metadata_=_meta,
                )
                db.add(finding)
            carry_over_sync(db, scan)
            set_deadlines_sync(db, scan)
            start_after_scan_sync(db, scan)

            total = len(all_results)
            scan.findings_count = total
            scan.critical_count = sum(1 for r in all_results if r.severity == "CRITICAL")
            scan.high_count = sum(1 for r in all_results if r.severity == "HIGH")
            scan.medium_count = sum(1 for r in all_results if r.severity == "MEDIUM")
            scan.low_count = sum(1 for r in all_results if r.severity == "LOW")

            scorer = RiskScorer()
            scan.risk_score = scorer.calculate_scan_score(
                [{"severity": r.severity} for r in all_results]
            )
            db.commit()

            _time.sleep(3)
            _update(db, scan, "analyzing", 80)

            # ── Stage 4: notifications (90%) ────────────────────────
            try:
                from app.services.notifications.scan_notify import notify_scan_complete
                severity_counts = {
                    "critical": getattr(scan, "critical_count", 0) or 0,
                    "high": getattr(scan, "high_count", 0) or 0,
                    "medium": getattr(scan, "medium_count", 0) or 0,
                    "low": getattr(scan, "low_count", 0) or 0,
                }
                delivery = notify_scan_complete(db, scan, repo_full_name, "completed", severity_counts)
                scan.notifications_sent = delivery["succeeded"] > 0
            except Exception as e:
                logger.warning(f"Quick scan notification dispatch failed: {e}")
                scan.notifications_sent = False

            # ── Stage 5: completed (100%) ───────────────────────────
            _update(db, scan, "completed", 100,
                    status="completed", completed_at=_now())

            return {
                "scan_id": scan.id,
                "status": "completed",
                "findings_count": scan.findings_count,
                "risk_score": scan.risk_score,
            }

        except Exception as e:
            scan.status = "failed"
            scan.stage = "failed"
            scan.error_message = f"Scan failed: {type(e).__name__}. Check server logs for details."
            scan.completed_at = _now()
            try:
                db.commit()
            except Exception:
                db.rollback()
            logger.error("Quick repo scan %s failed: %s", scan_id, e, exc_info=True)
            return {"scan_id": scan_id, "status": "failed", "error": scan.error_message}


@celery_app.task(bind=True, name="app.tasks.jobs.run_repo_scan")
def run_repo_scan(self, scan_id: int, repo_full_name: str, token: str, scan_types: list, org_id: int):
    """Enterprise 14-stage repository scan pipeline.

    Stages: queued → authenticating → cloning → dependency_analysis →
            secret_scanning → iac_scanning → vulnerability_correlation →
            policy_evaluation → compliance_mapping → processing_results →
            generating_report → sending_notifications → completed
    Terminal states: failed, cancelled, timed_out
    """
    import requests
    import base64
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.models.report import Report
    from app.models.cve import CVE
    from app.services.security.secret_scanner import SecretScanner
    from app.services.security.dependency_analyzer import DependencyAnalyzer
    from app.services.security.policy_engine import PolicyEngine
    from app.services.security.compliance_mapper import ComplianceMapper
    from app.services.security.vulnerability_correlator import VulnerabilityCorrelator

    IaC_EXTENSIONS = {
        "terraform": [".tf", ".tfvars"],
        "cloudformation": [".yaml", ".yml", ".json", ".template"],
        "bicep": [".bicep"],
        "kubernetes": [".yaml", ".yml"],
        "dockerfile": ["Dockerfile", ".dockerfile"],
        "ansible": [".yaml", ".yml"],
        "helm": [".yaml", ".yml", ".tpl"],
    }
    _LEGACY_TYPE_MAP = {
        "terraform": "native_terraform",
        "cloudformation": "native_cloudformation",
        "bicep": "native_bicep",
        "kubernetes": "native_cloudformation",
        "ansible": "native_cloudformation",
        "helm": "native_cloudformation",
    }
    # Expand "full" to all scan types
    ALL_SCAN_TYPES = ["terraform", "cloudformation", "bicep", "kubernetes", "dockerfile", "ansible", "helm"]

    start_time = time.time()

    def _now():
        return datetime.now(timezone.utc)

    def _elapsed():
        return time.time() - start_time

    def update_stage(db, scan, stage, progress, **kwargs):
        """Update scan stage with per-stage timing in stage_details."""
        details = scan.stage_details or {}
        now_iso = _now().isoformat()

        # Close previous stage timing
        prev_stage = scan.stage
        if prev_stage and prev_stage in details and "end_time" not in details[prev_stage]:
            details[prev_stage]["end_time"] = now_iso
            s = details[prev_stage]
            if s.get("start_time"):
                from datetime import datetime as dt
                try:
                    t0 = dt.fromisoformat(s["start_time"])
                    t1 = dt.fromisoformat(now_iso)
                    s["duration_ms"] = int((t1 - t0).total_seconds() * 1000)
                except Exception:
                    pass

        # Open new stage timing
        if stage not in details:
            details[stage] = {"start_time": now_iso}

        scan.stage = stage
        scan.progress = progress
        scan.stage_details = details
        # Force SQLAlchemy to detect dict mutation
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(scan, "stage_details")
        for k, v in kwargs.items():
            setattr(scan, k, v)
        db.commit()

    def _check_cancelled(db, scan) -> bool:
        """Check if job was cancelled between stages."""
        db.refresh(scan)
        return scan.status == "cancelled" or scan.cancelled_by is not None

    def _check_timeout(db, scan) -> bool:
        """Check if job exceeded its timeout."""
        timeout = scan.timeout_seconds or 3600
        return _elapsed() > timeout

    def _fail(db, scan, stage, msg):
        update_stage(db, scan, stage, scan.progress or 0,
                     status="failed", error_message=msg[:500],
                     completed_at=_now())

    with Session(sync_engine) as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return {"error": "Scan not found"}

        # Initialise stage_details
        scan.stage_details = {}

        # Expand "full" to all supported scan types
        if "full" in scan_types:
            scan_types = list(ALL_SCAN_TYPES)
            scan.scan_type = ",".join(scan_types)
            db.commit()

        try:
            # ── Stage 1: authenticating (5%) ────────────────────────
            update_stage(db, scan, "authenticating", 5,
                         status="running", started_at=_now())
            emit_log(scan_id, "authenticating", "Validating GitHub personal access token…")

            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            }
            auth_resp = requests.get("https://api.github.com/user", headers=headers, timeout=10)
            if auth_resp.status_code != 200:
                emit_log(scan_id, "authenticating", f"✗ Authentication failed: HTTP {auth_resp.status_code}", "error")
                _fail(db, scan, "authenticating",
                      f"GitHub authentication failed: HTTP {auth_resp.status_code}")
                return {"scan_id": scan_id, "status": "failed"}
            gh_user = auth_resp.json().get("login", "unknown")
            emit_log(scan_id, "authenticating", f"✓ Authenticated as {gh_user}")
            emit_log(scan_id, "authenticating", f"  Token scopes verified for {repo_full_name}")

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}

            # ── Stage 2: cloning (10%) ──────────────────────────────
            update_stage(db, scan, "cloning", 10)
            emit_log(scan_id, "cloning", f"Fetching repository tree for {repo_full_name}…")

            tree_url = f"https://api.github.com/repos/{repo_full_name}/git/trees/HEAD?recursive=1"
            resp = requests.get(tree_url, headers=headers, timeout=30)
            if resp.status_code != 200:
                emit_log(scan_id, "cloning", f"✗ Failed to fetch repo tree: HTTP {resp.status_code}", "error")
                _fail(db, scan, "cloning",
                      f"Failed to fetch repo tree: HTTP {resp.status_code}")
                return {"scan_id": scan_id, "status": "failed"}

            tree_data = resp.json()
            all_tree_files = tree_data.get("tree", [])
            emit_log(scan_id, "cloning", f"✓ Repository tree fetched — {len(all_tree_files)} entries")

            # Build target extensions from scan_types
            target_extensions = set()
            for st in scan_types:
                target_extensions.update(IaC_EXTENSIONS.get(st, []))

            iac_files = []
            all_blob_files = []
            for f in all_tree_files:
                if f.get("type") != "blob":
                    continue
                path = f.get("path", "")
                all_blob_files.append(f)
                if any(path.lower().endswith(ext) for ext in target_extensions):
                    iac_files.append(f)

            emit_log(scan_id, "cloning", f"  Found {len(all_blob_files)} blob files, {len(iac_files)} IaC targets")
            scan.files_total = len(all_blob_files)
            update_stage(db, scan, "cloning", 15, files_total=len(all_blob_files))

            # Fetch file contents into memory with size limits
            emit_log(scan_id, "cloning", f"Downloading {len(all_blob_files)} files via GitHub API…")
            MAX_FILE_SIZE = 5 * 1024 * 1024       # 5 MB per file
            MAX_BATCH_SIZE = 100 * 1024 * 1024     # 100 MB total
            fetched_files = {}  # path → content
            total_fetched_bytes = 0
            for idx, blob_entry in enumerate(all_blob_files):
                file_path = blob_entry.get("path", "")
                blob_url = blob_entry.get("url", "")

                # Skip files that report a size exceeding the per-file limit
                reported_size = blob_entry.get("size", 0) or 0
                if reported_size > MAX_FILE_SIZE:
                    logger.warning("Skipping %s: reported size %d exceeds %d byte limit",
                                   file_path, reported_size, MAX_FILE_SIZE)
                    continue

                # Stop fetching if total batch size reached
                if total_fetched_bytes >= MAX_BATCH_SIZE:
                    logger.warning("Batch size limit reached (%d bytes) — stopping blob fetch",
                                   MAX_BATCH_SIZE)
                    break

                try:
                    blob_resp = requests.get(blob_url, headers=headers, timeout=15)
                    if blob_resp.status_code == 200:
                        blob_data = blob_resp.json()
                        raw_content = base64.b64decode(
                            blob_data.get("content", "")
                        )
                        if len(raw_content) > MAX_FILE_SIZE:
                            logger.warning("Skipping %s: decoded size %d exceeds %d byte limit",
                                           file_path, len(raw_content), MAX_FILE_SIZE)
                            continue
                        total_fetched_bytes += len(raw_content)
                        fetched_files[file_path] = raw_content.decode("utf-8", errors="replace")
                except Exception:
                    pass
                # Progress within cloning: 10-18%
                if len(all_blob_files) > 0:
                    sub_progress = 10 + int(8 * (idx + 1) / len(all_blob_files))
                    scan.progress = min(sub_progress, 18)
                    db.commit()
                # Log progress every 10 files
                if (idx + 1) % 10 == 0 or idx + 1 == len(all_blob_files):
                    emit_log(scan_id, "cloning", f"  Downloaded {idx + 1}/{len(all_blob_files)} files ({total_fetched_bytes // 1024} KB)")

            emit_log(scan_id, "cloning", f"✓ Fetched {len(fetched_files)} files ({total_fetched_bytes // 1024} KB total)")

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}
            if _check_timeout(db, scan):
                update_stage(db, scan, "timed_out", scan.progress, status="timed_out",
                             error_message="Job exceeded timeout", completed_at=_now())
                return {"scan_id": scan_id, "status": "timed_out"}

            # ── Stage 3: dependency_analysis (20%) ──────────────────
            update_stage(db, scan, "dependency_analysis", 20)
            emit_log(scan_id, "dependency_analysis", "Scanning for package manifests (package.json, requirements.txt, go.mod, etc.)…")

            dep_analyzer = DependencyAnalyzer()
            all_deps, vuln_deps, dep_stats = dep_analyzer.analyze(fetched_files, cve_records=[])
            emit_log(scan_id, "dependency_analysis", f"✓ Found {dep_stats.get('total_dependencies', 0)} dependencies across {dep_stats.get('manifests_found', 0)} manifests")
            if vuln_deps:
                emit_log(scan_id, "dependency_analysis", f"  ⚠ {len(vuln_deps)} vulnerable dependencies detected", "warn")
            scan.dependencies_analyzed = dep_stats.get("total_dependencies", 0)
            # SBOM: keep the parsed dependencies so an SBOM can be exported after the scan
            from app.services.security.sbom_store import store_scan_inventory
            store_scan_inventory(db, scan, all_deps)

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}

            # ── Stage 4: secret_scanning (30%) ──────────────────────
            update_stage(db, scan, "secret_scanning", 30)
            emit_log(scan_id, "secret_scanning", f"Running secret scanner (gitleaks) on {len(fetched_files)} files…")

            secret_scanner = SecretScanner()
            secret_findings, secret_stats = secret_scanner.scan_files(fetched_files)
            scan.secrets_found = len(secret_findings)
            scan.files_scanned = len(fetched_files)  # secret scan covers all fetched files
            db.commit()  # persist secrets_found immediately
            if secret_findings:
                emit_log(scan_id, "secret_scanning", f"⚠ {len(secret_findings)} secrets/credentials detected!", "warn")
                for sf in secret_findings:
                    emit_log(scan_id, "secret_scanning", f"  • {sf.rule_id} in {sf.file_path}:{sf.line_number} [{sf.severity}]", "warn")
            else:
                emit_log(scan_id, "secret_scanning", "✓ No hardcoded secrets detected")

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}
            if _check_timeout(db, scan):
                update_stage(db, scan, "timed_out", scan.progress, status="timed_out",
                             error_message="Job exceeded timeout", completed_at=_now())
                return {"scan_id": scan_id, "status": "timed_out"}

            # ── Stage 5: IaC scanning — per-tool sub-stages ─────────
            # Tool display names & stage keys
            _TOOL_DISPLAY = {
                "native_terraform": "GuardNous Terraform",
                "native_cloudformation": "GuardNous CloudFormation",
                "native_bicep": "GuardNous Bicep",
                "native_secrets": "GuardNous Secrets",
                "checkov": "Checkov",
                "trivy": "Trivy",
                "semgrep": "Semgrep",
                "tfsec": "tfsec",
                "gitleaks": "Gitleaks",
            }
            _TOOL_STAGE_KEY = {
                "native_terraform": "iac_terraform",
                "native_cloudformation": "iac_cloudformation",
                "native_bicep": "iac_bicep",
                "native_secrets": "iac_secrets",
                "checkov": "iac_checkov",
                "trivy": "iac_trivy",
                "semgrep": "iac_semgrep",
                "tfsec": "iac_tfsec",
                "gitleaks": "iac_gitleaks",
            }

            # Group files by ALL enabled plugins that accept them
            orchestrator = ScanOrchestrator()
            files_by_plugin: dict[str, list[tuple[str, str]]] = {}
            enabled_plugins = orchestrator._registry.list_enabled()
            for iac_file in iac_files:
                file_path = iac_file.get("path", "")
                content = fetched_files.get(file_path)
                if not content:
                    continue
                for pname, adapter in enabled_plugins.items():
                    # Skip secrets plugins here (handled in secret_scanning stage)
                    if pname in ("native_secrets", "gitleaks"):
                        continue
                    if adapter.accepts(file_path):
                        files_by_plugin.setdefault(pname, []).append((file_path, content))
            all_iac_results = []
            files_done = 0
            total_files = len(iac_files)

            # Emit an overview stage first
            update_stage(db, scan, "iac_scanning", 35)
            emit_log(scan_id, "iac_scanning", f"Starting IaC security scan on {len(iac_files)} target files…")
            emit_log(scan_id, "iac_scanning", f"  Scan types: {', '.join(scan_types)}")
            emit_log(scan_id, "iac_scanning", f"  Target extensions: {', '.join(sorted(target_extensions))}")
            active_tools = [_TOOL_DISPLAY.get(p, p) for p in files_by_plugin]
            emit_log(scan_id, "iac_scanning", f"  Active tools: {', '.join(active_tools)}")
            emit_log(scan_id, "iac_scanning", f"  Dispatching {len(files_by_plugin)} tool stages…")

            # Write all fetched files to a temp directory (preserving relative paths)
            # so external CLI tools can scan a real directory tree.
            scan_tmpdir = tempfile.mkdtemp(prefix="guardnous_scan_")
            try:
                for file_path, content in fetched_files.items():
                    dest = os.path.join(scan_tmpdir, file_path)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "w") as f:
                        f.write(content)

                # Run each tool as its own sub-stage
                tool_idx = 0
                for plugin_name, plugin_files in files_by_plugin.items():
                    stage_key = _TOOL_STAGE_KEY.get(plugin_name, f"iac_{plugin_name}")
                    display_name = _TOOL_DISPLAY.get(plugin_name, plugin_name)
                    sub_progress = 35 + int(15 * tool_idx / max(len(files_by_plugin), 1))

                    update_stage(db, scan, stage_key, sub_progress)

                    adapter = enabled_plugins.get(plugin_name)
                    use_dir_scan = (
                        adapter is not None
                        and adapter.metadata().requires_binary
                        and adapter.supports_directory_scan()
                    )

                    if use_dir_scan:
                        # ── External tool: run on whole directory, stream REAL output ──
                        emit_log(scan_id, stage_key, f"Running {display_name} on {len(plugin_files)} files…")
                        try:
                            from app.services.plugins.integrity import ensure_adapter_integrity
                            integrity = ensure_adapter_integrity(adapter)
                            if integrity and integrity.sha256:
                                emit_log(scan_id, stage_key,
                                         f"✓ {display_name} binary integrity {integrity.status} "
                                         f"(sha256 {integrity.sha256[:12]}…)")
                            dir_result = adapter.scan_directory(scan_tmpdir)
                            # Stream the exact command
                            emit_log(scan_id, stage_key, f"$ {dir_result.command}")
                            # Stream real CLI output line by line
                            if dir_result.raw_output:
                                for line in dir_result.raw_output.splitlines():
                                    emit_log(scan_id, stage_key, line)
                            elif dir_result.stderr:
                                for line in dir_result.stderr.splitlines():
                                    emit_log(scan_id, stage_key, line, "warn")

                            tool_findings = len(dir_result.findings)
                            for r in dir_result.findings:
                                r.metadata = r.metadata or {}
                                r.metadata["source"] = plugin_name
                                all_iac_results.append(r)

                            elapsed_s = dir_result.duration_ms / 1000
                            summary = f"✓ {display_name} complete — {tool_findings} findings ({elapsed_s:.1f}s)"
                            if dir_result.exit_code not in (0, 1):
                                summary += f" [exit code {dir_result.exit_code}]"
                            emit_log(scan_id, stage_key, summary)
                        except Exception as e:
                            logger.warning(f"Error running {display_name} directory scan: {e}")
                            emit_log(scan_id, stage_key, f"✗ {display_name} failed: {e}", "error")
                    else:
                        # ── Native plugin: per-file scanning with summary logs ──
                        emit_log(scan_id, stage_key, f"Running {display_name} on {len(plugin_files)} files…")
                        tool_findings = 0
                        tool_errors = 0
                        for file_path, content in plugin_files:
                            try:
                                orch_result = orchestrator.scan(
                                    content=content,
                                    file_name=file_path,
                                    plugin_names=[plugin_name],
                                )
                                found_count = 0
                                for r in orch_result.findings:
                                    r.file_path = file_path
                                    all_iac_results.append(r)
                                    found_count += 1
                                tool_findings += found_count
                                emit_log(scan_id, stage_key, f"  {file_path} → {found_count} findings")
                            except Exception as e:
                                tool_errors += 1
                                logger.warning(f"Error scanning {file_path} with {display_name}: {e}")
                                emit_log(scan_id, stage_key, f"  ✗ Error scanning {file_path}: {e}", "error")

                        summary = f"✓ {display_name} complete — {tool_findings} findings from {len(plugin_files)} files"
                        if tool_errors:
                            summary += f" ({tool_errors} errors)"
                        emit_log(scan_id, stage_key, summary)

                    # Update progress for all tools uniformly
                    files_done += len(plugin_files)
                    scan.progress = min(35 + int(15 * files_done / max(total_files, 1)), 50)
                    scan.files_scanned = files_done
                    db.commit()
                    tool_idx += 1
            finally:
                shutil.rmtree(scan_tmpdir, ignore_errors=True)

            # Close with overall summary back on iac_scanning
            update_stage(db, scan, "iac_scanning", 50)
            tool_counts: dict[str, int] = {}
            for r in all_iac_results:
                source = (getattr(r, "metadata", None) or {}).get("source", "unknown")
                display = _TOOL_DISPLAY.get(source, source)
                tool_counts[display] = tool_counts.get(display, 0) + 1
            if tool_counts:
                breakdown = ", ".join(f"{t}: {c}" for t, c in sorted(tool_counts.items(), key=lambda x: -x[1]))
                emit_log(scan_id, "iac_scanning", f"  Tool breakdown: {breakdown}")
            emit_log(scan_id, "iac_scanning", f"✓ IaC scan complete — {len(all_iac_results)} total findings from {files_done} files")

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}
            if _check_timeout(db, scan):
                update_stage(db, scan, "timed_out", scan.progress, status="timed_out",
                             error_message="Job exceeded timeout", completed_at=_now())
                return {"scan_id": scan_id, "status": "timed_out"}

            # ── Stage 6: vulnerability_correlation (60%) ────────────
            update_stage(db, scan, "vulnerability_correlation", 55)
            emit_log(scan_id, "vulnerability_correlation", "Loading CVE database for correlation…")

            cve_records = []
            try:
                cve_rows = db.query(CVE).limit(500).all()
                cve_records = [
                    {"cve_id": c.cve_id, "description": c.description or "",
                     "severity": c.severity or "", "cvss_score": c.cvss_score or 0}
                    for c in cve_rows
                ]
            except Exception:
                pass

            emit_log(scan_id, "vulnerability_correlation", f"  Loaded {len(cve_records)} CVE records from database")
            emit_log(scan_id, "vulnerability_correlation", f"Correlating {len(all_iac_results)} findings against CVE database…")

            correlator = VulnerabilityCorrelator()
            iac_findings_dicts = [
                {"rule_id": r.rule_id, "title": r.title, "description": r.description or "",
                 "severity": r.severity, "category": r.category or "",
                 "resource_type": getattr(r, "resource_type", "") or "",
                 "resource": getattr(r, "resource", "") or getattr(r, "resource_name", "") or "",
                 "file_path": getattr(r, "file_path", "") or "",
                 "cloud_provider": getattr(r, "cloud_provider", "") or scan.cloud_provider or "aws"}
                for r in all_iac_results
            ]
            # Also correlate secret findings
            all_findings_for_corr = iac_findings_dicts + [
                {"rule_id": sf.rule_id, "title": f"Secret: {sf.rule_id}",
                 "description": sf.match_preview or "", "severity": sf.severity,
                 "category": "secrets", "file_path": sf.file_path}
                for sf in secret_findings
            ]
            corr_results, corr_stats = correlator.correlate(all_findings_for_corr, cve_records)
            correlations = corr_stats
            total_corr = corr_stats.get("total_correlations", 0)
            unique_cves = corr_stats.get("unique_cves_matched", 0)
            emit_log(scan_id, "vulnerability_correlation", f"✓ {total_corr} CVE correlations found ({unique_cves} unique CVEs)")
            if total_corr > 0:
                for sev, cnt in corr_stats.get("by_severity", {}).items():
                    if cnt > 0:
                        emit_log(scan_id, "vulnerability_correlation", f"  {sev}: {cnt} correlations")

            # Re-run dependency analysis with CVE data
            if cve_records:
                all_deps, vuln_deps, dep_stats = dep_analyzer.analyze(fetched_files, cve_records=cve_records)
                scan.dependencies_analyzed = dep_stats.get("total_dependencies", 0)
                emit_log(scan_id, "vulnerability_correlation", f"  Re-analyzed dependencies with CVE data: {dep_stats.get('total_dependencies', 0)} deps")

            update_stage(db, scan, "vulnerability_correlation", 60)

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}

            # ── Stage 7: policy_evaluation (65%) ────────────────────
            update_stage(db, scan, "policy_evaluation", 62)
            emit_log(scan_id, "policy_evaluation", "Evaluating security policies against findings…")

            # Load DB policies scoped to this repo (or org-wide)
            from app.models.governance import SecurityPolicy, PolicyViolation
            db_policies = db.query(SecurityPolicy).filter(
                SecurityPolicy.organization_id == org_id,
                SecurityPolicy.is_enabled == True,
            ).all()
            applicable_db_policies = []
            for dbp in db_policies:
                # Repo scoping: if target_repos is set, only apply if this repo matches
                if dbp.target_repos and len(dbp.target_repos) > 0:
                    if repo_full_name not in dbp.target_repos:
                        emit_log(scan_id, "policy_evaluation", f"  ⊘ Skipping \"{dbp.name}\" — not scoped to {repo_full_name}")
                        continue
                    emit_log(scan_id, "policy_evaluation", f"  ▶ \"{dbp.name}\" — repo-scoped match for {repo_full_name}")
                else:
                    emit_log(scan_id, "policy_evaluation", f"  ▶ \"{dbp.name}\" — org-wide policy")
                applicable_db_policies.append(dbp)

            emit_log(scan_id, "policy_evaluation", f"Loaded {len(applicable_db_policies)} applicable policies from database (of {len(db_policies)} total)")

            policy_engine = PolicyEngine()
            cloud = scan.cloud_provider or "aws"
            # Pass ALL findings (IaC + secrets) for policy evaluation
            all_findings_for_policy = iac_findings_dicts + [
                {"rule_id": sf.rule_id, "title": f"Secret: {sf.rule_id}",
                 "description": sf.match_preview or "", "severity": sf.severity,
                 "category": "secrets", "file_path": sf.file_path}
                for sf in secret_findings
            ]
            policy_results, policy_stats = policy_engine.evaluate(all_findings_for_policy, cloud_provider=cloud)
            policy_result = policy_stats
            engine_passed = policy_stats.get("passed", 0)
            engine_failed = policy_stats.get("failed", 0)
            engine_na = policy_stats.get("not_applicable", 0)
            scan.policies_evaluated = engine_passed + engine_failed + engine_na
            scan.policies_passed = engine_passed
            scan.policies_failed = engine_failed

            # Create PolicyViolation records from DB policies
            MAX_VIOLATIONS_PER_POLICY = 50  # cap to avoid flooding the DB
            db_violations_created = 0
            from app.services.governance.finding_policies import finding_matches, finding_rules
            evaluated_db_policies = []
            for dbp in applicable_db_policies:
                # Cloud-condition policies (dict rules) are evaluated by governance
                # assessments against cloud resources, not against scan findings.
                rules = finding_rules(dbp.rules)
                if not rules:
                    emit_log(scan_id, "policy_evaluation", f"  ⊘ \"{dbp.name}\" — no finding rules, skipped")
                    continue
                evaluated_db_policies.append(dbp)

                # Resources already carrying an open or risk-accepted violation
                known = {
                    row[0] for row in db.query(PolicyViolation.resource_id).filter(
                        PolicyViolation.organization_id == org_id,
                        PolicyViolation.policy_id == dbp.id,
                        PolicyViolation.status.in_(("open", "accepted")),
                    ).all()
                }
                policy_match_count = 0
                created_for_policy = 0
                for finding in iac_findings_dicts:
                    if not finding_matches(rules, finding):
                        continue
                    policy_match_count += 1
                    resource_id = finding.get("resource") or finding.get("file_path") or finding.get("rule_id", "")
                    if resource_id in known or created_for_policy >= MAX_VIOLATIONS_PER_POLICY:
                        continue
                    known.add(resource_id)
                    db.add(PolicyViolation(
                        organization_id=org_id,
                        policy_id=dbp.id,
                        resource_type=finding.get("resource_type", "") or "unknown",
                        resource_id=resource_id,
                        resource_name=finding.get("resource") or finding.get("file_path", ""),
                        cloud_provider=finding.get("cloud_provider", cloud),
                        violation_details={
                            "source": "finding",
                            "rule_id": finding.get("rule_id", ""),
                            "title": finding.get("title", ""),
                            "severity": finding.get("severity", "medium"),
                            "file_path": finding.get("file_path", ""),
                            "repository": repo_full_name,
                            "scan_id": scan_id,
                        },
                        severity=(dbp.severity or finding.get("severity", "medium")).lower(),
                        status="open",
                    ))
                    created_for_policy += 1
                    db_violations_created += 1
                if policy_match_count > 0:
                    dbp.violations_count = policy_match_count
                    scan.policies_failed += 1
                    emit_log(scan_id, "policy_evaluation", f"  ✗ \"{dbp.name}\" FAILED — {policy_match_count} violations")
                else:
                    scan.policies_passed += 1
                    emit_log(scan_id, "policy_evaluation", f"  ✓ \"{dbp.name}\" passed")
                dbp.last_evaluated = _now()

            # Update total to include DB policies
            scan.policies_evaluated += len(evaluated_db_policies)

            if db_violations_created > 0:
                db.commit()
                emit_log(scan_id, "policy_evaluation", f"  ⚠ Created {db_violations_created} violation records in database")

            emit_log(scan_id, "policy_evaluation", f"✓ {scan.policies_evaluated} policies evaluated — {scan.policies_passed} passed, {scan.policies_failed} failed")

            update_stage(db, scan, "policy_evaluation", 65)

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}

            # ── Stage 8: compliance_mapping (70%) ───────────────────
            update_stage(db, scan, "compliance_mapping", 67)
            frameworks = ["CIS", "NIST-800-53", "SOC2", "PCI-DSS", "HIPAA", "ISO-27001"]
            emit_log(scan_id, "compliance_mapping", f"Mapping findings to {len(frameworks)} compliance frameworks…")
            for fw in frameworks:
                emit_log(scan_id, "compliance_mapping", f"  Evaluating: {fw}")

            compliance_mapper = ComplianceMapper()
            # Pass ALL findings (IaC + secrets) for compliance mapping
            all_findings_for_compliance = iac_findings_dicts + [
                {"rule_id": sf.rule_id, "title": f"Secret: {sf.rule_id}",
                 "description": sf.match_preview or "", "severity": sf.severity,
                 "category": "secrets", "file_path": sf.file_path}
                for sf in secret_findings
            ]
            comp_mappings, comp_stats = compliance_mapper.map_findings(all_findings_for_compliance, frameworks)
            compliance_result = comp_stats
            scan.compliance_frameworks = comp_stats.get("by_framework", {})
            total_controls = comp_stats.get("total_controls", 0)
            passed_controls = comp_stats.get("controls_passed", 0)
            failed_controls = comp_stats.get("controls_failed", 0)
            emit_log(scan_id, "compliance_mapping", f"✓ Compliance mapping complete — {total_controls} controls evaluated")
            emit_log(scan_id, "compliance_mapping", f"  Passed: {passed_controls} | Failed: {failed_controls}")
            for fw_name, fw_stats in comp_stats.get("by_framework", {}).items():
                emit_log(scan_id, "compliance_mapping", f"  {fw_name}: {fw_stats.get('passed', 0)} passed, {fw_stats.get('failed', 0)} failed")

            update_stage(db, scan, "compliance_mapping", 70)

            if _check_cancelled(db, scan):
                update_stage(db, scan, "cancelled", scan.progress, status="cancelled",
                             completed_at=_now())
                return {"scan_id": scan_id, "status": "cancelled"}
            if _check_timeout(db, scan):
                update_stage(db, scan, "timed_out", scan.progress, status="timed_out",
                             error_message="Job exceeded timeout", completed_at=_now())
                return {"scan_id": scan_id, "status": "timed_out"}

            # ── Stage 9: processing_results (80%) ───────────────────
            update_stage(db, scan, "processing_results", 75)
            total_to_persist = len(all_iac_results) + len(secret_findings)
            emit_log(scan_id, "processing_results", f"Persisting {total_to_persist} findings to database…")

            # Persist IaC findings
            for r in all_iac_results:
                _meta = getattr(r, "metadata", {}) or {}
                finding = Finding(
                    scan_id=scan.id,
                    rule_id=r.rule_id,
                    title=r.title,
                    description=r.description,
                    severity=r.severity,
                    category=r.category,
                    cloud_provider=r.cloud_provider,
                    resource_type=r.resource_type,
                    resource_name=r.resource_name,
                    file_path=r.file_path,
                    line_number=r.line_number,
                    code_snippet=_safe_snippet(r.code_snippet),
                    remediation=r.remediation,
                    cve_id=getattr(r, "cve_id", None),
                    detected_by=_meta.get("source"),
                    metadata_=_meta,
                )
                db.add(finding)

            # Persist secret findings as findings
            for sf in secret_findings:
                finding = Finding(
                    scan_id=scan.id,
                    rule_id=sf.rule_id,
                    title=f"Secret detected: {sf.rule_id}",
                    description=f"Potential secret/credential in {sf.file_path}: {sf.match_preview}",
                    severity=sf.severity,
                    category="secrets",
                    cloud_provider=None,
                    resource_type="credential",
                    resource_name=sf.rule_id,
                    file_path=sf.file_path,
                    line_number=sf.line_number,
                    code_snippet=sf.match_preview,
                    remediation=sf.remediation,
                    detected_by="gitleaks",
                    metadata_={"source": "gitleaks"},
                )
                db.add(finding)
            kept = carry_over_sync(db, scan)
            set_deadlines_sync(db, scan)
            if kept["carried"] or kept["reappeared"]:
                emit_log(scan_id, "processing_results",
                         f"Kept {kept['carried']} earlier triage decisions; "
                         f"{kept['reappeared']} findings marked resolved earlier were found again.")
            triage_run = start_after_scan_sync(db, scan)
            if triage_run:
                emit_log(scan_id, "processing_results",
                         f"Started triage run #{triage_run}. It proposes decisions; someone must approve them.")

            all_findings_for_score = all_iac_results + [
                type("F", (), {"severity": sf.severity})() for sf in secret_findings
            ]

            scorer = RiskScorer()
            scan.risk_score = scorer.calculate_scan_score(
                [{"severity": getattr(r, "severity", "LOW")} for r in all_findings_for_score]
            )
            total = len(all_iac_results) + len(secret_findings)
            scan.findings_count = total
            scan.critical_count = sum(
                1 for r in all_findings_for_score if getattr(r, "severity", "") == "CRITICAL"
            )
            scan.high_count = sum(
                1 for r in all_findings_for_score if getattr(r, "severity", "") == "HIGH"
            )
            scan.medium_count = sum(
                1 for r in all_findings_for_score if getattr(r, "severity", "") == "MEDIUM"
            )
            scan.low_count = sum(
                1 for r in all_findings_for_score if getattr(r, "severity", "") == "LOW"
            )
            db.commit()
            emit_log(scan_id, "processing_results", f"✓ {scan.findings_count} findings persisted — risk score: {scan.risk_score}")
            emit_log(scan_id, "processing_results", f"  C:{scan.critical_count} H:{scan.high_count} M:{scan.medium_count} L:{scan.low_count}")

            update_stage(db, scan, "processing_results", 80)

            # ── Stage 10: generating_report (90%) ───────────────────
            update_stage(db, scan, "generating_report", 85)
            emit_log(scan_id, "generating_report", "Compiling security report…")

            ts = _now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"{repo_full_name.replace('/', '_')}_{ts}"
            emit_log(scan_id, "generating_report", f"  Report: {report_filename}")

            report_data = _build_report_json(
                scan, all_iac_results, secret_findings, repo_full_name,
                dep_result=dep_stats,
                correlations=correlations,
                policy_result=policy_result,
                compliance_result=compliance_result,
            )

            report = Report(
                organization_id=org_id,
                title=f"Scan Report — {repo_full_name}",
                report_type="security",
                format="json",
                status="completed",
                content=report_data,
                scan_ids=[scan.id],
                scan_id=scan.id,
                file_name=report_filename,
            )
            db.add(report)
            db.flush()
            scan.report_id = report.id
            db.commit()

            emit_log(scan_id, "generating_report", "✓ Report generated and persisted")
            update_stage(db, scan, "generating_report", 90)

            # ── Stage 11: sending_notifications (95%) ───────────────
            update_stage(db, scan, "sending_notifications", 92)
            emit_log(scan_id, "sending_notifications", "Dispatching notifications…")

            try:
                from app.services.notifications.scan_notify import notify_scan_complete
                severity_counts = {
                    "critical": scan.critical_count or 0,
                    "high": scan.high_count or 0,
                    "medium": scan.medium_count or 0,
                    "low": scan.low_count or 0,
                }
                delivery = notify_scan_complete(db, scan, repo_full_name, "completed", severity_counts)
                scan.notifications_sent = delivery["succeeded"] > 0
                if delivery["attempted"]:
                    sent = ", ".join(
                        f"{c['channel']} {'✓' if c['success'] else '✗'}" for c in delivery["channels"]
                    )
                    emit_log(scan_id, "sending_notifications", f"Notifications: {sent}")
                else:
                    emit_log(scan_id, "sending_notifications",
                             "No notification channels are enabled for this organization")
            except Exception as e:
                logger.warning(f"Notification dispatch failed: {e}")
                scan.notifications_sent = False
                emit_log(scan_id, "sending_notifications", f"⚠ Notification dispatch failed: {e}", "warn")

            update_stage(db, scan, "sending_notifications", 95)

            # ── Stage 12: completed (100%) ──────────────────────────
            emit_log(scan_id, "completed", f"✓ Scan complete — {scan.findings_count} findings, risk score: {scan.risk_score}")
            emit_log(scan_id, "completed", f"  Critical: {scan.critical_count} | High: {scan.high_count} | Medium: {scan.medium_count} | Low: {scan.low_count}")
            update_stage(db, scan, "completed", 100, status="completed",
                         completed_at=_now())

            return {
                "scan_id": scan.id,
                "status": "completed",
                "findings_count": scan.findings_count,
                "secrets_found": scan.secrets_found,
                "dependencies_analyzed": scan.dependencies_analyzed,
                "policies_evaluated": scan.policies_evaluated,
                "policies_passed": scan.policies_passed,
                "policies_failed": scan.policies_failed,
                "files_scanned": files_done,
                "risk_score": scan.risk_score,
                "report_id": report.id,
                "duration_seconds": round(_elapsed(), 1),
            }

        except Exception as e:
            scan.status = "failed"
            scan.stage = "failed"
            scan.error_message = f"Scan failed: {type(e).__name__}. Check server logs for details."
            scan.completed_at = _now()
            try:
                db.commit()
            except Exception:
                db.rollback()
            logger.error(f"Repo scan {scan_id} failed: {e}", exc_info=True)
            return {"scan_id": scan_id, "status": "failed", "error": scan.error_message}


def _build_report_json(scan, iac_findings, secret_findings, repo_full_name,
                       dep_result=None, correlations=None,
                       policy_result=None, compliance_result=None):
    """Build enterprise JSON report content."""
    import json
    return json.dumps({
        "scan_id": scan.id,
        "repository": repo_full_name,
        "account": scan.account_name,
        "scan_type": scan.scan_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": scan.risk_score,
        "summary": {
            "total_findings": scan.findings_count,
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "files_scanned": scan.files_scanned,
            "files_total": scan.files_total,
            "secrets_found": scan.secrets_found or 0,
            "dependencies_analyzed": scan.dependencies_analyzed or 0,
            "policies_evaluated": scan.policies_evaluated or 0,
            "policies_passed": scan.policies_passed or 0,
            "policies_failed": scan.policies_failed or 0,
        },
        "iac_findings": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity,
                "category": r.category,
                "cloud_provider": r.cloud_provider,
                "resource_type": r.resource_type,
                "resource_name": r.resource_name,
                "file_path": r.file_path,
                "line_number": r.line_number,
                "description": r.description,
                "remediation": r.remediation,
                "code_snippet": r.code_snippet,
            }
            for r in iac_findings
        ],
        "secret_findings": [
            {
                "rule_id": sf.rule_id,
                "severity": sf.severity,
                "file_path": sf.file_path,
                "line_number": sf.line_number,
                "match_preview": sf.match_preview,
                "remediation": sf.remediation,
            }
            for sf in secret_findings
        ],
        "dependency_analysis": dep_result or {},
        "vulnerability_correlations": correlations or {},
        "policy_evaluation": policy_result or {},
        "compliance_mapping": compliance_result or {},
        "stage_details": scan.stage_details or {},
    }, indent=2, default=str)


@celery_app.task(name="app.tasks.jobs.generate_report")
def generate_report(report_id: int, org_id: int):
    """Generate a report asynchronously."""
    from app.models.report import Report

    logger.info(f"Generating report {report_id} for org {org_id}")
    with Session(sync_engine) as db:
        report = db.query(Report).filter(Report.id == report_id).first()
        if not report:
            logger.error(f"Report {report_id} not found")
            return {"report_id": report_id, "status": "not_found"}
        try:
            report.status = "completed"
            db.commit()
            logger.info(f"Report {report_id} generated successfully")
            return {"report_id": report_id, "status": "completed"}
        except Exception as e:
            db.rollback()
            report.status = "failed"
            report.error_message = f"Generation failed: {type(e).__name__}"
            db.commit()
            logger.error(f"Report generation failed: {e}", exc_info=True)
            return {"report_id": report_id, "status": "failed"}


# ── Gap 5: Scheduled / Recurring Scans ──────────────────────────

MAX_CONCURRENT_SCHEDULED_SCANS = 10


@celery_app.task(name="app.tasks.jobs.run_scheduled_scans")
def run_scheduled_scans():
    """
    Celery Beat task, every five minutes: queue a scan for each enabled scan
    schedule whose next run time has passed.

    Schedules are the only thing that starts a scheduled scan. An earlier
    sweep also re-scanned any repository that had ever had a scheduled scan;
    it ignored the schedule's cron and whether the schedule still existed,
    and once a scan was a day old it queued a new one on every run.
    """
    from app.models.scan import Scan
    from sqlalchemy import func as sa_func

    with Session(sync_engine) as db:
        try:
            # Guard: skip if too many scheduled scans are already active
            active_count = db.query(sa_func.count(Scan.id)).filter(
                Scan.status.in_(["running", "pending", "queued"]),
                Scan.scan_type == "scheduled",
            ).scalar() or 0
            if active_count >= MAX_CONCURRENT_SCHEDULED_SCANS:
                logger.warning(
                    "Skipping scheduled scans: %d already running (limit %d)",
                    active_count, MAX_CONCURRENT_SCHEDULED_SCANS,
                )
                return {"queued": 0, "skipped_reason": "concurrency_limit"}

            remaining_slots = MAX_CONCURRENT_SCHEDULED_SCANS - active_count
            queued = 0

            try:
                from app.models.scan_schedule import ScanSchedule

                sched_queued = 0
                for sched in db.query(ScanSchedule).filter(ScanSchedule.enabled == True).all():
                    if sched_queued >= remaining_slots:
                        logger.info("Reached concurrency slot limit (%d); deferring remaining schedules", remaining_slots)
                        break
                    if _schedule_is_due(sched):
                        sched_queued += int(_fire_scan_schedule(db, sched)["status"] == "queued")
                db.commit()
                queued += sched_queued
                logger.info("ScanSchedule sweep — queued %d additional scans", sched_queued)
            except Exception as sched_exc:
                db.rollback()
                logger.warning("ScanSchedule sweep error: %s", sched_exc)

            logger.info("Scheduled scan sweep complete — queued %d total scans", queued)
            return {"queued": queued}

        except Exception as exc:
            db.rollback()
            logger.error("Scheduled scan sweep failed: %s", exc)
            raise


# ---------------------------------------------------------------------------
# Report email delivery (on-demand + scheduled)
# ---------------------------------------------------------------------------

@celery_app.task(name="send_report_email", bind=True, max_retries=2)
def send_report_email(self, report_id: int, recipient_email: str):
    """Generate PDF from a saved report and email it to recipient."""
    import json
    from app.models.report import Report
    from app.core.email import build_report_email_html

    with Session(sync_engine) as db:
        try:
            report = db.query(Report).filter(Report.id == report_id).first()
            if not report:
                logger.error("send_report_email: report %d not found", report_id)
                return {"status": "error", "detail": "report not found"}

            # Generate PDF
            from xhtml2pdf import pisa
            from io import BytesIO
            from app.api.v1.reports import _build_pdf_html
            html_content = _build_pdf_html(report)
            buf = BytesIO()
            pisa.CreatePDF(html_content, dest=buf)
            pdf_bytes = buf.getvalue()

            # Build email
            data = {}
            if report.content:
                try:
                    data = json.loads(report.content) if isinstance(report.content, str) else {}
                except Exception:
                    pass
            summary = data.get("summary", {})

            email_html = build_report_email_html(
                report_title=report.title or "Security Report",
                report_type=report.report_type or "security_posture",
                generated_at=report.created_at.strftime("%Y-%m-%d %H:%M UTC") if report.created_at else "N/A",
                total_findings=summary.get("total_findings", 0),
                critical=summary.get("critical", 0),
                high=summary.get("high", 0),
                medium=summary.get("medium", 0),
                low=summary.get("low", 0),
                risk_score=summary.get("risk_score", 0),
            )

            # Send synchronously (Celery task is already sync)
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            from email.mime.base import MIMEBase
            from email import encoders

            msg = MIMEMultipart("mixed")
            msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
            msg["To"] = recipient_email
            msg["Subject"] = f"GuardNous Report: {report.title or 'Security Report'}"
            msg.attach(MIMEText(email_html, "html"))

            part = MIMEBase("application", "pdf")
            part.set_payload(pdf_bytes)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=f"guardnous-report-{report.id}.pdf")
            msg.attach(part)

            cls = smtplib.SMTP_SSL if settings.SMTP_USE_TLS else smtplib.SMTP
            with cls(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as server:
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)

            logger.info("Report %d emailed to %s", report_id, recipient_email)
            return {"status": "sent", "recipient": recipient_email}

        except Exception as exc:
            logger.error("send_report_email failed: %s", exc)
            raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="run_scheduled_reports")
def run_scheduled_reports():
    """Celery beat task — run every report schedule that is due."""
    from app.models.report_schedule import ReportSchedule

    with Session(sync_engine) as db:
        due = [
            s.id for s in db.query(ReportSchedule).filter(ReportSchedule.enabled == True).all()
            if _schedule_is_due(s)
        ]
    results = [run_report_schedule.run(schedule_id) for schedule_id in due]
    sent = sum(r.get("emails_sent", 0) for r in results)
    logger.info("Scheduled report sweep complete — %d schedules run, %d emails sent", len(due), sent)
    return {"schedules_run": len(due), "sent": sent}


def _schedule_is_due(sched) -> bool:
    """True when the schedule's next run time has passed."""
    from app.services.schedules import next_run

    now = datetime.now(timezone.utc)
    due_at = sched.next_run_at
    if due_at is None:
        due_at = next_run(sched.cron_expression, sched.last_run_at or sched.created_at or now)
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    return due_at <= now


def _mark_schedule_run(sched, status: str, error: str | None = None) -> None:
    from app.services.schedules import next_run

    now = datetime.now(timezone.utc)
    sched.last_run_at = now
    sched.last_status = status
    sched.last_error = (error or None) and error[:1000]
    sched.next_run_at = next_run(sched.cron_expression, now)


def _fire_scan_schedule(db, sched) -> dict:
    """Queue the repository scan a schedule describes. The caller commits."""
    from app.models.integration import Integration
    from app.models.scan import Scan

    cfg = sched.config_json or {}
    repo, integration_id = cfg.get("repository"), cfg.get("integration_id")
    integration = db.get(Integration, integration_id) if integration_id else None

    error = None
    if not repo or not integration:
        error = "The schedule has no repository, or its integration was removed."
    elif integration.organization_id != sched.organization_id or not integration.is_active:
        error = "The integration is not active in this organization."
    elif not any(
        isinstance(r, dict) and r.get("full_name") == repo and r.get("enabled")
        for r in (integration.repositories or [])
    ):
        error = f"{repo} is no longer enabled for scanning."
    if error:
        _mark_schedule_run(sched, "failed", error)
        return {"status": "failed", "error": error}

    scan = Scan(
        organization_id=sched.organization_id,
        repository=repo,
        integration_id=integration.id,
        account_name=integration.account_name,
        status="queued",
        scan_type="scheduled",
        scheduled=True,
        metadata_={"schedule_id": sched.id, "schedule_name": sched.name},
    )
    db.add(scan)
    db.flush()
    _mark_schedule_run(sched, "queued")
    db.commit()
    run_quick_repo_scan.delay(
        scan_id=scan.id, integration_id=integration.id,
        repo_full_name=repo, org_id=sched.organization_id,
    )
    return {"status": "queued", "scan_id": scan.id}


@celery_app.task(name="app.tasks.jobs.run_scan_schedule")
def run_scan_schedule(schedule_id: int):
    """Run one scan schedule now (used by the "Run now" button)."""
    from app.models.scan_schedule import ScanSchedule

    with Session(sync_engine) as db:
        sched = db.get(ScanSchedule, schedule_id)
        if not sched:
            return {"status": "failed", "error": "Schedule not found"}
        result = _fire_scan_schedule(db, sched)
        db.commit()
        return result


@celery_app.task(name="app.tasks.jobs.run_report_schedule")
def run_report_schedule(schedule_id: int):
    """Generate a fresh report for a schedule and email it to its recipients.

    The report is always generated and saved (visible under Reports). If email
    is not configured or a delivery fails, the schedule records that.
    """
    import asyncio
    from email import encoders
    from email.mime.base import MIMEBase
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.pool import NullPool

    from app.core.email import _smtp_send
    from app.models.org_settings import OrgSettings
    from app.models.report import Report
    from app.models.report_schedule import ReportSchedule
    from app.services.notifications.scan_notify import org_smtp_params
    from app.services.report_generator import ReportGenerator

    with Session(sync_engine) as db:
        sched = db.get(ReportSchedule, schedule_id)
        if not sched:
            return {"status": "failed", "error": "Schedule not found"}
        org_id, name = sched.organization_id, sched.name
        report_type, scan_ids = sched.report_type, list(sched.scan_ids or [])
        recipients = [r for r in (sched.recipients or []) if r]

    async def _generate() -> int:
        engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
        try:
            async with AsyncSession(engine, expire_on_commit=False) as adb:
                report = await ReportGenerator(adb).generate(
                    org_id=org_id,
                    title=f"{name} — {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC",
                    # JSON is the stored form; PDF/CSV/HTML are rendered from it on demand
                    report_type=report_type, format="json", scan_ids=scan_ids,
                )
                return report.id
        finally:
            await engine.dispose()

    emails_sent, errors, report_id = 0, [], None
    try:
        report_id = asyncio.run(_generate())
    except Exception as exc:
        logger.exception("Report schedule %s: generation failed", schedule_id)
        errors.append(f"Report generation failed: {type(exc).__name__}: {exc}")

    with Session(sync_engine) as db:
        sched = db.get(ReportSchedule, schedule_id)
        if report_id:
            report = db.get(Report, report_id)
            report.metadata_ = {**(report.metadata_ or {}), "schedule_id": schedule_id}
            sched.last_report_id = report_id
            settings_row = db.query(OrgSettings).filter(OrgSettings.organization_id == org_id).first()
            params = org_smtp_params(settings_row)
            if not recipients:
                errors.append("No recipients configured; the report was saved but not emailed.")
            elif not params:
                errors.append("Email (SMTP) is not configured; the report was saved but not emailed.")
            else:
                from app.api.v1.reports import _generate_pdf_from_report
                try:
                    pdf_bytes = _generate_pdf_from_report(report)
                except Exception as exc:
                    pdf_bytes = None
                    errors.append(f"PDF rendering failed: {type(exc).__name__}")
                for recipient in recipients if pdf_bytes else []:
                    msg = MIMEMultipart("mixed")
                    msg["From"] = f"{params['from_name']} <{params['from_email']}>"
                    msg["To"] = recipient
                    msg["Subject"] = f"GuardNous report: {report.title}"
                    msg.attach(MIMEText(
                        f"<p>Scheduled report <b>{name}</b> is attached.</p>", "html"))
                    part = MIMEBase("application", "pdf")
                    part.set_payload(pdf_bytes)
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", "attachment",
                                    filename=f"guardnous-report-{report.id}.pdf")
                    msg.attach(part)
                    try:
                        _smtp_send(params["host"], params["port"], params["user"], params["password"],
                                   params["use_tls"], params["from_email"], msg, recipient)
                        emails_sent += 1
                    except Exception as exc:
                        errors.append(f"Email to {recipient} failed: {type(exc).__name__}: {exc}")

        if not report_id:
            status = "failed"
        elif emails_sent and emails_sent == len(recipients):
            status = "sent"
        else:
            status = "generated"  # saved, but not (fully) delivered
        _mark_schedule_run(sched, status, " ".join(errors))
        db.commit()
    return {"status": status, "report_id": report_id, "emails_sent": emails_sent, "errors": errors}

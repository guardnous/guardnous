"""
Autonomous background agents for GuardNous (Project AEGIS).

These agents run as Celery tasks without user interaction, continuously
monitoring for CVEs, posture drift, compliance violations, and stale findings.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.agent import AgentInsight
from app.models.cve import CVE
from app.models.finding import Finding
from app.models.scan import Scan
from app.tasks.celery_app import celery_app

logger = logging.getLogger("guardnous.agents.autonomous")

sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
SyncSessionLocal = sessionmaker(bind=sync_engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_sync_session() -> Session:
    """Return a synchronous SQLAlchemy session for Celery tasks."""
    return SyncSessionLocal()


def _publish_agent_alert(
    redis_url: str,
    org_id: int,
    agent_name: str,
    alert_data: dict,
) -> None:
    """Publish an alert to the Redis channel ``agent:alerts:{org_id}``."""
    try:
        client = redis.Redis.from_url(redis_url, decode_responses=True)
        channel = f"agent:alerts:{org_id}"
        payload = json.dumps(
            {
                "agent": agent_name,
                "org_id": org_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **alert_data,
            }
        )
        client.publish(channel, payload)
        logger.info("Published alert on %s from %s", channel, agent_name)
    except Exception:
        logger.exception("Failed to publish alert for org %s", org_id)


def _create_insight(
    session: Session,
    org_id: int,
    agent_name: str,
    insight_type: str,
    title: str,
    summary: str,
    details: dict,
) -> AgentInsight:
    """Create and persist an ``AgentInsight`` record."""
    insight = AgentInsight(
        organization_id=org_id,
        kind=insight_type,
        content=f"**{title}**\n\n{summary}",
        data={
            "agent": agent_name,
            "title": title,
            "details": details,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        provider="autonomous-agent",
        model=agent_name,
    )
    session.add(insight)
    session.commit()
    session.refresh(insight)
    logger.info(
        "Created insight id=%s kind=%s for org %s",
        insight.id,
        insight_type,
        org_id,
    )
    return insight


def _get_org_ids(session: Session, org_id: Optional[int]) -> list[int]:
    """Return a list of org IDs to process.  If *org_id* is ``None``, return
    all distinct organisation IDs that have at least one scan."""
    if org_id is not None:
        return [org_id]
    rows = session.query(Scan.organization_id).distinct().all()
    return [r[0] for r in rows]


# ---------------------------------------------------------------------------
# CVE lookup against the synced CVE table (NVD/GHSA/OSV + EPSS + CISA KEV)
# ---------------------------------------------------------------------------

_URGENT_EPSS = 0.5


def _urgent_cves(session: Session, cve_ids: set[str]) -> dict[str, dict]:
    """Return the CVEs in *cve_ids* that warrant an alert, keyed by CVE ID.

    A CVE is urgent when it is in the CISA KEV catalog, has a high EPSS
    exploit probability, or is rated CRITICAL/HIGH. CVEs that have not been
    synced into the local table are not reported.
    """
    if not cve_ids:
        return {}
    rows = session.query(CVE).filter(CVE.cve_id.in_(cve_ids)).all()
    urgent: dict[str, dict] = {}
    for row in rows:
        severity = (row.severity or "").upper()
        epss = row.epss_score or 0.0
        if not (row.is_kev or epss >= _URGENT_EPSS or severity in ("CRITICAL", "HIGH")):
            continue
        urgent[row.cve_id] = {
            "cve_id": row.cve_id,
            "severity": severity or "UNKNOWN",
            "cvss_score": row.cvss_score,
            "summary": (row.description or "")[:300],
            "is_kev": bool(row.is_kev),
            "epss_score": row.epss_score,
        }
    return urgent


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@celery_app.task(name="agent.cve_watchdog", bind=True, max_retries=2)
def cve_watchdog(self, org_id: int = None) -> dict:  # noqa: D401
    """Check dependency findings against CVE feeds every 6 hours."""
    logger.info("CVE Watchdog starting (org_id=%s)", org_id)
    results: dict[str, list] = {}
    try:
        session = _get_sync_session()
        try:
            org_ids = _get_org_ids(session, org_id)
            for oid in org_ids:
                findings = (
                    session.query(Finding)
                    .join(Scan, Finding.scan_id == Scan.id)
                    .filter(
                        Scan.organization_id == oid,
                        Finding.is_fixed.is_(False),
                        Finding.is_ignored.is_(False),
                        Finding.cve_id.isnot(None),
                    )
                    .all()
                )

                urgent = _urgent_cves(session, {f.cve_id for f in findings})
                matches: list[dict] = []
                for f in findings:
                    cve_detail = urgent.get(f.cve_id)
                    if cve_detail:
                        matches.append(
                            {
                                "finding_id": f.id,
                                **cve_detail,
                                "resource": f.resource_name,
                                "file_path": f.file_path,
                            }
                        )

                if matches:
                    _create_insight(
                        session,
                        oid,
                        "cve_watchdog",
                        "triage",
                        f"CVE Watchdog: {len(matches)} open finding(s) with urgent CVEs",
                        (
                            f"{len(matches)} open findings reference CVEs that are critical/high, "
                            f"actively exploited (CISA KEV: {sum(1 for m in matches if m['is_kev'])}) "
                            "or have a high EPSS exploit probability."
                        ),
                        {"matches": matches},
                    )
                    _publish_agent_alert(
                        settings.REDIS_URL,
                        oid,
                        "cve_watchdog",
                        {
                            "type": "cve_match",
                            "match_count": len(matches),
                            "critical_count": sum(
                                1 for m in matches if m["severity"] == "CRITICAL"
                            ),
                            "cve_ids": [m["cve_id"] for m in matches],
                        },
                    )
                results[str(oid)] = matches
                logger.info(
                    "CVE Watchdog org=%s: %d matches", oid, len(matches)
                )
        finally:
            session.close()
    except Exception as exc:
        logger.exception("CVE Watchdog failed")
        raise self.retry(exc=exc, countdown=60)
    return results


@celery_app.task(name="agent.posture_drift", bind=True, max_retries=2)
def posture_drift(self, org_id: int = None, scan_id: int = None) -> dict:  # noqa: D401
    """Compare current scan results with the previous scan to detect drift."""
    logger.info(
        "Posture Drift agent starting (org_id=%s, scan_id=%s)", org_id, scan_id
    )
    results: dict[str, dict] = {}
    try:
        session = _get_sync_session()
        try:
            org_ids = _get_org_ids(session, org_id)

            for oid in org_ids:
                scan_query = (
                    session.query(Scan)
                    .filter(
                        Scan.organization_id == oid,
                        Scan.status == "completed",
                    )
                    .order_by(Scan.completed_at.desc())
                )
                if scan_id:
                    current_scan = session.query(Scan).get(scan_id)
                    if not current_scan:
                        logger.warning("Scan %s not found, skipping", scan_id)
                        continue
                else:
                    current_scan = scan_query.first()
                    if not current_scan:
                        continue

                previous_scan = (
                    scan_query.filter(Scan.id != current_scan.id).first()
                )
                if not previous_scan:
                    logger.info("No previous scan for org %s, skipping drift", oid)
                    continue

                def _severity_dist(s: Scan) -> dict:
                    return {
                        "critical": s.critical_count or 0,
                        "high": s.high_count or 0,
                        "medium": s.medium_count or 0,
                        "low": s.low_count or 0,
                        "total": s.findings_count or 0,
                    }

                curr = _severity_dist(current_scan)
                prev = _severity_dist(previous_scan)

                new_criticals = max(0, curr["critical"] - prev["critical"])
                resolved = max(0, prev["total"] - curr["total"])
                net_change = curr["total"] - prev["total"]
                regression = new_criticals > 0 or net_change > 0

                drift_summary = {
                    "current_scan_id": current_scan.id,
                    "previous_scan_id": previous_scan.id,
                    "current_distribution": curr,
                    "previous_distribution": prev,
                    "new_criticals": new_criticals,
                    "resolved_findings": resolved,
                    "net_change": net_change,
                    "regression_detected": regression,
                }

                status_label = "regression" if regression else "improved"
                _create_insight(
                    session,
                    oid,
                    "posture_drift",
                    "triage",
                    f"Posture Drift: {status_label} ({net_change:+d} findings)",
                    (
                        f"Scan {current_scan.id} vs {previous_scan.id}: "
                        f"{new_criticals} new critical, {resolved} resolved, "
                        f"net change {net_change:+d}."
                    ),
                    drift_summary,
                )

                if regression:
                    _publish_agent_alert(
                        settings.REDIS_URL,
                        oid,
                        "posture_drift",
                        {
                            "type": "posture_regression",
                            "new_criticals": new_criticals,
                            "net_change": net_change,
                            "scan_id": current_scan.id,
                        },
                    )

                results[str(oid)] = drift_summary
                logger.info("Posture Drift org=%s: %s", oid, status_label)
        finally:
            session.close()
    except Exception as exc:
        logger.exception("Posture Drift agent failed")
        raise self.retry(exc=exc, countdown=60)
    return results


@celery_app.task(name="agent.compliance_monitor", bind=True, max_retries=2)
def compliance_monitor(self, org_id: int = None) -> dict:  # noqa: D401
    """Daily check of findings tagged with compliance frameworks."""
    FRAMEWORKS = ("CIS", "SOC2", "HIPAA", "PCI")
    logger.info("Compliance Monitor starting (org_id=%s)", org_id)
    results: dict[str, dict] = {}
    try:
        session = _get_sync_session()
        try:
            org_ids = _get_org_ids(session, org_id)

            for oid in org_ids:
                latest_scan = (
                    session.query(Scan)
                    .filter(
                        Scan.organization_id == oid,
                        Scan.status == "completed",
                    )
                    .order_by(Scan.completed_at.desc())
                    .first()
                )
                if not latest_scan:
                    continue

                open_findings = (
                    session.query(Finding)
                    .filter(
                        Finding.scan_id == latest_scan.id,
                        Finding.is_fixed.is_(False),
                        Finding.is_ignored.is_(False),
                    )
                    .all()
                )

                framework_status: dict[str, dict] = {}
                for fw in FRAMEWORKS:
                    violations = [
                        f
                        for f in open_findings
                        if (f.rule_id and fw.lower() in f.rule_id.lower())
                        or (f.category and fw.lower() in f.category.lower())
                        or (
                            isinstance(f.metadata_, dict)
                            and fw.lower()
                            in json.dumps(f.metadata_).lower()
                        )
                    ]
                    critical_violations = [
                        v for v in violations if v.severity == "CRITICAL"
                    ]
                    framework_status[fw] = {
                        "total_violations": len(violations),
                        "critical_violations": len(critical_violations),
                        "high_violations": sum(
                            1 for v in violations if v.severity == "HIGH"
                        ),
                        "sample_rule_ids": [
                            v.rule_id for v in violations[:5]
                        ],
                    }

                total_violations = sum(
                    fs["total_violations"] for fs in framework_status.values()
                )
                total_critical = sum(
                    fs["critical_violations"] for fs in framework_status.values()
                )

                _create_insight(
                    session,
                    oid,
                    "compliance_monitor",
                    "triage",
                    f"Compliance Status: {total_violations} violation(s) across {len(FRAMEWORKS)} frameworks",
                    (
                        f"Found {total_violations} compliance violations "
                        f"({total_critical} critical) spanning "
                        f"{', '.join(FRAMEWORKS)}."
                    ),
                    {
                        "scan_id": latest_scan.id,
                        "frameworks": framework_status,
                        "total_violations": total_violations,
                        "total_critical": total_critical,
                    },
                )

                if total_critical > 0:
                    _publish_agent_alert(
                        settings.REDIS_URL,
                        oid,
                        "compliance_monitor",
                        {
                            "type": "compliance_violation",
                            "total_violations": total_violations,
                            "critical_violations": total_critical,
                            "frameworks_affected": [
                                fw
                                for fw, fs in framework_status.items()
                                if fs["total_violations"] > 0
                            ],
                        },
                    )

                results[str(oid)] = framework_status
                logger.info(
                    "Compliance Monitor org=%s: %d violations", oid, total_violations
                )
        finally:
            session.close()
    except Exception as exc:
        logger.exception("Compliance Monitor failed")
        raise self.retry(exc=exc, countdown=60)
    return results


@celery_app.task(name="agent.stale_finding_detector", bind=True, max_retries=2)
def stale_finding_detector(self, org_id: int = None) -> dict:  # noqa: D401
    """Daily scan for critical/high findings older than 30 days without remediation."""
    STALE_THRESHOLD_DAYS = 30
    logger.info("Stale Finding Detector starting (org_id=%s)", org_id)
    results: dict[str, list] = {}
    try:
        session = _get_sync_session()
        try:
            org_ids = _get_org_ids(session, org_id)
            cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_THRESHOLD_DAYS)

            for oid in org_ids:
                stale_findings = (
                    session.query(Finding)
                    .join(Scan, Finding.scan_id == Scan.id)
                    .filter(
                        Scan.organization_id == oid,
                        Finding.is_fixed.is_(False),
                        Finding.is_ignored.is_(False),
                        Finding.severity.in_(["CRITICAL", "HIGH"]),
                        Finding.created_at < cutoff,
                    )
                    .order_by(Finding.severity, Finding.created_at)
                    .all()
                )

                if not stale_findings:
                    logger.info("No stale findings for org %s", oid)
                    continue

                stale_items = [
                    {
                        "finding_id": f.id,
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "title": f.title,
                        "file_path": f.file_path,
                        "age_days": (
                            datetime.now(timezone.utc) - f.created_at.replace(tzinfo=timezone.utc)
                        ).days
                        if f.created_at
                        else STALE_THRESHOLD_DAYS,
                    }
                    for f in stale_findings
                ]

                critical_count = sum(
                    1 for s in stale_items if s["severity"] == "CRITICAL"
                )
                high_count = sum(
                    1 for s in stale_items if s["severity"] == "HIGH"
                )

                _create_insight(
                    session,
                    oid,
                    "stale_finding_detector",
                    "triage",
                    f"Stale Findings: {len(stale_items)} unresolved for 30+ days",
                    (
                        f"{critical_count} critical and {high_count} high severity "
                        f"findings have been open for over {STALE_THRESHOLD_DAYS} days. "
                        "Review and remediate or explicitly accept the risk."
                    ),
                    {
                        "threshold_days": STALE_THRESHOLD_DAYS,
                        "stale_count": len(stale_items),
                        "critical_count": critical_count,
                        "high_count": high_count,
                        "items": stale_items[:50],
                    },
                )

                _publish_agent_alert(
                    settings.REDIS_URL,
                    oid,
                    "stale_finding_detector",
                    {
                        "type": "stale_findings",
                        "stale_count": len(stale_items),
                        "critical_count": critical_count,
                        "high_count": high_count,
                    },
                )

                results[str(oid)] = stale_items
                logger.info(
                    "Stale Finding Detector org=%s: %d stale",
                    oid,
                    len(stale_items),
                )
        finally:
            session.close()
    except Exception as exc:
        logger.exception("Stale Finding Detector failed")
        raise self.retry(exc=exc, countdown=60)
    return results


# The beat schedule for these tasks lives in app/tasks/celery_app.py.

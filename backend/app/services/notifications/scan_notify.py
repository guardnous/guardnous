"""Deliver scan-completion notifications according to the organization's
saved notification preferences (Settings → Notifications).

Used by the Celery scan jobs, so everything here is synchronous.
"""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx
from sqlalchemy.orm import Session

from app.core.rbac import ROLE_RANK
from app.models.notification import Notification
from app.models.org_settings import OrgSettings
from app.models.user import User
from app.services.notifications.dispatcher import NotificationDispatcher

logger = logging.getLogger(__name__)

_SEVERITIES = ("critical", "high", "medium", "low")
# Defaults mirror NotificationPrefsResponse in app/api/v1/org_settings.py
_DEFAULTS = {
    "email_enabled": True, "email_critical": True, "email_high": True,
    "email_medium": False, "email_low": False, "email_digest": "daily",
    "in_app_enabled": True, "in_app_scans": True,
    "slack_enabled": False, "slack_webhook": "",
    "teams_enabled": False, "teams_webhook": "",
}
_EMAIL_MIN_RANK = ROLE_RANK["security_lead"]


def _send_teams(webhook_url: str, payload: dict, timeout: float = 10.0) -> bool:
    counts = payload["severity_counts"]
    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": payload["summary"],
        "title": "GuardNous Scan Result",
        "text": payload["summary"],
        "sections": [{"facts": [
            {"name": s.capitalize(), "value": str(counts.get(s, 0))} for s in _SEVERITIES
        ]}],
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            client.post(webhook_url, json=card).raise_for_status()
        return True
    except Exception as exc:
        logger.warning("Teams delivery failed: %s", exc)
        return False


def org_smtp_params(settings_row: OrgSettings | None) -> dict | None:
    """SMTP settings for an organization (its own, else the server's). None if unconfigured."""
    from app.core.email import _resolve_smtp_params
    from app.core.encryption import decrypt_token

    smtp_config = None
    if settings_row is not None and settings_row.smtp_enabled and settings_row.smtp_host:
        password = ""
        if settings_row.smtp_password_encrypted:
            password = decrypt_token(settings_row.smtp_password_encrypted)
        smtp_config = {
            "host": settings_row.smtp_host, "port": settings_row.smtp_port,
            "user": settings_row.smtp_user, "password": password,
            "use_tls": settings_row.smtp_use_tls,
            "from_email": settings_row.smtp_from_email,
            "from_name": settings_row.smtp_from_name,
        }
    return _resolve_smtp_params(smtp_config)


def _send_scan_email(settings_row: OrgSettings, to_email: str, payload: dict) -> bool:
    from app.core.email import _smtp_send

    params = org_smtp_params(settings_row)
    if not params:
        return False

    counts = payload["severity_counts"]
    lines = "".join(f"<li>{s.capitalize()}: {counts.get(s, 0)}</li>" for s in _SEVERITIES)
    msg = MIMEMultipart("alternative")
    msg["From"] = f"{params['from_name']} <{params['from_email']}>"
    msg["To"] = to_email
    msg["Subject"] = f"GuardNous scan #{payload['scan_id']}: {payload['total_findings']} findings"
    msg.attach(MIMEText(payload["summary"], "plain"))
    msg.attach(MIMEText(f"<p>{payload['summary']}</p><ul>{lines}</ul>", "html"))
    try:
        _smtp_send(params["host"], params["port"], params["user"], params["password"],
                   params["use_tls"], params["from_email"], msg, to_email)
        return True
    except Exception as exc:
        logger.warning("Scan email to %s failed: %s", to_email, exc)
        return False


def notify_scan_complete(
    db: Session, scan, repository: str, status: str, severity_counts: dict,
) -> dict:
    """Send the scan result to every channel the organization has enabled.

    Returns {"attempted", "succeeded", "channels": [...]}. Nothing is sent, and
    nothing is reported as sent, for channels that are disabled or unconfigured.
    The caller commits the session (in-app notifications are added to it).
    """
    result = {"attempted": 0, "succeeded": 0, "channels": []}

    def _record(channel: str, ok: bool) -> None:
        result["attempted"] += 1
        result["succeeded"] += int(ok)
        result["channels"].append({"channel": channel, "success": ok})

    org_id = scan.organization_id
    settings_row = db.query(OrgSettings).filter(OrgSettings.organization_id == org_id).first()
    prefs = {**_DEFAULTS, **((settings_row.notification_prefs if settings_row else None) or {})}

    dispatcher = NotificationDispatcher()
    payload = dispatcher._build_payload(
        scan.id, repository, scan.account_name or "", status, severity_counts, None
    )

    if prefs["slack_enabled"] and prefs["slack_webhook"]:
        _record("slack", dispatcher._send_slack(prefs["slack_webhook"], payload))

    if prefs["teams_enabled"] and prefs["teams_webhook"]:
        _record("teams", _send_teams(prefs["teams_webhook"], payload))

    users = db.query(User).filter(User.organization_id == org_id, User.is_active.is_(True)).all()

    # Email is sent per scan only in realtime mode, and only when the scan has
    # findings at a severity the organization opted into.
    wants_email = (
        settings_row is not None
        and prefs["email_enabled"]
        and prefs["email_digest"] == "realtime"
        and any(prefs[f"email_{s}"] and severity_counts.get(s, 0) for s in _SEVERITIES)
    )
    if wants_email:
        for user in users:
            if user.email and ROLE_RANK.get(user.role, 0) >= _EMAIL_MIN_RANK:
                _record("email", _send_scan_email(settings_row, user.email, payload))

    if prefs["in_app_enabled"] and prefs["in_app_scans"] and users:
        category = "success" if payload["total_findings"] == 0 else "warning"
        for user in users:
            db.add(Notification(
                user_id=user.id, tenant_id=user.tenant_id, organization_id=org_id,
                title=f"Scan #{scan.id} {status}", message=payload["summary"],
                category=category, link=f"/scans/{scan.id}",
            ))
        _record("in_app", True)

    return result

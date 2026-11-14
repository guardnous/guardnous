"""Reusable audit-log writer.

Usage:
    from app.core.audit import write_audit_log

    await write_audit_log(
        db=db,
        user=current_user,       # SQLAlchemy User model
        action="create",         # create | read | update | delete | login | logout
        resource_type="scan",    # users, scans, roles, integrations, ...
        resource_id=scan.id,
        details={"name": scan.name},
        request=request,         # optional FastAPI Request (extracts IP + UA)
    )
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


async def write_audit_log(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    resource_id: Optional[int] = None,
    details: Optional[dict[str, Any]] = None,
    user: Any = None,
    user_id: Optional[int] = None,
    tenant_id: Optional[int] = None,
    request: Optional[Request] = None,
) -> AuditLog:
    """Insert an immutable audit-log row and flush it."""

    uid = user_id or (getattr(user, "id", None) if user else None)
    tid = tenant_id or (getattr(user, "tenant_id", None) if user else None)

    ip_address = None
    user_agent = None
    if request:
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

    # Enrich details with user display info when available
    enriched = dict(details or {})
    if user:
        enriched.setdefault("user_name", getattr(user, "full_name", None) or getattr(user, "email", ""))
        enriched.setdefault("user_email", getattr(user, "email", ""))

    entry = AuditLog(
        tenant_id=tid,
        user_id=uid,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=enriched,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(entry)
    await db.flush()
    logger.debug("audit: %s %s/%s by user=%s", action, resource_type, resource_id, uid)

    # Generate in-app notification for the acting user
    if uid:
        try:
            from app.core.notifications import notify
            _CATEGORY_MAP = {
                "create": "success", "delete": "warning", "login": "info",
                "update": "info", "invite": "success",
            }
            _TITLE_MAP = {
                ("login", "auth"): "Signed in successfully",
                ("create", "scan"): "Assessment started",
                ("create", "integration"): "Integration connected",
                ("invite", "users"): "Invitation sent",
                ("create", "role"): "New role created",
                ("delete", "role"): "Role deleted",
                ("create", "tenant"): "New organization created",
                ("update", "tenant"): "Organization updated",
                ("create", "policy"): "Security policy created",
                ("delete", "policy"): "Security policy deleted",
                ("create", "report"): "Report generated",
                ("delete", "report"): "Report deleted",
                ("update", "repository"): "Repository scan toggled",
            }
            title = _TITLE_MAP.get((action, resource_type), f"{action.capitalize()}d {resource_type}")
            msg = enriched.get("user_name", "") or ""
            if msg:
                msg = f"By {msg}"
            cat = _CATEGORY_MAP.get(action, "info")
            _LINK_MAP = {
                "scan": "/scans", "integration": "/integrations",
                "users": "/admin/users", "role": "/admin/roles",
                "tenant": "/admin/tenants", "policy": "/governance",
                "auth": "/dashboard", "report": "/reports",
                "repository": "/integrations",
            }
            link = _LINK_MAP.get(resource_type)
            await notify(
                db=db, user_id=uid, title=title, message=msg or None,
                category=cat, link=link, tenant_id=tid,
            )
        except Exception as exc:
            logger.warning("Failed to create notification: %s", exc)

    return entry

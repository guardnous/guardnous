"""Reusable in-app notification writer.

Usage:
    from app.core.notifications import notify

    await notify(
        db=db,
        user_id=current_user.id,
        title="Scan completed",
        message="Terraform scan found 3 critical findings",
        category="warning",
        link="/scans/5",
        tenant_id=current_user.tenant_id,
    )
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.notification import Notification

logger = logging.getLogger(__name__)


async def notify(
    db: AsyncSession,
    *,
    user_id: int,
    title: str,
    message: Optional[str] = None,
    category: str = "info",
    link: Optional[str] = None,
    tenant_id: Optional[int] = None,
) -> Notification:
    """Insert an in-app notification."""
    entry = Notification(
        user_id=user_id,
        tenant_id=tenant_id,
        title=title,
        message=message,
        category=category,
        link=link,
    )
    db.add(entry)
    await db.flush()
    logger.debug("notification: [%s] %s for user=%s", category, title, user_id)
    return entry

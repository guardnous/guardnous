"""
Notifications API — in-app notification bell endpoints.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import select, func, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.notification import Notification
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

router = APIRouter()


class NotificationResponse(BaseModel):
    id: int
    title: str
    message: Optional[str] = None
    category: str
    is_read: bool
    link: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class NotificationListResponse(BaseModel):
    items: list[NotificationResponse]
    unread_count: int
    total: int


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    limit: int = 50,
    unread_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List notifications for the current user."""
    base = select(Notification).where(Notification.user_id == current_user.id)
    if unread_only:
        base = base.where(Notification.is_read == False)  # noqa: E712

    q = base.order_by(Notification.created_at.desc()).limit(limit)
    result = await db.execute(q)
    items = result.scalars().all()

    # Unread count
    count_q = select(func.count()).select_from(Notification).where(
        Notification.user_id == current_user.id,
        Notification.is_read == False,  # noqa: E712
    )
    unread_count = (await db.execute(count_q)).scalar() or 0

    total_q = select(func.count()).select_from(Notification).where(
        Notification.user_id == current_user.id,
    )
    total = (await db.execute(total_q)).scalar() or 0

    return NotificationListResponse(
        items=[NotificationResponse.model_validate(n) for n in items],
        unread_count=unread_count,
        total=total,
    )


@router.patch("/{notification_id}/read")
async def mark_read(
    notification_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark a single notification as read."""
    await db.execute(
        update(Notification)
        .where(Notification.id == notification_id, Notification.user_id == current_user.id)
        .values(is_read=True)
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/mark-all-read")
async def mark_all_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark all notifications as read for the current user."""
    await db.execute(
        update(Notification)
        .where(Notification.user_id == current_user.id, Notification.is_read == False)  # noqa: E712
        .values(is_read=True)
    )
    await db.commit()
    return {"status": "ok"}


@router.delete("/clear")
async def clear_all(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete all notifications for the current user."""
    await db.execute(
        delete(Notification).where(Notification.user_id == current_user.id)
    )
    await db.commit()
    return {"status": "ok"}

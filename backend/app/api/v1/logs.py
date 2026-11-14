"""Application logs API — query, stream (SSE tail), and manage log entries."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func, delete, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, async_session
from app.core.rbac import require_permission, is_superuser
from app.core.app_logger import CATEGORIES, LEVEL_ORDER, app_log
from app.models.app_log import AppLog
from app.models.user import User

router = APIRouter()


def _org_scope(user: User) -> list:
    """Log rows are installation-wide; only superusers may see other orgs' entries."""
    if is_superuser(user):
        return []
    return [AppLog.organization_id == user.organization_id]


class LogEntry(BaseModel):
    id: int
    level: str
    category: str
    message: str
    source: Optional[str] = None
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    organization_id: Optional[int] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    request_ip: Optional[str] = None
    status_code: Optional[int] = None
    duration_ms: Optional[int] = None
    metadata: Optional[dict] = None
    traceback: Optional[str] = None
    created_at: Optional[str] = None

    class Config:
        from_attributes = True


class LogsResponse(BaseModel):
    logs: list[LogEntry]
    total: int
    page: int
    page_size: int
    has_more: bool


class LogStats(BaseModel):
    total: int
    by_level: dict[str, int]
    by_category: dict[str, int]
    categories: list[str]
    levels: list[str]


def _serialize_log(row: AppLog) -> dict:
    return {
        "id": row.id,
        "level": row.level,
        "category": row.category,
        "message": row.message,
        "source": row.source,
        "user_id": row.user_id,
        "user_email": row.user_email,
        "organization_id": row.organization_id,
        "request_method": row.request_method,
        "request_path": row.request_path,
        "request_ip": row.request_ip,
        "status_code": row.status_code,
        "duration_ms": row.duration_ms,
        "metadata": row.metadata_,
        "traceback": row.traceback,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("", response_model=LogsResponse)
async def get_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    level: Optional[str] = Query(None, description="Filter by level: DEBUG,VERBOSE,INFO,WARNING,ERROR,CRITICAL"),
    category: Optional[str] = Query(None, description="Filter by category: AUTH,SCAN,REPORT,..."),
    search: Optional[str] = Query(None, description="Search in message text"),
    since: Optional[str] = Query(None, description="ISO datetime — logs after this time"),
    until: Optional[str] = Query(None, description="ISO datetime — logs before this time"),
    user_email: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Query application logs with filters and pagination."""
    conditions = _org_scope(current_user)

    if level:
        levels = [l.strip().upper() for l in level.split(",")]
        conditions.append(AppLog.level.in_(levels))
    if category:
        cats = [c.strip().upper() for c in category.split(",")]
        conditions.append(AppLog.category.in_(cats))
    if search:
        conditions.append(AppLog.message.ilike(f"%{search}%"))
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            conditions.append(AppLog.created_at >= since_dt)
        except ValueError:
            pass
    if until:
        try:
            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
            conditions.append(AppLog.created_at <= until_dt)
        except ValueError:
            pass
    if user_email:
        conditions.append(AppLog.user_email.ilike(f"%{user_email}%"))

    where = and_(*conditions) if conditions else True

    # Count
    count_q = select(func.count(AppLog.id)).where(where)
    total = (await db.execute(count_q)).scalar() or 0

    # Fetch
    offset = (page - 1) * page_size
    q = (
        select(AppLog)
        .where(where)
        .order_by(desc(AppLog.created_at))
        .offset(offset)
        .limit(page_size)
    )
    rows = (await db.execute(q)).scalars().all()

    return LogsResponse(
        logs=[LogEntry(**_serialize_log(r)) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        has_more=offset + page_size < total,
    )


@router.get("/stats", response_model=LogStats)
async def get_log_stats(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Get log statistics for the last N hours."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    scope = and_(AppLog.created_at >= since, *_org_scope(current_user))

    total_q = select(func.count(AppLog.id)).where(scope)
    total = (await db.execute(total_q)).scalar() or 0

    level_q = (
        select(AppLog.level, func.count(AppLog.id))
        .where(scope)
        .group_by(AppLog.level)
    )
    level_rows = (await db.execute(level_q)).all()
    by_level = {r[0]: r[1] for r in level_rows}

    cat_q = (
        select(AppLog.category, func.count(AppLog.id))
        .where(scope)
        .group_by(AppLog.category)
    )
    cat_rows = (await db.execute(cat_q)).all()
    by_category = {r[0]: r[1] for r in cat_rows}

    return LogStats(
        total=total,
        by_level=by_level,
        by_category=by_category,
        categories=list(CATEGORIES),
        levels=list(LEVEL_ORDER.keys()),
    )


@router.get("/stream")
async def stream_logs(
    level: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Server-Sent Events (SSE) stream for real-time log tailing.

    EventSource doesn't support Authorization headers, so accept token via query param.
    """
    if not token:
        raise HTTPException(status_code=401, detail="Token required")
    from jose import JWTError
    from app.core.security import decode_access_token
    from app.core.rbac import get_user_permissions, is_superuser
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    stream_user = (await db.execute(select(User).where(User.id == int(payload["sub"])))).scalar_one_or_none()
    if not stream_user or not stream_user.is_active:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not is_superuser(stream_user):
        perms = await get_user_permissions(stream_user.id, db, tenant_id=stream_user.tenant_id)
        if not ({"settings:read", "settings:manage", "*:*"} & perms):
            raise HTTPException(status_code=403, detail="Permission denied: requires settings:read")
    stream_scope = _org_scope(stream_user)

    async def event_generator():
        last_id = 0
        # Get the latest ID to start from
        async with async_session() as db:
            result = await db.execute(
                select(func.max(AppLog.id)).where(*stream_scope)
            )
            max_id = result.scalar()
            if max_id:
                last_id = max_id

        while True:
            try:
                async with async_session() as db:
                    conditions = [AppLog.id > last_id, *stream_scope]
                    if level:
                        levels = [l.strip().upper() for l in level.split(",")]
                        conditions.append(AppLog.level.in_(levels))
                    if category:
                        cats = [c.strip().upper() for c in category.split(",")]
                        conditions.append(AppLog.category.in_(cats))

                    q = (
                        select(AppLog)
                        .where(and_(*conditions))
                        .order_by(AppLog.id)
                        .limit(50)
                    )
                    rows = (await db.execute(q)).scalars().all()

                    for row in rows:
                        data = json.dumps(_serialize_log(row), default=str)
                        yield f"data: {data}\n\n"
                        last_id = row.id

                await asyncio.sleep(2)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.delete("")
async def clear_logs(
    before_days: int | None = Query(None, alias="before_days", ge=1, le=365, description="Delete logs older than N days"),
    days: int | None = Query(None, ge=0, le=365, description="Alias for before_days (0 = clear all)"),
    all: bool = Query(False, description="Clear all logs"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "delete")),
):
    """Delete logs. Use all=true or days=0 to clear everything."""
    effective_days = before_days or days
    clear_all = all or effective_days == 0

    scope = _org_scope(current_user)
    if clear_all:
        result = await db.execute(delete(AppLog).where(*scope))
        msg = f"Cleared {result.rowcount} log entries (all)"
    else:
        effective_days = effective_days or 30
        cutoff = datetime.now(timezone.utc) - timedelta(days=effective_days)
        result = await db.execute(
            delete(AppLog).where(AppLog.created_at < cutoff, *scope)
        )
        msg = f"Cleared {result.rowcount} log entries older than {effective_days} days"

    count = result.rowcount
    await db.commit()

    await app_log.info(db, "SYSTEM", msg, user=current_user)

    return {"deleted": count, "message": msg}

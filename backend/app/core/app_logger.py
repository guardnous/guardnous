"""
Centralized application logger for GuardNous.

Writes structured log entries to the app_logs table.
Log level filtering is controlled by the org's `log_level` setting.

Categories (tuples):
    AUTH        – login, logout, token refresh, failed login, password reset, 2FA
    USER        – create, update, delete, invite, role change
    SCAN        – start, complete, fail, cancel, progress
    REPORT      – generate, download, delete, export
    INTEGRATION – connect, disconnect, sync, webhook, token refresh, error
    SETTINGS    – general update, notification update, SMTP update, log level change
    SYSTEM      – startup, shutdown, health check, migration, scheduler
    API         – request, response, slow query, rate limit
    SECURITY    – permission denied, brute force, suspicious activity, encryption error
    AI          – chat, provider switch, token usage, error
    IAM         – scan, threat detected, policy violation
    GOVERNANCE  – policy create, policy update, compliance check
    NOTIFICATION – email sent, email failed, in-app created

Usage:
    from app.core.app_logger import app_log

    # Fire-and-forget (uses background task, no await needed in request handlers)
    await app_log(
        db=db,
        level="INFO",
        category="AUTH",
        message="User logged in successfully",
        user=current_user,
        request=request,
        metadata={"method": "password"},
    )

    # Or use convenience methods:
    await app_log.info(db, "AUTH", "User logged in", user=current_user, request=request)
    await app_log.error(db, "SCAN", "Scan failed", metadata={"scan_id": 42, "error": str(e)})
"""

from __future__ import annotations

import logging
import traceback as tb_mod
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.models.app_log import AppLog

python_logger = logging.getLogger("guardnous.app")

# Log level hierarchy (numeric for comparison)
LEVEL_ORDER = {
    "DEBUG": 10,
    "VERBOSE": 15,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

# All defined categories
CATEGORIES = (
    "AUTH",
    "USER",
    "SCAN",
    "REPORT",
    "INTEGRATION",
    "SETTINGS",
    "SYSTEM",
    "API",
    "SECURITY",
    "AI",
    "IAM",
    "GOVERNANCE",
    "NOTIFICATION",
)

# Cached org log levels – refreshed periodically
_org_level_cache: dict[int, str] = {}


async def _get_org_log_level(db: AsyncSession, org_id: int | None) -> str:
    """Get configured log level for an org. Defaults to INFO."""
    if org_id is None:
        return "INFO"
    if org_id in _org_level_cache:
        return _org_level_cache[org_id]
    try:
        result = await db.execute(
            text("SELECT log_level FROM org_settings WHERE organization_id = :oid"),
            {"oid": org_id},
        )
        row = result.first()
        level = (row[0] if row and row[0] else "INFO").upper()
        _org_level_cache[org_id] = level
        return level
    except Exception:
        return "INFO"


def clear_log_level_cache(org_id: int | None = None):
    """Clear cached log levels. Call when settings change."""
    if org_id:
        _org_level_cache.pop(org_id, None)
    else:
        _org_level_cache.clear()


async def _write_log(
    db: AsyncSession,
    *,
    level: str,
    category: str,
    message: str,
    source: str | None = None,
    user: Any = None,
    user_id: int | None = None,
    user_email: str | None = None,
    organization_id: int | None = None,
    request: Request | None = None,
    status_code: int | None = None,
    duration_ms: int | None = None,
    metadata: dict[str, Any] | None = None,
    traceback: str | None = None,
) -> AppLog | None:
    """Write a log entry to the database if it passes the configured level filter."""

    level = level.upper()
    category = category.upper()

    uid = user_id or (getattr(user, "id", None) if user else None)
    uemail = user_email or (getattr(user, "email", None) if user else None)
    oid = organization_id or (getattr(user, "organization_id", None) if user else None)

    # Check level against org setting
    configured_level = await _get_org_log_level(db, oid)
    if LEVEL_ORDER.get(level, 20) < LEVEL_ORDER.get(configured_level, 20):
        return None

    req_method = None
    req_path = None
    req_ip = None
    if request:
        req_method = request.method
        req_path = str(request.url.path)
        req_ip = request.client.host if request.client else None

    entry = AppLog(
        level=level,
        category=category,
        message=message,
        source=source,
        user_id=uid,
        user_email=uemail,
        organization_id=oid,
        request_method=req_method,
        request_path=req_path,
        request_ip=req_ip,
        status_code=status_code,
        duration_ms=duration_ms,
        metadata_=metadata or {},
        traceback=traceback,
    )
    db.add(entry)
    await db.flush()

    # Also log to Python logger
    python_logger.log(
        LEVEL_ORDER.get(level, 20),
        "[%s] %s: %s",
        category,
        level,
        message,
    )

    return entry


class AppLogger:
    """Convenience wrapper providing level-specific methods."""

    async def __call__(
        self,
        db: AsyncSession,
        *,
        level: str = "INFO",
        category: str = "SYSTEM",
        message: str = "",
        **kwargs: Any,
    ) -> AppLog | None:
        return await _write_log(db, level=level, category=category, message=message, **kwargs)

    async def debug(self, db: AsyncSession, category: str, message: str, **kw: Any) -> AppLog | None:
        return await _write_log(db, level="DEBUG", category=category, message=message, **kw)

    async def verbose(self, db: AsyncSession, category: str, message: str, **kw: Any) -> AppLog | None:
        return await _write_log(db, level="VERBOSE", category=category, message=message, **kw)

    async def info(self, db: AsyncSession, category: str, message: str, **kw: Any) -> AppLog | None:
        return await _write_log(db, level="INFO", category=category, message=message, **kw)

    async def warning(self, db: AsyncSession, category: str, message: str, **kw: Any) -> AppLog | None:
        return await _write_log(db, level="WARNING", category=category, message=message, **kw)

    async def error(self, db: AsyncSession, category: str, message: str, **kw: Any) -> AppLog | None:
        return await _write_log(db, level="ERROR", category=category, message=message, **kw)

    async def critical(self, db: AsyncSession, category: str, message: str, **kw: Any) -> AppLog | None:
        return await _write_log(db, level="CRITICAL", category=category, message=message, **kw)

    async def exception(self, db: AsyncSession, category: str, message: str, exc: Exception | None = None, **kw: Any) -> AppLog | None:
        tb = tb_mod.format_exc() if exc else None
        return await _write_log(db, level="ERROR", category=category, message=message, traceback=tb, **kw)


# Singleton instance
app_log = AppLogger()

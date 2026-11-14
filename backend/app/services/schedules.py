"""Shared helpers for scan and report schedules."""
from datetime import datetime, timezone

from croniter import croniter
from fastapi import HTTPException

# The beat sweep runs every 5 minutes, so anything more frequent cannot be honoured.
MIN_INTERVAL_SECONDS = 15 * 60


def next_run(cron_expression: str, after: datetime | None = None) -> datetime:
    base = after or datetime.now(timezone.utc)
    nxt = croniter(cron_expression, base).get_next(datetime)
    return nxt if nxt.tzinfo else nxt.replace(tzinfo=timezone.utc)


def validate_cron(cron_expression: str) -> str:
    """Return the normalized expression or raise HTTP 400."""
    expr = " ".join((cron_expression or "").split())
    if len(expr.split(" ")) != 5 or not croniter.is_valid(expr):
        raise HTTPException(
            status_code=400,
            detail="Invalid schedule. Use a 5-field cron expression, e.g. '0 2 * * *' (daily at 02:00 UTC).",
        )
    first = next_run(expr)
    second = next_run(expr, first)
    if (second - first).total_seconds() < MIN_INTERVAL_SECONDS:
        raise HTTPException(status_code=400, detail="Schedules cannot run more often than every 15 minutes.")
    return expr

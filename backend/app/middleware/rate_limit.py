"""Token-bucket rate limiting middleware (in-memory, no Redis required)."""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


@dataclass
class TokenBucket:
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    @property
    def retry_after(self) -> int:
        if self.tokens >= 1:
            return 0
        return max(1, int((1 - self.tokens) / self.refill_rate) + 1)


# Path-specific limits: (capacity, requests_per_minute)
PATH_LIMITS: dict[str, tuple[float, float]] = {
    "/api/v1/auth/login": (5, 5),
    "/api/v1/auth/register": (3, 3),
}

AUTHENTICATED_LIMIT = (300, 300)   # 300 req/min — UI polls logs/stats frequently
UNAUTHENTICATED_LIMIT = (30, 30)   # 30 req/min


def _client_ip(request: Request, trusted_proxies: int) -> str:
    """Real client IP. Behind N trusted proxies, take the Nth X-Forwarded-For hop from the right."""
    if trusted_proxies > 0:
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(hops) >= trusted_proxies:
            return hops[-trusted_proxies]
    return request.client.host if request.client else "unknown"


def _bucket_key(client_ip: str, path: str, user_id: Optional[str]) -> str:
    for prefix, _ in PATH_LIMITS.items():
        if path.startswith(prefix):
            return f"path:{prefix}:{client_ip}"
    if user_id:
        return f"user:{user_id}"
    return f"ip:{client_ip}"


def _get_limits(path: str, user_id: Optional[str]) -> tuple[float, float]:
    for prefix, limits in PATH_LIMITS.items():
        if path.startswith(prefix):
            return limits
    return AUTHENTICATED_LIMIT if user_id else UNAUTHENTICATED_LIMIT


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:  # noqa: ANN001
        super().__init__(app)
        self._buckets: dict[str, TokenBucket] = defaultdict()

    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        # Skip rate limiting for health checks and WebSocket upgrades
        if request.url.path in ("/health", "/api/health"):
            return await call_next(request)
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        from app.core.config import settings

        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)

        client_ip = _client_ip(request, settings.TRUSTED_PROXY_COUNT)
        user_id = getattr(request.state, "user_id", None) if hasattr(request.state, "user_id") else None

        path = request.url.path
        key = _bucket_key(client_ip, path, user_id)
        capacity, rpm = _get_limits(path, user_id)
        refill_rate = rpm / 60.0  # convert per-minute to per-second

        if key not in self._buckets:
            self._buckets[key] = TokenBucket(capacity=capacity, refill_rate=refill_rate)

        bucket = self._buckets[key]

        if not bucket.consume():
            retry_after = bucket.retry_after
            # Build response with CORS headers so the browser doesn't mask
            # 429 as a CORS error when the origin is allowed.
            origin = request.headers.get("origin", "")
            resp_headers: dict[str, str] = {"Retry-After": str(retry_after)}
            if origin in settings.CORS_ORIGINS:
                resp_headers["Access-Control-Allow-Origin"] = origin
                resp_headers["Access-Control-Allow-Credentials"] = "true"
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please try again later.",
                    "retry_after": retry_after,
                },
                headers=resp_headers,
            )

        response = await call_next(request)

        # Prevent unbounded memory growth — purge stale buckets
        now = time.monotonic()
        if len(self._buckets) > 10000:
            expired = [k for k, v in self._buckets.items() if now - v.last_refill > 60]
            for k in expired:
                del self._buckets[k]

        return response

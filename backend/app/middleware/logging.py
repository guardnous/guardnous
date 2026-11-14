"""Request logging middleware — structured access log + DB persistence."""

import logging
import time

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.database import async_session
from app.models.app_log import AppLog

logger = logging.getLogger("guardnous.access")

SKIP_PATHS = frozenset({"/health", "/api/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico"})
SKIP_PREFIXES = ("/api/v1/logs/stream",)


def _categorize_path(path: str) -> str:
    p = path.lower()
    if "/auth/" in p or p.endswith("/auth"):
        return "AUTH"
    if "/scans" in p:
        return "SCAN"
    if "/reports" in p:
        return "REPORT"
    if "/integrations" in p or "/webhooks" in p:
        return "INTEGRATION"
    if "/settings" in p:
        return "SETTINGS"
    if "/agents" in p:
        return "AI"
    if "/iam" in p:
        return "IAM"
    if "/governance" in p:
        return "GOVERNANCE"
    if "/users" in p or "/roles" in p or "/groups" in p or "/tenants" in p:
        return "USER"
    if "/notifications" in p:
        return "NOTIFICATION"
    if "/audit" in p or "/logs" in p:
        return "SYSTEM"
    return "API"


def _describe_action(method: str, path: str, status: int) -> str:
    """Build a human-readable action description from the request."""
    p = path.lower()
    verb = {"GET": "Fetched", "POST": "Created", "PUT": "Updated", "PATCH": "Updated", "DELETE": "Deleted"}.get(method, method)
    status_label = "OK" if status < 400 else f"HTTP {status}"

    # Extract resource from path
    segments = [s for s in p.rstrip("/").split("/") if s and s != "api" and s != "v1"]
    if not segments:
        return f"{verb} / → {status_label}"

    resource = segments[-1]
    # If last segment looks like an ID (uuid or int), use the parent
    if len(segments) >= 2 and (len(resource) > 20 or resource.isdigit()):
        resource = segments[-2]

    resource = resource.replace("-", " ").replace("_", " ").title()
    return f"{verb} {resource} → {status_label}"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        path = request.url.path
        if path in SKIP_PATHS or any(path.startswith(p) for p in SKIP_PREFIXES):
            return await call_next(request)

        start = time.perf_counter()
        error_msg = None
        response: Response | None = None
        try:
            response = await call_next(request)
        except Exception as exc:
            error_msg = str(exc)
            raise
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            status_code = response.status_code if response else 500

            user_id = getattr(request.state, "user_id", None) if hasattr(request.state, "user_id") else None
            user_email = getattr(request.state, "user_email", None) if hasattr(request.state, "user_email") else None
            client_ip = request.client.host if request.client else "-"

            logger.info(
                "method=%s path=%s status=%d duration_ms=%.2f user=%s client=%s",
                request.method, path, status_code, duration_ms,
                user_email or user_id or "-",
                client_ip,
            )

            # Persist to DB — level mapping for visibility
            if status_code >= 500:
                level = "ERROR"
            elif status_code >= 400:
                level = "WARNING"
            elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
                level = "INFO"
            else:
                level = "VERBOSE"  # GET requests visible when log level is VERBOSE or lower

            # Build a descriptive message
            category = _categorize_path(path)
            action = _describe_action(request.method, path, status_code)
            msg = f"{action} ({duration_ms:.0f}ms)"
            if error_msg:
                msg += f" — Error: {error_msg}"
            if status_code == 401:
                msg += " — Unauthorized"
            elif status_code == 403:
                msg += " — Forbidden"
            elif status_code == 404:
                msg += " — Not Found"

            meta: dict = {}
            if error_msg:
                meta["error"] = error_msg
            if user_email:
                meta["user"] = user_email
            if client_ip and client_ip != "-":
                meta["ip"] = client_ip
            content_length = response.headers.get("content-length") if response else None
            if content_length:
                meta["response_bytes"] = int(content_length)

            # Skip DB logging for 429 rate-limit responses — they spam the log viewer
            if status_code != 429:
                try:
                    async with async_session() as db:
                        entry = AppLog(
                            level=level,
                            category=category,
                            message=msg,
                            source="middleware.request",
                            user_id=user_id,
                            user_email=user_email,
                            request_method=request.method,
                            request_path=path,
                            request_ip=client_ip if client_ip != "-" else None,
                            status_code=status_code,
                            duration_ms=int(duration_ms),
                            metadata_=meta if meta else {},
                        )
                        db.add(entry)
                        await db.commit()
                except Exception:
                    pass  # never break the request for a logging failure

        return response

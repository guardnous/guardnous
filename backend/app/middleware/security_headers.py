"""Security headers middleware — adds defensive HTTP headers to every response.

Skips OPTIONS (CORS preflight) so the CORSMiddleware response is not altered.
CSP connect-src is built dynamically from CORS_ORIGINS so cross-origin API
calls are not blocked by the browser.
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def _build_csp() -> str:
    """Build CSP that allows connect-src to configured CORS origins."""
    if settings.CORS_ALLOW_ALL:
        return "default-src 'self'; connect-src *"
    origins = " ".join(settings.CORS_ORIGINS) if settings.CORS_ORIGINS else ""
    connect_src = f"connect-src 'self' {origins}".strip()
    return f"default-src 'self'; {connect_src}"


# The interactive API docs (served outside production only, see app/main.py)
# load their script and stylesheet from a CDN and start with an inline script,
# which the default policy blocks. Only these two pages get the wider policy.
_API_DOCS_PATHS = frozenset({"/docs", "/redoc"})
_API_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "worker-src 'self' blob:"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        response: Response = await call_next(request)
        # Don't add security headers to CORS preflight — let CORSMiddleware own those.
        if request.method == "OPTIONS":
            return response
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        if request.url.path in _API_DOCS_PATHS:
            response.headers["Content-Security-Policy"] = _API_DOCS_CSP
        else:
            response.headers["Content-Security-Policy"] = _build_csp()
        return response

"""
Tenant isolation middleware — extracts organization_id from JWT or header
and injects it into request.state for all downstream endpoints.
"""
import logging
from typing import Optional

from fastapi import Request
from jose import JWTError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


logger = logging.getLogger(__name__)

# Paths that don't require tenant context
PUBLIC_PATHS = {
    "/api/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/setup/check",
    "/api/v1/setup/initialize",
}


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """Extract tenant_id and organization_id from the JWT and attach to request.state.

    This runs before any route handler, ensuring every endpoint can access
    ``request.state.tenant_id`` and ``request.state.organization_id``
    without repeating token-parsing logic.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Defaults — unauthenticated requests get None
        request.state.tenant_id = None
        request.state.organization_id = None
        request.state.user_id = None
        request.state.user_email = None

        # Skip public paths
        if request.url.path in PUBLIC_PATHS or request.url.path.startswith("/docs"):
            return await call_next(request)

        token = self._extract_token(request)
        claims = None
        if token:
            claims = self._decode_token(token)
            if claims:
                request.state.user_id = claims.get("sub")
                request.state.user_email = claims.get("email")
                request.state.tenant_id = claims.get("tenant_id")
                request.state.organization_id = claims.get("org_id")

                # Allow X-Organization-Id header override ONLY for admins
                header_org_id = request.headers.get("X-Organization-Id")
                if header_org_id:
                    try:
                        header_org = int(header_org_id)
                        user_role = claims.get("role", "")
                        # Only installation-level superusers may act on another org.
                        # "platform_admin" is the self-registered tenant owner and is tenant-scoped.
                        if user_role in ("admin", "superadmin"):
                            request.state.organization_id = header_org
                        # Non-admins: silently ignore the header (keep JWT org_id)
                    except (ValueError, TypeError):
                        pass

        return await call_next(request)

    @staticmethod
    def _extract_token(request: Request) -> Optional[str]:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    @staticmethod
    def _decode_token(token: str) -> Optional[dict]:
        from app.core.security import decode_access_token

        try:
            return decode_access_token(token)
        except JWTError:
            return None

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import async_session
from app.api.v1 import router as api_router
from app.api.admin import router as admin_router
from app.middleware import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    RequestLoggingMiddleware,
)

from app.core.seed import ensure_seed_data
from app.core.logging_config import setup_logging
from sqlalchemy import text
import logging

setup_logging(
    level="DEBUG" if settings.DEBUG else "INFO",
    json_output=not settings.DEBUG,  # human-readable in dev, JSON in prod
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Create or upgrade the schema (see app/core/migrations.py)
    import asyncio
    from app.core.migrations import bootstrap_schema
    await asyncio.to_thread(bootstrap_schema)

    # 2. Ensure seed data (idempotent)
    await ensure_seed_data()
    from app.services.sla import backfill_at_startup
    await backfill_at_startup()   # deadlines for findings written before SLA tracking; idempotent


    # 4. Log system startup
    try:
        from app.core.app_logger import app_log
        from app.core.database import async_session
        async with async_session() as db:
            await app_log.info(db, "SYSTEM", "GuardNous API server started", source="main.lifespan")
    except Exception:
        pass

    yield


# Interactive API docs and the OpenAPI schema are served everywhere except production.
_api_docs_enabled = settings.ENVIRONMENT.lower() != "production"

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="IaC Security Consolidation Platform - One dashboard for all your infrastructure security.",
    lifespan=lifespan,
    docs_url="/docs" if _api_docs_enabled else None,
    redoc_url="/redoc" if _api_docs_enabled else None,
    openapi_url="/openapi.json" if _api_docs_enabled else None,
)

# --- Middleware stack (order matters: last added = first executed) ---
# Starlette runs middleware in reverse-add order, so add CORS **last**
# to ensure it wraps everything and preflight/error responses always
# carry Access-Control-Allow-Origin headers.
#
# Desired EXECUTION order (outermost → innermost):
#   CORS → SecurityHeaders → TenantIsolation → RateLimit → RequestLogging → route
# TenantIsolation must execute BEFORE RateLimit and RequestLogging because it
# populates request.state.user_id, which both of those read. Since execution is
# reverse of add-order, TenantIsolation is added AFTER them here.

app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(RateLimitMiddleware)

# Tenant isolation — extracts tenant/org/user from JWT into request.state.
# Added after RateLimit/RequestLogging so it executes before them.
from app.middleware.tenant import TenantIsolationMiddleware
app.add_middleware(TenantIsolationMiddleware)

app.add_middleware(SecurityHeadersMiddleware)

# CORS — added last so it executes first (outermost wrapper).
# Companies self-hosting will set CORS_ORIGINS to their own domain(s),
# or CORS_ALLOW_ALL=true when behind a reverse proxy that handles origin checks.
_cors_origins = ["*"] if settings.CORS_ALLOW_ALL or "*" in settings.CORS_ORIGINS else settings.CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials="*" not in _cors_origins,  # credentials incompatible with wildcard
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After", "Content-Disposition"],
    max_age=600,
)

app.include_router(api_router)
app.include_router(admin_router)


# Public by design: cloud providers download these to verify tokens GuardNous signs.
# They contain the issuer address and public keys only.
@app.get("/.well-known/openid-configuration", include_in_schema=False)
async def oidc_discovery():
    from fastapi import HTTPException

    from app.services.federation import issuer

    try:
        return issuer.discovery()
    except issuer.FederationUnavailable as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/.well-known/jwks.json", include_in_schema=False)
async def oidc_jwks():
    from fastapi.concurrency import run_in_threadpool

    from app.services.federation import issuer

    return await run_in_threadpool(issuer.jwks)


@app.get("/health")
@app.get("/api/health")
async def health_check():
    db_status = "ok"
    redis_status = "ok"

    # Check DB connectivity
    try:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"

    # Check Redis connectivity
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
    except Exception:
        redis_status = "unavailable"

    overall = "healthy" if db_status == "ok" and redis_status == "ok" else "degraded"

    return {
        "status": overall,
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "db": db_status,
        "redis": redis_status,
    }

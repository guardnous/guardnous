from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.user import User
from app.services.cve.service import CVEService
from app.schemas.cve import CVEResponse, CVESearchResponse, CVESyncResponse, CVEStatsResponse

router = APIRouter()


@router.get("/stats", response_model=CVEStatsResponse)
async def get_cve_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get CVE database statistics."""
    service = CVEService(db)
    stats = await service.get_sync_stats()
    return CVEStatsResponse(
        total_cves=stats["total"],
        by_severity=stats["by_severity"],
        by_source=stats["by_source"],
        with_epss=stats["epss_enriched"],
        kev_flagged=stats.get("kev_flagged", 0),
        last_sync=stats.get("last_sync"),
    )


@router.get("", response_model=CVESearchResponse)
async def search_cves(
    query: str = None,
    severity: str = None,
    source: str = None,
    page: int = 1,
    page_size: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Search CVEs with optional severity and source filters."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    service = CVEService(db)
    cves, total = await service.search_cves(
        query=query, severity=severity, source=source, page=page, page_size=page_size
    )
    return CVESearchResponse(items=cves, total=total, page=page, page_size=page_size)


@router.get("/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    service = CVEService(db)
    cve = await service.get_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@router.post("/sync", response_model=CVESyncResponse)
async def sync_cves(
    keyword: str = None,
    days_back: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "manage")),
):
    """Trigger a CVE sync from NVD + GHSA with EPSS enrichment."""
    service = CVEService(db)
    result = await service.fetch_and_store_cves(keyword=keyword, days_back=days_back)
    return CVESyncResponse(
        status="success",
        total_stored=result["total_stored"],
        sources=result["sources"],
        epss_enriched=result.get("epss_enriched", 0),
        kev_flagged=result.get("kev_flagged", 0),
    )

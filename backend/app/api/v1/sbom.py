"""Software bill of materials (SBOM) of a repository assessment.

A repository scan stores the dependencies it parsed from package manifests.
From that inventory this module serves a CycloneDX 1.5 document, a summary for
the assessment page, and the licence check of the dependencies.
"""
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.core.config import settings
from app.core.database import get_db
from app.core.rbac import require_permission
from app.core.security import get_current_active_user
from app.models.sbom import ScanDependencyInventory
from app.models.scan import Scan
from app.models.user import User
from app.services.security import sbom_store
from app.services.security.dependency_analyzer import supported_manifest_types

router = APIRouter()

# SBOM export formats the platform can emit.
EXPORT_FORMATS = ["cyclonedx-1.5-json"]

CYCLONEDX_MEDIA_TYPE = "application/vnd.cyclonedx+json"

NO_INVENTORY_OLD_SCAN = (
    "This assessment was run before dependency inventories were stored. "
    "Run it again to export an SBOM."
)
NO_INVENTORY_QUICK_SCAN = (
    "A quick repository scan does not analyse dependencies. "
    "Run a full repository assessment to export an SBOM."
)
NO_INVENTORY_NOT_A_REPOSITORY = (
    "This assessment has no dependency inventory. "
    "An SBOM is available for repository assessments."
)

# Vulnerability intelligence sources cross-referenced during SBOM analysis.
INTEL_SOURCES = ["nvd", "ghsa", "epss", "cisa-kev"]


@router.get("/manifest-types")
async def list_manifest_types(current_user: User = Depends(get_current_active_user)):
    """List the distinct package-manifest types the analyzer can parse."""
    types = supported_manifest_types()
    return {
        "count": len(types),
        "manifest_types": types,
        "export_formats": EXPORT_FORMATS,
        "intel_sources": INTEL_SOURCES,
    }


async def _scan_inventory(db: AsyncSession, scan_id: int, user: User) -> tuple[Scan, ScanDependencyInventory]:
    """The caller's scan and its stored dependencies; other organizations' scans do not exist."""
    scan = (await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == user.organization_id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    inventory = await sbom_store.load_inventory(db, scan)
    if inventory is None:
        if scan.scan_type == "repository":
            raise HTTPException(status_code=409, detail=NO_INVENTORY_QUICK_SCAN)
        if scan.repository_name or scan.repository or scan.repository_url:
            raise HTTPException(status_code=409, detail=NO_INVENTORY_OLD_SCAN)
        raise HTTPException(status_code=404, detail=NO_INVENTORY_NOT_A_REPOSITORY)
    return scan, inventory


@router.get("/scans/{scan_id}")
async def export_scan_sbom(
    scan_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "export")),
):
    """Download the CycloneDX 1.5 SBOM of a repository assessment."""
    scan, inventory = await _scan_inventory(db, scan_id, current_user)
    sbom = await sbom_store.build_sbom(db, scan, inventory)
    await write_audit_log(
        db, action="sbom.export", resource_type="scan", resource_id=scan.id,
        details={"components": len(sbom["components"])}, user=current_user, request=request,
    )
    await db.commit()
    repo = re.sub(r"[^A-Za-z0-9._-]+", "-", sbom_store.repository_label(scan)).strip("-.") or "repository"
    return Response(
        content=json.dumps(sbom, indent=2),
        media_type=CYCLONEDX_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="sbom-{repo}-{scan.id}.cdx.json"'},
    )


@router.get("/scans/{scan_id}/summary")
async def scan_sbom_summary(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "read")),
):
    """Counts of the dependency inventory, known vulnerabilities and the licence check."""
    scan, inventory = await _scan_inventory(db, scan_id, current_user)
    return await sbom_store.build_summary(db, scan, inventory)


@router.post("/scans/{scan_id}/licenses/refresh")
async def refresh_scan_licenses(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("scans", "update")),
):
    """Look the licences of this assessment's dependencies up again, ignoring earlier results."""
    scan, inventory = await _scan_inventory(db, scan_id, current_user)
    if not settings.DEPENDENCY_LICENSE_LOOKUP:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Licence lookup is turned off. Set {sbom_store.LICENSE_SETTING}=true to allow it; "
                "package names and versions are then sent to deps.dev."
            ),
        )
    components = sbom_store.unique_components(sbom_store.dependencies_of(inventory))
    await sbom_store.ensure_licenses(db, inventory, components, force=True)
    return await sbom_store.build_summary(db, scan, inventory)

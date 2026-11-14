from fastapi import APIRouter
from app.api.admin import organizations, onboarding

router = APIRouter(prefix="/api/admin")
router.include_router(organizations.router, prefix="/organizations", tags=["Admin - Organizations"])
router.include_router(onboarding.router, prefix="/onboarding", tags=["Admin - Onboarding"])

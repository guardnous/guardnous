"""First-run onboarding status and completion API.

Tracks whether a user/org has completed the setup wizard so the frontend
can redirect new users to the guided onboarding flow.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.scan import Scan
from app.models.user import User
from app.services.agents.config import resolve_llm_settings
from app.services.agents.llm import LLMClient

router = APIRouter()


class OnboardingStep(BaseModel):
    key: str
    title: str
    description: str
    completed: bool


class OnboardingStatus(BaseModel):
    completed: bool
    steps: list[OnboardingStep]
    current_step: int
    total_steps: int


@router.get("/status", response_model=OnboardingStatus)
async def get_onboarding_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Check which onboarding steps the user/org has completed."""
    org_id = current_user.organization_id

    # Step 1: Profile set up (user exists with a name)
    profile_done = bool(current_user.full_name and current_user.full_name.strip())

    # Step 2: AI provider configured (not mock)
    try:
        llm_settings = await resolve_llm_settings(db, org_id)
        llm = LLMClient(llm_settings)
        ai_done = llm.is_live
    except Exception:
        ai_done = False

    # Step 3: First scan completed
    scan_count = (
        await db.execute(
            select(func.count(Scan.id)).where(Scan.organization_id == org_id)
        )
    ).scalar() or 0
    scan_done = scan_count > 0

    # Step 4: VCS integration connected
    from app.models.organization import Organization

    org_row = (
        await db.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    vcs_done = bool(org_row and org_row.vcs_type)

    steps = [
        OnboardingStep(
            key="profile",
            title="Set Up Your Profile",
            description="Tell us your name to personalize your experience.",
            completed=profile_done,
        ),
        OnboardingStep(
            key="ai_provider",
            title="Connect AI Provider",
            description="Power up the AI copilot with OpenAI, Anthropic, Azure, or Ollama.",
            completed=ai_done,
        ),
        OnboardingStep(
            key="first_scan",
            title="Run Your First Scan",
            description="Upload an IaC file to see GuardNous in action.",
            completed=scan_done,
        ),
        OnboardingStep(
            key="vcs_integration",
            title="Connect Version Control",
            description="Link GitHub, GitLab, or Bitbucket for continuous scanning.",
            completed=vcs_done,
        ),
    ]

    all_done = all(s.completed for s in steps)
    current = next((i for i, s in enumerate(steps) if not s.completed), len(steps))

    return OnboardingStatus(
        completed=all_done,
        steps=steps,
        current_step=current,
        total_steps=len(steps),
    )


class CompleteStepRequest(BaseModel):
    step: str
    data: dict | None = None


class CompleteStepResponse(BaseModel):
    success: bool
    message: str


@router.post("/complete-step", response_model=CompleteStepResponse)
async def complete_onboarding_step(
    req: CompleteStepRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "read")),
):
    """Mark an onboarding step as complete (e.g. update profile name)."""
    if req.step == "profile" and req.data:
        name = req.data.get("full_name", "").strip()
        if name:
            current_user.full_name = name
            db.add(current_user)
            await db.commit()
            return CompleteStepResponse(success=True, message="Profile updated")
        return CompleteStepResponse(success=False, message="Name is required")

    if req.step == "skip_all":
        # Mark onboarding as dismissed — store in localStorage on frontend
        return CompleteStepResponse(success=True, message="Onboarding skipped")

    return CompleteStepResponse(success=False, message=f"Unknown step: {req.step}")

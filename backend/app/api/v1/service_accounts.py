"""Service accounts API — manage bot identities that author automated remediation PRs.

A service account provides a consistent, auditable git author (name/email) and a
hashed access token for programmatic use. Tokens are returned exactly once at
creation/rotation and stored only as a sha256 hash (prefixed `gn_`).
"""
import hashlib
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.service_account import ServiceAccount
from app.models.user import User

router = APIRouter()


# ─── Schemas ────────────────────────────────────────────
class ServiceAccountCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = None
    bot_username: str = Field("guardnous-bot", max_length=120)
    bot_email: str = Field("bot@guardnous.local", max_length=255)


class ServiceAccountUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=120)
    description: Optional[str] = None
    bot_username: Optional[str] = Field(None, max_length=120)
    bot_email: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = None


class ServiceAccountOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    bot_username: str
    bot_email: str
    token_prefix: Optional[str]
    has_token: bool
    is_active: bool
    last_used_at: Optional[str]
    created_by: Optional[str]
    created_at: Optional[str]

    @classmethod
    def from_model(cls, sa: ServiceAccount) -> "ServiceAccountOut":
        return cls(
            id=sa.id,
            name=sa.name,
            description=sa.description,
            bot_username=sa.bot_username,
            bot_email=sa.bot_email,
            token_prefix=sa.token_prefix,
            has_token=bool(sa.token_hash),
            is_active=sa.is_active,
            last_used_at=sa.last_used_at.isoformat() if sa.last_used_at else None,
            created_by=sa.created_by,
            created_at=sa.created_at.isoformat() if sa.created_at else None,
        )


class ServiceAccountWithToken(ServiceAccountOut):
    token: str  # shown once


def _require_admin(user: User) -> None:
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Admin privileges required to manage service accounts")


def _new_token() -> tuple[str, str, str]:
    """Return (raw_token_with_prefix, token_hash, token_prefix)."""
    raw = secrets.token_urlsafe(48)
    token = f"gn_{raw}"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash, token[:12]


# ─── Routes ─────────────────────────────────────────────
@router.get("/service-accounts", response_model=list[ServiceAccountOut])
async def list_service_accounts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ServiceAccount)
        .where(ServiceAccount.organization_id == current_user.organization_id)
        .order_by(ServiceAccount.created_at.desc())
    )
    return [ServiceAccountOut.from_model(sa) for sa in result.scalars().all()]


@router.post("/service-accounts", response_model=ServiceAccountWithToken, status_code=201)
async def create_service_account(
    body: ServiceAccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    token, token_hash, token_prefix = _new_token()
    sa = ServiceAccount(
        organization_id=current_user.organization_id,
        name=body.name,
        description=body.description,
        bot_username=body.bot_username or "guardnous-bot",
        bot_email=body.bot_email or "bot@guardnous.local",
        token_hash=token_hash,
        token_prefix=token_prefix,
        is_active=True,
        created_by=current_user.email,
    )
    db.add(sa)
    await db.flush()
    await db.refresh(sa)

    out = ServiceAccountWithToken(**ServiceAccountOut.from_model(sa).model_dump(), token=token)
    return out


@router.patch("/service-accounts/{sa_id}", response_model=ServiceAccountOut)
async def update_service_account(
    sa_id: int,
    body: ServiceAccountUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    sa = await _get_owned(db, sa_id, current_user)

    for field in ("name", "description", "bot_username", "bot_email", "is_active"):
        val = getattr(body, field)
        if val is not None:
            setattr(sa, field, val)
    await db.flush()
    await db.refresh(sa)
    return ServiceAccountOut.from_model(sa)


@router.post("/service-accounts/{sa_id}/rotate", response_model=ServiceAccountWithToken)
async def rotate_token(
    sa_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    sa = await _get_owned(db, sa_id, current_user)

    token, token_hash, token_prefix = _new_token()
    sa.token_hash = token_hash
    sa.token_prefix = token_prefix
    await db.flush()
    await db.refresh(sa)

    out = ServiceAccountWithToken(**ServiceAccountOut.from_model(sa).model_dump(), token=token)
    return out


@router.delete("/service-accounts/{sa_id}", status_code=204)
async def delete_service_account(
    sa_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    sa = await _get_owned(db, sa_id, current_user)
    await db.delete(sa)
    await db.flush()
    return None


async def _get_owned(db: AsyncSession, sa_id: int, user: User) -> ServiceAccount:
    result = await db.execute(
        select(ServiceAccount).where(
            ServiceAccount.id == sa_id,
            ServiceAccount.organization_id == user.organization_id,
        )
    )
    sa = result.scalar_one_or_none()
    if not sa:
        raise HTTPException(status_code=404, detail="Service account not found")
    return sa

from datetime import datetime, timedelta, timezone
from typing import Optional
import json
import secrets
import io
import base64
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import pyotp
import qrcode
from app.core.config import settings
from app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

ACCESS_TOKEN_TYPE = "access"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="GuardNous")


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # ±30s tolerance


def generate_qr_base64(uri: str) -> str:
    qr = qrcode.make(uri, box_size=6, border=2)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def generate_backup_codes(count: int = 10) -> tuple[list[str], list[str]]:
    """Returns (plaintext_codes, hashed_codes)."""
    plain = [f"{secrets.randbelow(10**8):08d}" for _ in range(count)]
    hashed = [pwd_context.hash(c) for c in plain]
    return plain, hashed


def verify_backup_code(code: str, hashed_codes_json: str | None) -> tuple[bool, str | None]:
    """Check if a backup code is valid. Returns (valid, updated_json) with used code removed."""
    if not hashed_codes_json:
        return False, None
    hashed_codes: list[str] = json.loads(hashed_codes_json)
    for i, hc in enumerate(hashed_codes):
        if pwd_context.verify(code, hc):
            hashed_codes.pop(i)
            return True, json.dumps(hashed_codes)
    return False, None


def create_mfa_token(user_id: int) -> str:
    """Short-lived token (5 min) used between password verification and 2FA step."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    return jwt.encode(
        {"sub": str(user_id), "purpose": "mfa", "exp": expire},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def decode_mfa_token(token: str) -> int:
    """Returns user_id if valid, raises otherwise."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("purpose") != "mfa":
            raise ValueError("Not an MFA token")
        uid = payload.get("sub")
        if uid is None:
            raise ValueError("No sub")
        return int(uid)
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")


def create_email_verification_token(user_id: int) -> str:
    """24-hour token used for email address verification."""
    expire = datetime.now(timezone.utc) + timedelta(hours=24)
    return jwt.encode(
        {"sub": str(user_id), "purpose": "email_verify", "exp": expire},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def decode_email_verification_token(token: str) -> int:
    """Returns user_id if valid, raises otherwise."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("purpose") != "email_verify":
            raise ValueError("Not an email verification token")
        uid = payload.get("sub")
        if uid is None:
            raise ValueError("No sub")
        return int(uid)
    except (JWTError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid or expired verification link")


def create_password_reset_token(user_id: int) -> str:
    """1-hour token used for forgot-password flow."""
    expire = datetime.now(timezone.utc) + timedelta(hours=1)
    return jwt.encode(
        {"sub": str(user_id), "purpose": "password_reset", "exp": expire},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def decode_password_reset_token(token: str) -> int:
    """Returns user_id if valid, raises otherwise."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("purpose") != "password_reset":
            raise ValueError("Not a password reset token")
        uid = payload.get("sub")
        if uid is None:
            raise ValueError("No sub")
        return int(uid)
    except (JWTError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT with user, tenant, org, and role info."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": ACCESS_TOKEN_TYPE})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode a session token. Raises JWTError for anything that is not an access token.

    MFA, password-reset and email-verification tokens are signed with the same key,
    so the token type must be checked or they would work as session tokens.
    """
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    if payload.get("type") != ACCESS_TOKEN_TYPE or payload.get("purpose"):
        raise JWTError("Not an access token")
    if payload.get("sub") is None:
        raise JWTError("Missing subject")
    return payload


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    from app.models.user import User

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id: str = payload["sub"]
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception

    # Attach token-level org claims for quick access without extra DB round-trip
    token_org_id = payload.get("org_id")
    token_org_name = payload.get("org_name")
    if token_org_id is not None and user.organization_id is None:
        user.organization_id = token_org_id
    # Stash org_name from token (not a DB column) for downstream use
    user._token_org_name = token_org_name  # noqa: SLF001

    # Update last_login_at on each token validation
    if user.last_login_at is None or (
        datetime.now(timezone.utc) - user.last_login_at.replace(tzinfo=timezone.utc)
    ).seconds > 300:
        user.last_login_at = datetime.now(timezone.utc)
        await db.commit()

    return user


async def get_current_active_user(current_user=Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    if getattr(current_user, "status", "active") == "deactivated":
        raise HTTPException(status_code=403, detail="Account deactivated")
    return current_user

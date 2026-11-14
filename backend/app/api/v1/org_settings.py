"""Organization-level settings: general + notification + SMTP preferences."""
import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.core.rbac import require_permission
from app.core.audit import write_audit_log
from app.core.email import test_smtp_connection, send_email, build_test_email_html
from app.core.encryption import encrypt_token, decrypt_token
from app.core.app_logger import clear_log_level_cache, app_log
from app.models.user import User
from app.models.org_settings import OrgSettings

logger = logging.getLogger(__name__)
router = APIRouter()


class GeneralSettingsResponse(BaseModel):
    platform_name: str = "GuardNous"
    timezone: str = "UTC"
    date_format: str = "YYYY-MM-DD"
    session_timeout: int = 30
    dark_mode_default: str = "system"
    language: str = "en"
    data_retention_days: int = 90
    enforce_2fa: bool = False
    auto_remediation: bool = False
    risk_threshold: str = "high"
    scan_concurrency: int = 3
    log_level: str = "INFO"


class GeneralSettingsUpdate(BaseModel):
    platform_name: Optional[str] = None
    timezone: Optional[str] = None
    date_format: Optional[str] = None
    session_timeout: Optional[int] = Field(None, ge=5, le=480)
    dark_mode_default: Optional[str] = None
    language: Optional[str] = None
    data_retention_days: Optional[int] = Field(None, ge=7, le=3650)
    enforce_2fa: Optional[bool] = None
    auto_remediation: Optional[bool] = None
    risk_threshold: Optional[str] = None
    scan_concurrency: Optional[int] = Field(None, ge=1, le=20)
    log_level: Optional[str] = None


class NotificationPrefsResponse(BaseModel):
    email_enabled: bool = True
    email_critical: bool = True
    email_high: bool = True
    email_medium: bool = False
    email_low: bool = False
    email_digest: str = "daily"  # realtime | daily | weekly | off
    in_app_enabled: bool = True
    in_app_scans: bool = True
    in_app_findings: bool = True
    in_app_compliance: bool = True
    in_app_system: bool = True
    slack_webhook: str = ""
    slack_enabled: bool = False
    teams_webhook: str = ""
    teams_enabled: bool = False


class NotificationPrefsUpdate(BaseModel):
    email_enabled: Optional[bool] = None
    email_critical: Optional[bool] = None
    email_high: Optional[bool] = None
    email_medium: Optional[bool] = None
    email_low: Optional[bool] = None
    email_digest: Optional[str] = None
    in_app_enabled: Optional[bool] = None
    in_app_scans: Optional[bool] = None
    in_app_findings: Optional[bool] = None
    in_app_compliance: Optional[bool] = None
    in_app_system: Optional[bool] = None
    slack_webhook: Optional[str] = None
    slack_enabled: Optional[bool] = None
    teams_webhook: Optional[str] = None
    teams_enabled: Optional[bool] = None


async def _get_or_create(db: AsyncSession, org_id: int) -> OrgSettings:
    result = await db.execute(
        select(OrgSettings).where(OrgSettings.organization_id == org_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        row = OrgSettings(organization_id=org_id, notification_prefs={})
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


@router.get("/general", response_model=GeneralSettingsResponse)
async def get_general_settings(
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    # Open to every signed-in user: the UI shell needs the platform name and
    # date format. Nothing returned here is a secret.
    row = await _get_or_create(db, user.organization_id)
    return GeneralSettingsResponse(
        platform_name=row.platform_name or "GuardNous",
        timezone=row.timezone or "UTC",
        date_format=row.date_format or "YYYY-MM-DD",
        session_timeout=row.session_timeout or 30,
        dark_mode_default=row.dark_mode_default or "system",
        language=row.language or "en",
        data_retention_days=row.data_retention_days or 90,
        enforce_2fa=row.enforce_2fa or False,
        auto_remediation=row.auto_remediation or False,
        risk_threshold=row.risk_threshold or "high",
        scan_concurrency=row.scan_concurrency or 3,
        log_level=row.log_level or "INFO",
    )


@router.put("/general", response_model=GeneralSettingsResponse)
async def update_general_settings(
    body: GeneralSettingsUpdate,
    user: User = Depends(require_permission("settings", "update")),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_create(db, user.organization_id)
    updates = body.model_dump(exclude_none=True)
    for k, v in updates.items():
        setattr(row, k, v)
    await db.commit()
    await db.refresh(row)
    if "log_level" in updates:
        clear_log_level_cache(user.organization_id)
    await write_audit_log(db, action="update", resource_type="settings.general", user=user, details={"changed_fields": list(updates.keys())})
    await app_log.info(db, "SETTINGS", f"General settings updated: {list(updates.keys())}", user=user)
    return await get_general_settings(user=user, db=db)


@router.get("/notifications", response_model=NotificationPrefsResponse)
async def get_notification_prefs(
    # Holds the Slack and Teams webhook URLs, which are credentials.
    user: User = Depends(require_permission("settings", "read")),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_create(db, user.organization_id)
    prefs = row.notification_prefs or {}
    defaults = NotificationPrefsResponse()
    return NotificationPrefsResponse(**{k: prefs.get(k, getattr(defaults, k)) for k in defaults.model_fields})


@router.put("/notifications", response_model=NotificationPrefsResponse)
async def update_notification_prefs(
    body: NotificationPrefsUpdate,
    user: User = Depends(require_permission("settings", "update")),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_create(db, user.organization_id)
    prefs = dict(row.notification_prefs or {})
    updates = body.model_dump(exclude_none=True)
    prefs.update(updates)
    row.notification_prefs = prefs
    await db.commit()
    await db.refresh(row)
    await write_audit_log(db, action="update", resource_type="settings.notifications", user=user, details={"changed_fields": list(updates.keys())})
    return await get_notification_prefs(user=user, db=db)


# ─── SMTP Configuration ─────────────────────────────────────
class SmtpSettingsResponse(BaseModel):
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password_set: bool = False  # never return actual password
    smtp_from_email: str = ""
    smtp_from_name: str = "GuardNous"
    smtp_use_tls: bool = True


class SmtpSettingsUpdate(BaseModel):
    smtp_enabled: Optional[bool] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = Field(None, ge=1, le=65535)
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: Optional[str] = None
    smtp_from_name: Optional[str] = None
    smtp_use_tls: Optional[bool] = None


class SmtpTestRequest(BaseModel):
    recipient_email: str


@router.get("/smtp", response_model=SmtpSettingsResponse)
async def get_smtp_settings(
    user: User = Depends(require_permission("settings", "read")),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_create(db, user.organization_id)
    return SmtpSettingsResponse(
        smtp_enabled=row.smtp_enabled or False,
        smtp_host=row.smtp_host or "",
        smtp_port=row.smtp_port or 587,
        smtp_user=row.smtp_user or "",
        smtp_password_set=bool(row.smtp_password_encrypted),
        smtp_from_email=row.smtp_from_email or "",
        smtp_from_name=row.smtp_from_name or "GuardNous",
        smtp_use_tls=row.smtp_use_tls if row.smtp_use_tls is not None else True,
    )


@router.put("/smtp", response_model=SmtpSettingsResponse)
async def update_smtp_settings(
    body: SmtpSettingsUpdate,
    user: User = Depends(require_permission("settings", "update")),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_create(db, user.organization_id)
    updates = body.model_dump(exclude_none=True)
    # Encrypt SMTP password with Fernet before storing
    raw_password = updates.pop("smtp_password", None)
    if raw_password:
        row.smtp_password_encrypted = encrypt_token(raw_password)
    for k, v in updates.items():
        setattr(row, k, v)
    await db.commit()
    await db.refresh(row)
    await write_audit_log(db, action="update", resource_type="settings.smtp", user=user, details={"changed_fields": list(updates.keys()) + (["smtp_password"] if raw_password else [])})
    return await get_smtp_settings(user=user, db=db)


@router.post("/smtp/test")
async def test_smtp(
    body: SmtpTestRequest,
    user: User = Depends(require_permission("settings", "update")),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_create(db, user.organization_id)

    if not row.smtp_host or not row.smtp_port:
        raise HTTPException(status_code=400, detail="SMTP host and port must be configured first")

    # Decrypt password for use
    smtp_pass = ""
    if row.smtp_password_encrypted:
        try:
            smtp_pass = decrypt_token(row.smtp_password_encrypted)
        except Exception:
            return {"status": "error", "message": "Stored SMTP password could not be decrypted. Please re-save your SMTP password."}

    # Test connection
    result = await test_smtp_connection(
        smtp_host=row.smtp_host,
        smtp_port=row.smtp_port,
        smtp_user=row.smtp_user or "",
        smtp_password=smtp_pass,
        smtp_use_tls=row.smtp_use_tls if row.smtp_use_tls is not None else True,
    )

    if result["status"] != "ok":
        await app_log.error(db, "NOTIFICATION", f"SMTP connection test failed: {result.get('message', 'Unknown error')}", user=user, source="settings.smtp.test", metadata={"smtp_host": row.smtp_host, "smtp_port": row.smtp_port, "error": result.get("message")})
        return result

    # If connection succeeded, send test email
    try:
        platform_name = row.platform_name or "GuardNous"
        # Gmail/Outlook reject a From that differs from the authenticated user.
        _host_l = (row.smtp_host or "").lower()
        _from_email = row.smtp_from_email or row.smtp_user or "noreply@guardnous.io"
        if row.smtp_user and ("gmail" in _host_l or "googlemail" in _host_l):
            _from_email = row.smtp_user
        await send_email(
            smtp_host=row.smtp_host,
            smtp_port=row.smtp_port,
            smtp_user=row.smtp_user or "",
            smtp_password=smtp_pass,
            smtp_use_tls=row.smtp_use_tls if row.smtp_use_tls is not None else True,
            from_email=_from_email,
            from_name=row.smtp_from_name or platform_name,
            to_email=body.recipient_email,
            subject=f"[{platform_name}] SMTP Configuration Test",
            html_body=build_test_email_html(platform_name),
            text_body=f"SMTP configuration for {platform_name} is working correctly.",
        )
        await write_audit_log(db, action="create", resource_type="settings.smtp.test", user=user, details={"recipient": body.recipient_email, "status": "sent"})
        await app_log.info(db, "NOTIFICATION", f"SMTP test email sent successfully to {body.recipient_email}", user=user, source="settings.smtp.test", metadata={"recipient": body.recipient_email, "smtp_host": row.smtp_host, "smtp_port": row.smtp_port})
        return {"status": "ok", "message": f"Test email sent to {body.recipient_email}"}
    except Exception as e:
        import traceback as tb_mod
        tb_str = tb_mod.format_exc()
        await app_log.error(db, "NOTIFICATION", f"SMTP test email failed to {body.recipient_email}: {str(e)}", user=user, source="settings.smtp.test", metadata={"recipient": body.recipient_email, "smtp_host": row.smtp_host, "smtp_port": row.smtp_port, "error_type": type(e).__name__}, traceback=tb_str)
        return {"status": "error", "message": f"Connection OK but sending failed: {str(e)}"}


# ─── Setup Wizard ────────────────────────────────────────────

class SetupStatusResponse(BaseModel):
    setup_completed: bool = False


class CompleteSetupRequest(BaseModel):
    """All-in-one payload for the first-login setup wizard."""
    # Step 1 — Platform Identity
    platform_name: str = "GuardNous"
    timezone: str = "UTC"
    date_format: str = "YYYY-MM-DD"
    language: str = "en"
    # Step 2 — AI Provider (optional — saved to agents config)
    ai_provider: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None
    # Step 3 — Notifications
    email_digest: str = "daily"
    email_critical: bool = True
    email_high: bool = True
    email_medium: bool = False
    # Step 4 — SMTP (optional)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: Optional[str] = None
    smtp_from_name: Optional[str] = None
    smtp_use_tls: bool = True


@router.get("/setup-status", response_model=SetupStatusResponse)
async def get_setup_status(
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_create(db, user.organization_id)
    return SetupStatusResponse(setup_completed=bool(row.setup_completed))


@router.post("/complete-setup")
async def complete_setup(
    body: CompleteSetupRequest,
    # Replaces the AI provider, its key and the SMTP relay in one call.
    user: User = Depends(require_permission("settings", "manage")),
    db: AsyncSession = Depends(get_db),
):
    """Save all wizard settings in one shot and mark setup as complete."""
    row = await _get_or_create(db, user.organization_id)

    # Step 1 — General / Platform Identity
    row.platform_name = body.platform_name
    row.timezone = body.timezone
    row.date_format = body.date_format
    row.language = body.language

    # Step 2 — AI Provider config (stored in llm_configs table)
    if body.ai_provider and body.ai_api_key:
        from app.models.llm_config import LLMConfig
        ai_row = await db.execute(
            select(LLMConfig).where(LLMConfig.organization_id == user.organization_id)
        )
        ai_cfg = ai_row.scalar_one_or_none()
        if not ai_cfg:
            ai_cfg = LLMConfig(organization_id=user.organization_id)
            db.add(ai_cfg)
        ai_cfg.provider = body.ai_provider
        ai_cfg.api_key_encrypted = encrypt_token(body.ai_api_key)
        if body.ai_model:
            ai_cfg.model = body.ai_model
        if body.ai_base_url:
            ai_cfg.base_url = body.ai_base_url
        ai_cfg.enabled = True

    # Step 3 — Notification preferences
    prefs = dict(row.notification_prefs or {})
    prefs["email_digest"] = body.email_digest
    prefs["email_critical"] = body.email_critical
    prefs["email_high"] = body.email_high
    prefs["email_medium"] = body.email_medium
    prefs["email_enabled"] = True
    prefs["in_app_enabled"] = True
    row.notification_prefs = prefs

    # Step 4 — SMTP (optional)
    if body.smtp_host:
        row.smtp_enabled = True
        row.smtp_host = body.smtp_host
        row.smtp_port = body.smtp_port
        row.smtp_user = body.smtp_user or ""
        if body.smtp_password:
            row.smtp_password_encrypted = encrypt_token(body.smtp_password)
        row.smtp_from_email = body.smtp_from_email or ""
        row.smtp_from_name = body.smtp_from_name or body.platform_name
        row.smtp_use_tls = body.smtp_use_tls

    # Mark setup as complete
    row.setup_completed = True
    await db.commit()
    await db.refresh(row)

    await write_audit_log(db, action="create", resource_type="settings.setup_wizard", user=user, details={"platform_name": body.platform_name, "ai_provider": body.ai_provider})
    await app_log.info(db, "SETTINGS", "Initial setup wizard completed", user=user)

    return {"status": "ok", "message": "Setup completed successfully"}

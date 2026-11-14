"""User management API — invite, bulk import, status, CRUD for organization users."""
import logging
import secrets
import csv
import io
from datetime import datetime, timedelta, timezone
from typing import List

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from app.core.database import get_db
from app.core.security import get_password_hash, create_email_verification_token
from app.core.rbac import (
    require_permission, ensure_can_grant_role, ensure_can_invite_as, ensure_tenant_access, sync_user_role,
)
from app.core.audit import write_audit_log
from app.core.tenant import check_plan_limit
from app.core.app_logger import app_log
from app.core.config import settings
from app.core.email import send_invitation_email
from app.models.user import User
from app.models.tenant import Tenant
from app.models.invitation import UserInvitation
from app.models.rbac import Role, UserRole
from app.models.user_organization import UserOrganization
from app.schemas.enterprise import (
    UserInvite, BulkUserInvite, UserManagementResponse,
    UserStatusUpdate, InvitationResponse, InvitationAccept,
)

router = APIRouter()


@router.get("/", response_model=List[UserManagementResponse])
async def list_users(
    user=Depends(require_permission("users", "read")),
    db: AsyncSession = Depends(get_db),
):
    """List users scoped to the current user's organization.

    Super-admins see all users; regular users see only their org's members.
    """
    q = select(User).order_by(User.created_at.desc())
    if user.role in ("admin", "superadmin"):
        pass  # super-admins see everything
    elif user.organization_id:
        q = q.where(User.organization_id == user.organization_id)
    elif user.tenant_id:
        q = q.where(User.tenant_id == user.tenant_id)
    result = await db.execute(q)
    users = list(result.scalars().all())

    # Append pending invitations as synthetic user entries so the
    # "Pending Invitations" tab in the admin UI can display them.
    inv_q = select(UserInvitation).where(UserInvitation.status == "pending")
    if user.organization_id:
        inv_q = inv_q.where(UserInvitation.organization_id == user.organization_id)
    elif user.tenant_id:
        inv_q = inv_q.where(UserInvitation.tenant_id == user.tenant_id)
    inv_result = await db.execute(inv_q)
    for inv in inv_result.scalars().all():
        users.append(UserManagementResponse(
            id=inv.id,
            email=inv.email,
            full_name=None,
            role=inv.role_slug or "viewer",
            status="invited",
            is_active=False,
            tenant_id=inv.tenant_id,
            organization_id=inv.organization_id,
            last_login_at=None,
            created_at=inv.created_at,
        ))

    return users


@router.get("/{user_id}", response_model=UserManagementResponse)
async def get_user(
    user_id: int,
    user=Depends(require_permission("users", "read")),
    db: AsyncSession = Depends(get_db),
):
    """Get user detail — org-scoped. Only visible if same organization (or super-admin)."""
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role not in ("admin", "superadmin"):
        if target.organization_id != user.organization_id:
            raise HTTPException(status_code=403, detail="Access denied")
    return target


class UserRoleUpdate(BaseModel):
    role: str


@router.put("/{user_id}/role")
async def update_user_role(
    user_id: int,
    body: UserRoleUpdate,
    request: Request,
    user=Depends(require_permission("users", "update")),
    db: AsyncSession = Depends(get_db),
):
    """Change a user's role within the org. Only org admins / platform admins."""
    if user.role not in ("admin", "superadmin", "platform_admin", "org_admin"):
        raise HTTPException(403, "Only admins can change user roles")
    if user_id == user.id:
        raise HTTPException(400, "Cannot change your own role")

    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, "User not found")
    if user.role not in ("admin", "superadmin"):
        if target.organization_id != user.organization_id:
            raise HTTPException(403, "User is not in your organization")

    old_role = target.role
    ensure_can_grant_role(user, body.role, target_current_role=old_role)
    await sync_user_role(db, target, body.role, assigned_by=user)
    await write_audit_log(
        db, action="update", resource_type="user", resource_id=user_id,
        details={"field": "role", "old": old_role, "new": body.role, "email": target.email},
        user=user, request=request,
    )
    await app_log.info(
        db, "USER",
        f"User role changed: {target.email} {old_role} → {body.role}",
        user=user, source="users.role",
        metadata={"target_email": target.email, "old_role": old_role, "new_role": body.role},
    )
    await db.commit()
    return {"status": "updated", "user_id": user_id, "new_role": body.role}


@router.post("/invite", response_model=InvitationResponse, status_code=201)
async def invite_user(
    data: UserInvite,
    request: Request,
    user=Depends(require_permission("users", "create")),
    db: AsyncSession = Depends(get_db),
):
    # Check organization-level user limit (plan enforcement)
    if user.organization_id:
        await check_plan_limit(db, user.organization_id, User, "max_users")

    # Check if already invited / registered (scoped to same organization)
    existing = await db.execute(
        select(User).where(
            User.email == data.email,
            User.organization_id == user.organization_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "User already registered in this organization")

    existing_invite = await db.execute(
        select(UserInvitation).where(
            UserInvitation.email == data.email,
            UserInvitation.organization_id == user.organization_id,
            UserInvitation.status == "pending",
        )
    )
    if existing_invite.scalar_one_or_none():
        raise HTTPException(400, "Invitation already pending for this email")

    # Resolve role slug for display
    role_slug = None
    if data.role_id:
        r = await db.execute(select(Role).where(Role.id == data.role_id))
        role = r.scalar_one_or_none()
        role_slug = role.slug if role else None
        if role and not role.is_system:
            ensure_tenant_access(user, role.tenant_id)
    ensure_can_invite_as(user, role_slug)

    invitation = UserInvitation(
        tenant_id=user.tenant_id,
        organization_id=data.organization_id or user.organization_id,
        email=data.email,
        role_slug=role_slug or "viewer",
        invited_by_id=user.id,
        token=secrets.token_urlsafe(48),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        source="manual",
    )
    db.add(invitation)
    await db.flush()
    await write_audit_log(
        db, action="create", resource_type="invitation", resource_id=invitation.id,
        details={"email": data.email, "role": role_slug or "viewer"},
        user=user, request=request,
    )
    await app_log.info(db, "USER", f"User invited: {data.email} with role '{role_slug or 'viewer'}'", user=user, source="users.invite", metadata={"invited_email": data.email, "role": role_slug or "viewer"})
    await db.commit()
    await db.refresh(invitation)

    # Build invite URL and attempt to send email
    invite_url = f"{settings.FRONTEND_URL}/invite/{invitation.token}"
    inviter_name = user.full_name or user.email

    # Get org name for the email
    org_name = ""
    if user.organization_id:
        from app.models.organization import Organization
        org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = org_result.scalar_one_or_none()
        if org:
            org_name = org.name or ""

    # Load SMTP config from organization_settings DB table (user-configured via UI)
    smtp_config = None
    try:
        from app.models.org_settings import OrgSettings
        from app.core.encryption import decrypt_token
        org_id = user.organization_id or user.tenant_id
        smtp_row = await db.execute(
            select(OrgSettings).where(OrgSettings.organization_id == org_id)
        )
        smtp_row = smtp_row.scalar_one_or_none()
        if smtp_row and smtp_row.smtp_host:
            smtp_pass = ""
            if smtp_row.smtp_password_encrypted:
                try:
                    smtp_pass = decrypt_token(smtp_row.smtp_password_encrypted)
                except Exception:
                    logger.warning("SMTP password decrypt failed — user should re-save password")
            smtp_config = {
                "host": smtp_row.smtp_host,
                "port": smtp_row.smtp_port or 587,
                "user": smtp_row.smtp_user or "",
                "password": smtp_pass,
                "use_tls": smtp_row.smtp_use_tls if smtp_row.smtp_use_tls is not None else True,
                "from_email": smtp_row.smtp_from_email or "",
                "from_name": smtp_row.smtp_from_name or "GuardNous",
            }
    except Exception as exc:
        logger.warning("Failed to load SMTP config from DB: %s", exc)

    email_result = await send_invitation_email(
        to_email=data.email,
        invite_url=invite_url,
        inviter_name=inviter_name,
        role=role_slug or "viewer",
        org_name=org_name,
        smtp_config=smtp_config,
    )

    resp = InvitationResponse.model_validate(invitation)
    resp.invite_url = invite_url
    resp.email_sent = email_result.get("status") == "ok"
    if email_result.get("status") != "ok":
        resp.email_error = email_result.get("message")
    return resp


@router.post("/invite/resend/{invitation_id}")
async def resend_invitation(
    invitation_id: int,
    request: Request,
    user=Depends(require_permission("users", "create")),
    db: AsyncSession = Depends(get_db),
):
    inv = await db.get(UserInvitation, invitation_id)
    if not inv or inv.organization_id != user.organization_id:
        raise HTTPException(404, "Invitation not found")
    if inv.status != "pending":
        raise HTTPException(400, f"Invitation is {inv.status}, cannot resend")

    # Regenerate token and extend expiry
    inv.token = secrets.token_urlsafe(48)
    inv.expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    invite_url = f"{settings.FRONTEND_URL}/invite/{inv.token}"
    inviter_name = user.full_name or user.email

    org_name = ""
    if user.organization_id:
        from app.models.organization import Organization
        org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = org_result.scalar_one_or_none()
        if org:
            org_name = org.name or ""

    smtp_config = None
    try:
        from app.models.org_settings import OrgSettings
        from app.core.encryption import decrypt_token
        org_id = user.organization_id or user.tenant_id
        smtp_row = await db.execute(
            select(OrgSettings).where(OrgSettings.organization_id == org_id)
        )
        smtp_row = smtp_row.scalar_one_or_none()
        if smtp_row and smtp_row.smtp_host:
            smtp_pass = ""
            if smtp_row.smtp_password_encrypted:
                try:
                    smtp_pass = decrypt_token(smtp_row.smtp_password_encrypted)
                except Exception:
                    logger.warning("SMTP password decrypt failed — user should re-save password")
            smtp_config = {
                "host": smtp_row.smtp_host,
                "port": smtp_row.smtp_port or 587,
                "user": smtp_row.smtp_user or "",
                "password": smtp_pass,
                "use_tls": smtp_row.smtp_use_tls if smtp_row.smtp_use_tls is not None else True,
                "from_email": smtp_row.smtp_from_email or "",
                "from_name": smtp_row.smtp_from_name or "GuardNous",
            }
    except Exception as exc:
        logger.warning("Failed to load SMTP config for resend: %s", exc)

    email_result = await send_invitation_email(
        to_email=inv.email,
        invite_url=invite_url,
        inviter_name=inviter_name,
        role=inv.role_slug or "viewer",
        org_name=org_name,
        smtp_config=smtp_config,
    )

    await db.commit()
    return {
        "status": "resent",
        "email": inv.email,
        "invite_url": invite_url,
        "email_sent": email_result.get("status") == "ok",
        "email_error": email_result.get("message") if email_result.get("status") != "ok" else None,
    }


@router.post("/invite/bulk", status_code=201)
async def bulk_invite(
    data: BulkUserInvite,
    user=Depends(require_permission("users", "create")),
    db: AsyncSession = Depends(get_db),
):
    results = {"invited": 0, "skipped": 0, "emails_sent": 0, "errors": []}
    inviter_name = user.full_name or user.email

    # Resolve org name once
    org_name = ""
    if user.organization_id:
        from app.models.organization import Organization
        org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = org_result.scalar_one_or_none()
        if org:
            org_name = org.name or ""

    pending_emails = []
    for invite in data.users:
        try:
            existing = await db.execute(select(User).where(User.email == invite.email))
            if existing.scalar_one_or_none():
                results["skipped"] += 1
                results["errors"].append(f"{invite.email}: already registered")
                continue

            role_slug = None
            if invite.role_id:
                r = await db.execute(select(Role).where(Role.id == invite.role_id))
                role = r.scalar_one_or_none()
                role_slug = role.slug if role else None
                if role and not role.is_system:
                    ensure_tenant_access(user, role.tenant_id)
            ensure_can_invite_as(user, role_slug)

            invitation = UserInvitation(
                tenant_id=user.tenant_id,
                organization_id=invite.organization_id or user.organization_id,
                email=invite.email,
                role_slug=role_slug or "viewer",
                invited_by_id=user.id,
                token=secrets.token_urlsafe(48),
                expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                source=data.source,
            )
            db.add(invitation)
            await db.flush()
            invite_url = f"{settings.FRONTEND_URL}/invite/{invitation.token}"
            pending_emails.append((invite.email, invite_url, role_slug or "viewer"))
            results["invited"] += 1
        except Exception as e:
            results["errors"].append(f"{invite.email}: {str(e)}")
    await db.commit()

    # Send invitation emails (non-blocking — don't fail the request if email fails)
    for email, invite_url, role in pending_emails:
        try:
            email_result = await send_invitation_email(
                to_email=email, invite_url=invite_url,
                inviter_name=inviter_name, role=role, org_name=org_name,
            )
            if email_result.get("status") == "ok":
                results["emails_sent"] += 1
        except Exception:
            pass  # Email failure is non-fatal for bulk ops

    return results


@router.post("/invite/csv", status_code=201)
async def bulk_invite_csv(
    file: UploadFile = File(...),
    user=Depends(require_permission("users", "create")),
    db: AsyncSession = Depends(get_db),
):
    """Import users from CSV. Expected columns: email, full_name, role (optional)."""
    content = await file.read()
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    results = {"invited": 0, "skipped": 0, "emails_sent": 0, "errors": []}
    inviter_name = user.full_name or user.email

    org_name = ""
    if user.organization_id:
        from app.models.organization import Organization
        org_result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = org_result.scalar_one_or_none()
        if org:
            org_name = org.name or ""

    pending_emails = []
    for row in reader:
        email = row.get("email", "").strip()
        if not email:
            continue
        existing = await db.execute(select(User).where(User.email == email))
        if existing.scalar_one_or_none():
            results["skipped"] += 1
            continue
        role_slug = row.get("role", "viewer").strip() or "viewer"
        ensure_can_invite_as(user, role_slug)
        invitation = UserInvitation(
            tenant_id=user.tenant_id,
            organization_id=user.organization_id,
            email=email,
            role_slug=role_slug,
            invited_by_id=user.id,
            token=secrets.token_urlsafe(48),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            source="csv_import",
        )
        db.add(invitation)
        await db.flush()
        invite_url = f"{settings.FRONTEND_URL}/invite/{invitation.token}"
        pending_emails.append((email, invite_url, role_slug))
        results["invited"] += 1
    await db.commit()

    for email, invite_url, role in pending_emails:
        try:
            email_result = await send_invitation_email(
                to_email=email, invite_url=invite_url,
                inviter_name=inviter_name, role=role, org_name=org_name,
            )
            if email_result.get("status") == "ok":
                results["emails_sent"] += 1
        except Exception:
            pass

    return results


@router.get("/invite/template")
async def download_csv_template():
    """Download sample CSV template for bulk user import."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["email", "full_name", "role"])
    writer.writerow(["john.doe@example.com", "John Doe", "security_engineer"])
    writer.writerow(["jane.smith@example.com", "Jane Smith", "devops_engineer"])
    writer.writerow(["bob.wilson@example.com", "Bob Wilson", "viewer"])
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=guardnous_user_import_template.csv"},
    )


@router.get("/invite/{token}")
async def get_invitation(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """Validate an invitation token and return details (no auth required)."""
    result = await db.execute(
        select(UserInvitation).where(UserInvitation.token == token)
    )
    invitation = result.scalar_one_or_none()
    if not invitation:
        raise HTTPException(404, "Invitation not found")
    if invitation.status != "pending":
        raise HTTPException(400, f"Invitation already {invitation.status}")
    if invitation.expires_at < datetime.now(timezone.utc):
        invitation.status = "expired"
        await db.commit()
        raise HTTPException(400, "Invitation has expired")

    # Get tenant and org names for display
    tenant_name = None
    org_name = None
    if invitation.tenant_id:
        t = await db.execute(select(Tenant).where(Tenant.id == invitation.tenant_id))
        tenant = t.scalar_one_or_none()
        tenant_name = tenant.name if tenant else None
    if invitation.organization_id:
        from app.models.organization import Organization
        o = await db.execute(select(Organization).where(Organization.id == invitation.organization_id))
        org = o.scalar_one_or_none()
        org_name = org.name if org else None

    return {
        "email": invitation.email,
        "full_name": invitation.full_name,
        "role": invitation.role_slug,
        "tenant_name": tenant_name,
        "organization_name": org_name,
        "expires_at": invitation.expires_at.isoformat(),
    }


@router.post("/invite/accept")
async def accept_invitation(
    data: InvitationAccept,
    db: AsyncSession = Depends(get_db),
):
    """Accept an invitation and create the user account."""
    result = await db.execute(
        select(UserInvitation).where(
            UserInvitation.token == data.token,
            UserInvitation.status == "pending",
        )
    )
    invitation = result.scalar_one_or_none()
    if not invitation:
        raise HTTPException(400, "Invalid or expired invitation")
    if invitation.expires_at < datetime.now(timezone.utc):
        invitation.status = "expired"
        await db.commit()
        raise HTTPException(400, "Invitation has expired")

    # Create user
    new_user = User(
        email=invitation.email,
        hashed_password=get_password_hash(data.password),
        full_name=data.full_name or invitation.email.split("@")[0],
        role=invitation.role_slug or "viewer",
        organization_id=invitation.organization_id,
        tenant_id=invitation.tenant_id,
        status="active",
        invited_by_id=invitation.invited_by_id,
    )
    db.add(new_user)
    await db.flush()

    # Add user→org membership in junction table
    if new_user.organization_id:
        db.add(UserOrganization(
            user_id=new_user.id,
            organization_id=new_user.organization_id,
            role_in_org=invitation.role_slug or "member",
            added_by=invitation.invited_by_id,
        ))

    # Assign role
    role_result = await db.execute(select(Role).where(Role.slug == invitation.role_slug))
    role = role_result.scalar_one_or_none()
    if role:
        db.add(UserRole(
            user_id=new_user.id, role_id=role.id,
            tenant_id=invitation.tenant_id,
            organization_id=invitation.organization_id,
        ))

    invitation.status = "accepted"
    invitation.accepted_at = datetime.now(timezone.utc)
    await db.commit()

    # Send account-created + email verification email (fire-and-forget)
    try:
        from app.core.email import send_account_created_email
        from app.core.config import settings

        # Get org name for the email
        org_name = "your organization"
        if invitation.organization_id:
            from app.models.organization import Organization
            org_result = await db.execute(select(Organization).where(Organization.id == invitation.organization_id))
            org = org_result.scalar_one_or_none()
            if org:
                org_name = org.name

        verify_token = create_email_verification_token(new_user.id)
        verify_url = f"{settings.FRONTEND_URL}/verify-email?token={verify_token}"

        await send_account_created_email(
            to_email=new_user.email,
            user_name=new_user.full_name or new_user.email.split("@")[0],
            org_name=org_name,
            role=invitation.role_slug or "viewer",
            verify_url=verify_url,
        )
    except Exception as e:
        logger.warning("Account-created email failed for %s: %s", new_user.email, e)

    return {"status": "accepted", "user_id": new_user.id}


@router.patch("/{user_id}/status")
async def update_user_status(
    user_id: int,
    data: UserStatusUpdate,
    request: Request,
    user=Depends(require_permission("users", "update")),
    db: AsyncSession = Depends(get_db),
):
    if user_id == user.id and data.status in ("deactivated", "suspended"):
        raise HTTPException(400, "Cannot deactivate your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        # The ID might be an invitation ID (invited users shown with invitation ID)
        inv = await db.get(UserInvitation, user_id)
        if inv:
            ensure_tenant_access(user, inv.tenant_id)
            if data.status in ("deactivated", "revoked"):
                if inv.status == "revoked":
                    return {"status": "updated", "user_status": "revoked"}
                inv.status = "revoked"
                await write_audit_log(
                    db, action="revoke", resource_type="invitation", resource_id=user_id,
                    details={"email": inv.email}, user=user, request=request,
                )
                await app_log.info(db, "USER", f"Invitation revoked: {inv.email}", user=user, source="users.status", metadata={"email": inv.email})
                await db.commit()
                return {"status": "updated", "user_status": "revoked"}
            raise HTTPException(400, f"Cannot change invitation to status '{data.status}'")
        raise HTTPException(404, "User not found")
    if user.role not in ("admin", "superadmin"):
        if target.organization_id != user.organization_id:
            raise HTTPException(403, "Cannot modify users outside your organization")

    target.status = data.status
    target.is_active = data.status == "active"
    await write_audit_log(
        db, action="update", resource_type="user", resource_id=user_id,
        details={"new_status": data.status, "target_email": target.email},
        user=user, request=request,
    )
    await app_log.info(db, "USER", f"User status changed: {target.email} → {data.status}", user=user, source="users.status", metadata={"target_email": target.email, "new_status": data.status, "target_user_id": user_id})
    await db.commit()
    return {"status": "updated", "user_status": data.status}


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    confirm_email: str = Query(..., description="Type the user's email to confirm deletion"),
    request: Request = None,
    user=Depends(require_permission("users", "delete")),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete a deactivated user. Requires typing the user's email to confirm."""
    if user_id == user.id:
        raise HTTPException(400, "Cannot delete your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()

    if not target:
        # Check if it's an invitation
        inv = await db.get(UserInvitation, user_id)
        if inv:
            ensure_tenant_access(user, inv.tenant_id)
            if confirm_email.lower() != inv.email.lower():
                raise HTTPException(400, "Confirmation email does not match")
            await db.delete(inv)
            await write_audit_log(
                db, action="delete", resource_type="invitation", resource_id=user_id,
                details={"email": inv.email}, user=user, request=request,
            )
            await app_log.info(db, "USER", f"Invitation permanently deleted: {inv.email}", user=user, source="users.delete")
            await db.commit()
            return {"status": "deleted", "message": f"Invitation for {inv.email} permanently deleted"}
        raise HTTPException(404, "User not found")

    if user.role not in ("admin", "superadmin"):
        if target.organization_id != user.organization_id:
            raise HTTPException(403, "Cannot delete users outside your organization")

    if target.is_active or target.status == "active":
        raise HTTPException(400, "Cannot delete an active user. Deactivate the user first.")

    if confirm_email.lower() != target.email.lower():
        raise HTTPException(400, "Confirmation email does not match")

    target_email = target.email

    # Clean up related records before deleting user
    # Tables with user_id FK
    for tbl in ["user_roles", "user_organizations", "group_members", "notifications",
                "agent_conversations", "agent_audit_entries"]:
        await db.execute(text(f"DELETE FROM {tbl} WHERE user_id = :uid"), {"uid": user_id})
    # Tables with created_by FK
    for tbl in ["report_schedules", "scan_schedules"]:
        await db.execute(text(f"DELETE FROM {tbl} WHERE created_by = :uid"), {"uid": user_id})
    # Nullify FK references where user is referenced as "added_by" / "assigned_by" / "invited_by"
    await db.execute(text("UPDATE group_members SET added_by_id = NULL WHERE added_by_id = :uid"), {"uid": user_id})
    await db.execute(text("UPDATE user_roles SET assigned_by_id = NULL WHERE assigned_by_id = :uid"), {"uid": user_id})
    await db.execute(text("UPDATE user_organizations SET added_by = NULL WHERE added_by = :uid"), {"uid": user_id})
    await db.execute(text("UPDATE user_invitations SET invited_by_id = NULL WHERE invited_by_id = :uid"), {"uid": user_id})
    await db.execute(text("UPDATE users SET invited_by_id = NULL WHERE invited_by_id = :uid"), {"uid": user_id})
    await db.execute(text("UPDATE audit_logs SET user_id = NULL WHERE user_id = :uid"), {"uid": user_id})

    await db.delete(target)
    await write_audit_log(
        db, action="delete", resource_type="user", resource_id=user_id,
        details={"email": target_email, "was_status": target.status},
        user=user, request=request,
    )
    await app_log.info(db, "USER", f"User permanently deleted: {target_email}", user=user, source="users.delete")
    await db.commit()
    return {"status": "deleted", "message": f"User {target_email} permanently deleted"}

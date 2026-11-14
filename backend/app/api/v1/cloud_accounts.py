"""Cloud Accounts API — CRUD for connecting cloud provider accounts."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.rbac import ensure_permission, require_permission
from app.services.cloud_connectors.base import sdk_missing
from app.models.user import User
from app.models.cloud_account import CloudAccount
from app.models.cloud_resource import CloudResource
from app.core.encryption import encrypt_token, decrypt_token

logger = logging.getLogger(__name__)

# Cloud credentials are sensitive: every route needs at least integrations:read,
# and the mutating routes check their own permission on top.
router = APIRouter(dependencies=[Depends(require_permission("integrations", "read"))])

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CloudAccountCreate(BaseModel):
    provider: str = Field(..., pattern="^(aws|azure|gcp)$")
    name: str = Field(..., min_length=1, max_length=255)
    account_identifier: str = Field(..., min_length=1, max_length=255)
    credentials: dict = Field(..., description="Provider-specific credentials (encrypted at rest)")
    regions: list[str] = Field(default_factory=list)
    sync_interval_hours: int = Field(default=6, ge=1, le=168)
    resource_types_filter: list[str] = Field(default_factory=list)


class CloudAccountUpdate(BaseModel):
    name: Optional[str] = None
    regions: Optional[list[str]] = None
    sync_enabled: Optional[bool] = None
    sync_interval_hours: Optional[int] = Field(default=None, ge=1, le=168)
    resource_types_filter: Optional[list[str]] = None
    credentials: Optional[dict] = None  # re-encrypt if provided


class CloudAccountOut(BaseModel):
    id: int
    provider: str
    name: str
    account_identifier: str
    status: str
    last_error: Optional[str] = None
    last_synced_at: Optional[str] = None
    resources_count: int
    sync_enabled: bool
    sync_interval_hours: int
    resource_types_filter: list
    regions: list
    created_at: str
    updated_at: str
    has_credentials: bool = False

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Provider credential schemas (for UI validation guidance)
# ---------------------------------------------------------------------------

PROVIDER_CREDENTIAL_SCHEMAS = {
    "aws": {
        "fields": [
            {"key": "role_arn", "label": "IAM Role ARN", "type": "text", "required": True,
             "placeholder": "arn:aws:iam::123456789012:role/GuardNousReadOnly",
             "help": "Cross-account IAM role with SecurityAudit + ViewOnlyAccess policies"},
            {"key": "external_id", "label": "External ID", "type": "text", "required": False,
             "placeholder": "guardnous-external-id",
             "help": "Optional external ID for additional security on AssumeRole"},
            {"key": "access_key_id", "label": "Access Key ID", "type": "text", "required": False,
             "placeholder": "AKIAIOSFODNN7EXAMPLE",
             "help": "Alternative: static access key (less secure than AssumeRole)"},
            {"key": "secret_access_key", "label": "Secret Access Key", "type": "password", "required": False,
             "placeholder": "",
             "help": "Required if using static access key"},
        ],
        "auth_methods": ["assume_role", "access_key"],
        "instructions": (
            "Create an IAM Role in your AWS account with the following policies:\n"
            "• SecurityAudit (AWS managed)\n"
            "• ViewOnlyAccess (AWS managed)\n\n"
            "Set the trust policy to allow GuardNous to assume the role."
        ),
    },
    "azure": {
        "fields": [
            {"key": "tenant_id", "label": "Tenant ID", "type": "text", "required": True,
             "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
            {"key": "client_id", "label": "Application (Client) ID", "type": "text", "required": True,
             "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True,
             "placeholder": ""},
            {"key": "subscription_id", "label": "Subscription ID", "type": "text", "required": True,
             "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
             "help": "Azure subscription to scan"},
        ],
        "auth_methods": ["service_principal"],
        "instructions": (
            "Create an App Registration in Azure AD:\n"
            "1. Register a new application in Azure AD\n"
            "2. Create a client secret\n"
            "3. Assign the 'Reader' role on the target subscription"
        ),
    },
    "gcp": {
        "fields": [
            {"key": "project_id", "label": "Project ID", "type": "text", "required": True,
             "placeholder": "my-project-123456"},
            {"key": "service_account_json", "label": "Service Account Key (JSON)", "type": "textarea", "required": True,
             "placeholder": '{"type": "service_account", ...}',
             "help": "Paste the full JSON key file contents"},
        ],
        "auth_methods": ["service_account"],
        "instructions": (
            "Create a Service Account in your GCP project:\n"
            "1. Go to IAM & Admin → Service Accounts\n"
            "2. Create a service account with 'Viewer' role\n"
            "3. Create and download a JSON key"
        ),
    },
}


def _validate_credentials(provider: str, creds: dict) -> list[str]:
    """Validate that required credential fields are present."""
    schema = PROVIDER_CREDENTIAL_SCHEMAS.get(provider)
    if not schema:
        return [f"Unknown provider: {provider}"]
    errors = []
    required_fields = [f for f in schema["fields"] if f["required"]]

    if provider == "aws":
        # Either role_arn OR (access_key_id + secret_access_key)
        has_role = bool(creds.get("role_arn"))
        has_keys = bool(creds.get("access_key_id") and creds.get("secret_access_key"))
        if not has_role and not has_keys:
            errors.append("Provide either 'role_arn' (recommended) or both 'access_key_id' and 'secret_access_key'")
    else:
        for f in required_fields:
            if not creds.get(f["key"]):
                errors.append(f"Missing required field: {f['label']}")
    return errors


def _row_to_out(row: CloudAccount) -> dict:
    return {
        "id": row.id,
        "provider": row.provider,
        "name": row.name,
        "account_identifier": row.account_identifier,
        "status": row.status or "pending",
        "last_error": row.last_error,
        "last_synced_at": row.last_synced_at.isoformat() if row.last_synced_at else None,
        "resources_count": row.resources_count or 0,
        "sync_enabled": row.sync_enabled if row.sync_enabled is not None else True,
        "sync_interval_hours": row.sync_interval_hours or 6,
        "resource_types_filter": row.resource_types_filter or [],
        "regions": row.regions or [],
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
        "has_credentials": bool(row.credentials_encrypted),
        "keyless": _is_keyless(row),
    }


def _is_keyless(row: CloudAccount) -> bool:
    """True when the connection stores no secret (OIDC federation)."""
    try:
        return json.loads(decrypt_token(row.credentials_encrypted)).get("auth") == "oidc"
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/credential-schema/{provider}")
async def get_credential_schema(provider: str, user: User = Depends(get_current_user)):
    """Return the credential field schema for a given cloud provider."""
    schema = PROVIDER_CREDENTIAL_SCHEMAS.get(provider)
    if not schema:
        raise HTTPException(404, f"Unknown provider: {provider}")
    return schema


@router.get("")
async def list_cloud_accounts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    provider: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List all connected cloud accounts for the user's org."""
    q = select(CloudAccount).where(CloudAccount.organization_id == user.organization_id)
    if provider:
        q = q.where(CloudAccount.provider == provider)
    if status:
        q = q.where(CloudAccount.status == status)
    q = q.order_by(CloudAccount.created_at.desc())
    rows = (await db.execute(q)).scalars().all()
    return {"accounts": [_row_to_out(r) for r in rows], "total": len(rows)}


@router.get("/{account_id}")
async def get_cloud_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get a single cloud account."""
    row = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == user.organization_id,
        )
    )).scalars().first()
    if not row:
        raise HTTPException(404, "Cloud account not found")
    return _row_to_out(row)


class CredentialTest(BaseModel):
    provider: str = Field(..., pattern="^(aws|azure|gcp)$")
    credentials: dict


@router.post("/test-credentials")
async def test_credentials(
    body: CredentialTest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Validate credentials against the provider without saving them."""
    await ensure_permission(user, db, "integrations", "create")
    errors = _validate_credentials(body.provider, body.credentials)
    if errors:
        raise HTTPException(422, detail="; ".join(errors))
    return await _test_provider_connection(body.provider, body.credentials)


@router.post("", status_code=201)
async def create_cloud_account(
    body: CloudAccountCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Connect a new cloud account."""
    await ensure_permission(user, db, "integrations", "create")
    # Validate credentials
    errors = _validate_credentials(body.provider, body.credentials)
    if errors:
        raise HTTPException(422, detail="; ".join(errors))

    # Encrypt credentials
    creds_json = json.dumps(body.credentials)
    encrypted = encrypt_token(creds_json)

    acct = CloudAccount(
        organization_id=user.organization_id,
        provider=body.provider,
        name=body.name,
        account_identifier=body.account_identifier,
        credentials_encrypted=encrypted,
        status="pending",
        sync_enabled=True,
        sync_interval_hours=body.sync_interval_hours,
        regions=body.regions,
        resource_types_filter=body.resource_types_filter,
        created_by=user.id,
    )
    db.add(acct)
    await db.flush()
    acct_id = acct.id
    await db.commit()

    # Refresh to get server defaults
    result = (await db.execute(
        select(CloudAccount).where(CloudAccount.id == acct_id)
    )).scalars().first()

    return _row_to_out(result)


# ---------------------------------------------------------------------------
# AWS without access keys (OIDC federation)
# ---------------------------------------------------------------------------

class AwsFederatedCreate(BaseModel):
    account_id: str = Field(..., pattern=r"^\d{12}$", description="12-digit AWS account ID")
    name: Optional[str] = Field(None, max_length=255)
    allow_fixes: bool = False
    regions: list[str] = []


def _federated_creds(row: CloudAccount) -> Optional[dict]:
    try:
        creds = json.loads(decrypt_token(row.credentials_encrypted)) if row.credentials_encrypted else {}
    except Exception:  # noqa: BLE001
        return None
    return creds if creds.get("auth") == "oidc" else None


@router.get("/aws/federation")
async def aws_federation_status(user: User = Depends(get_current_user)):
    """Whether AWS accounts can be connected without access keys on this installation."""
    from app.services.federation import issuer

    try:
        return {"available": True, "issuer": issuer.issuer_url(), "reason": None}
    except issuer.FederationUnavailable as exc:
        return {"available": False, "issuer": None, "reason": str(exc)}


@router.get("/aws/federation/template")
async def aws_generic_template(user: User = Depends(get_current_user)):
    """The generic onboarding template (everything as parameters), for hosting in S3
    so that AWS_ONBOARDING_TEMPLATE_URL can offer a one-click link."""
    from fastapi.responses import PlainTextResponse

    from app.services.federation import aws as aws_federation

    return PlainTextResponse(aws_federation.template(), media_type="application/x-yaml", headers={
        "Content-Disposition": 'attachment; filename="guardnous-access.yaml"',
    })


@router.post("/aws/federated", status_code=201)
async def connect_aws_federated(
    body: AwsFederatedCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Start connecting an AWS account without access keys.

    Returns the account (pending) and what to deploy in AWS. Nothing secret is
    created or stored: the saved connection is a role ARN and a subject.
    """
    from fastapi.concurrency import run_in_threadpool

    from app.services.federation import aws as aws_federation
    from app.services.federation import issuer

    await ensure_permission(user, db, "integrations", "create")
    existing = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.organization_id == user.organization_id, CloudAccount.provider == "aws",
            CloudAccount.account_identifier == body.account_id,
        )
    )).scalars().first()
    if existing:
        raise HTTPException(409, f"AWS account {body.account_id} is already connected as '{existing.name}'.")
    try:
        creds = aws_federation.new_connection(user.organization_id, body.account_id)
        await run_in_threadpool(issuer.jwks)          # make sure the signing key exists before anyone trusts it
    except issuer.FederationUnavailable as exc:
        raise HTTPException(409, str(exc))
    creds["allow_fixes"] = body.allow_fixes

    acct = CloudAccount(
        organization_id=user.organization_id, provider="aws", name=body.name or f"AWS {body.account_id}",
        account_identifier=body.account_id, credentials_encrypted=encrypt_token(json.dumps(creds)),
        status="pending", sync_enabled=True, regions=body.regions, created_by=user.id,
    )
    db.add(acct)
    await db.commit()
    await db.refresh(acct)
    return {
        "account": _row_to_out(acct),
        "setup": aws_federation.setup_instructions(creds, body.account_id, allow_fixes=body.allow_fixes),
    }


async def _federated_account(db: AsyncSession, user: User, account_id: int) -> tuple[CloudAccount, dict]:
    row = (await db.execute(
        select(CloudAccount).where(CloudAccount.id == account_id, CloudAccount.organization_id == user.organization_id)
    )).scalars().first()
    creds = _federated_creds(row) if row else None
    if not row or creds is None:
        raise HTTPException(404, "No keyless AWS connection with this ID")
    return row, creds


@router.get("/{account_id}/aws-setup")
async def aws_federated_setup(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The deployment instructions again, for a connection that is still pending."""
    from app.services.federation import aws as aws_federation

    row, creds = await _federated_account(db, user, account_id)
    return aws_federation.setup_instructions(creds, row.account_identifier, allow_fixes=bool(creds.get("allow_fixes")))


@router.get("/{account_id}/aws-template")
async def aws_federated_template(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The CloudFormation template for this connection, ready to deploy as it is."""
    from fastapi.responses import PlainTextResponse

    from app.services.federation import aws as aws_federation

    row, creds = await _federated_account(db, user, account_id)
    body = aws_federation.template(
        issuer_host=creds["issuer"].removeprefix("https://"), subject=creds["subject"], role_name=creds["role_name"],
        allow_fixes=bool(creds.get("allow_fixes")),
    )
    filename = f"guardnous-aws-{row.account_identifier}.yaml"
    return PlainTextResponse(body, media_type="application/x-yaml", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
    })


@router.patch("/{account_id}")
async def update_cloud_account(
    account_id: int,
    body: CloudAccountUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update cloud account settings."""
    await ensure_permission(user, db, "integrations", "update")
    row = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == user.organization_id,
        )
    )).scalars().first()
    if not row:
        raise HTTPException(404, "Cloud account not found")

    if body.name is not None:
        row.name = body.name
    if body.regions is not None:
        row.regions = body.regions
    if body.sync_enabled is not None:
        row.sync_enabled = body.sync_enabled
    if body.sync_interval_hours is not None:
        row.sync_interval_hours = body.sync_interval_hours
    if body.resource_types_filter is not None:
        row.resource_types_filter = body.resource_types_filter
    if body.credentials is not None:
        errors = _validate_credentials(row.provider, body.credentials)
        if errors:
            raise HTTPException(422, detail="; ".join(errors))
        row.credentials_encrypted = encrypt_token(json.dumps(body.credentials))
        row.status = "pending"  # re-validate on next sync

    row.updated_at = datetime.now(timezone.utc)
    await db.commit()

    result = (await db.execute(
        select(CloudAccount).where(CloudAccount.id == account_id)
    )).scalars().first()
    return _row_to_out(result)


@router.delete("/{account_id}", status_code=204)
async def delete_cloud_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Delete a cloud account and all its discovered resources."""
    await ensure_permission(user, db, "integrations", "delete")
    row = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == user.organization_id,
        )
    )).scalars().first()
    if not row:
        raise HTTPException(404, "Cloud account not found")

    # Delete associated cloud resources
    await db.execute(
        delete(CloudResource).where(
            CloudResource.organization_id == user.organization_id,
            CloudResource.account_id == row.account_identifier,
            CloudResource.provider == row.provider,
        )
    )

    await db.delete(row)
    await db.commit()


@router.post("/{account_id}/test")
async def test_cloud_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Test connectivity to a cloud account (validates credentials)."""
    row = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == user.organization_id,
        )
    )).scalars().first()
    if not row:
        raise HTTPException(404, "Cloud account not found")

    if not row.credentials_encrypted:
        raise HTTPException(400, "No credentials stored for this account")

    try:
        creds = json.loads(decrypt_token(row.credentials_encrypted))
    except Exception:
        row.status = "error"
        row.last_error = "Failed to decrypt credentials — encryption key may have changed"
        await db.commit()
        raise HTTPException(500, "Credential decryption failed")

    # Provider-specific connectivity test
    test_result = await _test_provider_connection(row.provider, creds)

    row.status = test_result["status"]
    row.last_error = test_result.get("error")
    if test_result["status"] == "connected":
        row.last_synced_at = datetime.now(timezone.utc)
    await db.commit()

    return test_result


@router.post("/{account_id}/sync")
async def trigger_sync(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Manually trigger resource discovery for a cloud account."""
    await ensure_permission(user, db, "integrations", "update")
    row = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == user.organization_id,
        )
    )).scalars().first()
    if not row:
        raise HTTPException(404, "Cloud account not found")

    if not row.credentials_encrypted:
        raise HTTPException(400, "No credentials configured")

    from app.tasks.cloud_sync import sync_cloud_account
    task = sync_cloud_account.delay(row.id)
    return {
        "status": "queued",
        "message": f"Resource discovery queued for {row.name} ({row.provider})",
        "account_id": account_id,
        "task_id": task.id,
    }


@router.get("/{account_id}/resources")
async def list_account_resources(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    resource_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    """List discovered resources for a specific cloud account."""
    acct = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == user.organization_id,
        )
    )).scalars().first()
    if not acct:
        raise HTTPException(404, "Cloud account not found")

    q = select(CloudResource).where(
        CloudResource.organization_id == user.organization_id,
        CloudResource.provider == acct.provider,
        CloudResource.account_id == acct.account_identifier,
    )
    if resource_type:
        q = q.where(CloudResource.resource_type == resource_type)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    q = q.order_by(CloudResource.last_synced.desc()).limit(limit).offset(offset)
    rows = (await db.execute(q)).scalars().all()

    return {
        "resources": [
            {
                "id": r.id,
                "provider": r.provider,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "resource_name": r.resource_name,
                "region": r.region,
                "status": r.status,
                "source": r.source,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_synced": r.last_synced.isoformat() if r.last_synced else None,
                "tags": r.tags or {},
            }
            for r in rows
        ],
        "total": total,
    }


# ---------------------------------------------------------------------------
# Provider connection testers
# ---------------------------------------------------------------------------

async def _test_provider_connection(provider: str, creds: dict) -> dict:
    """Test connectivity to a cloud provider. Returns status dict."""
    if provider == "aws":
        return await _test_aws(creds)
    elif provider == "azure":
        return await _test_azure(creds)
    elif provider == "gcp":
        return await _test_gcp(creds)
    return {"status": "error", "error": f"Unknown provider: {provider}"}


async def _test_aws(creds: dict) -> dict:
    """Test AWS connectivity via STS GetCallerIdentity."""
    try:
        import boto3

        if creds.get("auth") == "oidc":
            from fastapi.concurrency import run_in_threadpool

            from app.services.federation.aws import assume_role

            session = await run_in_threadpool(assume_role, creds)
            identity = await run_in_threadpool(session.client("sts").get_caller_identity)
        elif creds.get("role_arn"):
            sts = boto3.client("sts")
            assume_kwargs: dict[str, Any] = {
                "RoleArn": creds["role_arn"],
                "RoleSessionName": "guardnous-test",
            }
            if creds.get("external_id"):
                assume_kwargs["ExternalId"] = creds["external_id"]
            resp = sts.assume_role(**assume_kwargs)
            temp = resp["Credentials"]
            test_sts = boto3.client(
                "sts",
                aws_access_key_id=temp["AccessKeyId"],
                aws_secret_access_key=temp["SecretAccessKey"],
                aws_session_token=temp["SessionToken"],
            )
            identity = test_sts.get_caller_identity()
        else:
            sts = boto3.client(
                "sts",
                aws_access_key_id=creds.get("access_key_id"),
                aws_secret_access_key=creds.get("secret_access_key"),
            )
            identity = sts.get_caller_identity()

        return {
            "status": "connected",
            "details": {
                "account": identity.get("Account"),
                "arn": identity.get("Arn"),
                "user_id": identity.get("UserId"),
            },
        }
    except ImportError:
        return {"status": "error", "error": str(sdk_missing("AWS"))}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def _test_azure(creds: dict) -> dict:
    """Test Azure connectivity via token acquisition."""
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import ResourceManagementClient

        credential = ClientSecretCredential(
            tenant_id=creds["tenant_id"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )
        client = ResourceManagementClient(credential, creds["subscription_id"])
        # List first resource group to verify access
        rgs = list(client.resource_groups.list())
        return {
            "status": "connected",
            "details": {
                "subscription_id": creds["subscription_id"],
                "resource_groups_found": len(rgs),
            },
        }
    except ImportError:
        return {"status": "error", "error": str(sdk_missing("Azure"))}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def _test_gcp(creds: dict) -> dict:
    """Test GCP connectivity via listing projects."""
    try:
        import json as _json
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        sa_info = _json.loads(creds["service_account_json"]) if isinstance(creds["service_account_json"], str) else creds["service_account_json"]
        credentials = service_account.Credentials.from_service_account_info(
            sa_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        service = build("cloudresourcemanager", "v1", credentials=credentials)
        result = service.projects().list().execute()
        return {
            "status": "connected",
            "details": {
                "project_id": creds.get("project_id"),
                "projects_visible": len(result.get("projects", [])),
            },
        }
    except ImportError:
        return {"status": "error", "error": str(sdk_missing("GCP"))}
    except Exception as e:
        return {"status": "error", "error": str(e)}

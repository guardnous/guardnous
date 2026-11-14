"""Fixing a cloud posture finding in the cloud account itself.

Only a few findings can be fixed this way: the ones where the fix is a single,
well-understood setting that can be put back exactly as it was.

The sequence is always:

1. :func:`plan` reads the resource's **live** state and works out the change.
   Nothing is written. The plan is what a person approves.
2. :func:`apply` reads the live state again. If it differs from the plan, the
   change is refused. Otherwise it is made, read back to confirm, and recorded
   as a :class:`CloudChange` together with the previous state.
3. :func:`rollback` puts the previous state back.

The connected credentials must be allowed to make the change. Accounts are
usually connected read-only, in which case AWS refuses and the error says so.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudAccount
from app.models.cloud_resource import CloudChange, CloudResource
from app.models.finding import Finding
from app.services.cloud_posture.engine import DETECTED_BY

logger = logging.getLogger(__name__)

WORLD_V4, WORLD_V6 = "0.0.0.0/0", "::/0"
_BLOCK_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


class RemediationError(Exception):
    """The change cannot be planned or made; the message says why."""


def _code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "") or type(exc).__name__


def _explain(exc: Exception, doing: str) -> RemediationError:
    code = _code(exc)
    if "AccessDenied" in code or "UnauthorizedOperation" in code:
        return RemediationError(
            f"AWS refused to {doing} ({code}). The credentials connected for this account do not allow it; "
            "they are probably read-only. Grant the permission or make the change by hand."
        )
    return RemediationError(f"AWS could not {doing}: {code}")


# ── actions ─────────────────────────────────────────────────────────
# read(session, target) -> state; fix(state) -> wanted state or None if nothing to do;
# apply / revert make the call. States are plain JSON.

class BlockBucketPublicAccess:
    name = "Block public access on the S3 bucket"
    warning = "Anything this bucket serves publicly on purpose (a website, public downloads) will stop being reachable."

    def target(self, finding: Finding, resource: Optional[CloudResource]) -> dict:
        return {"bucket": finding.resource_name}

    def read(self, session, t: dict) -> Any:
        try:
            cfg = session.client("s3").get_public_access_block(Bucket=t["bucket"])["PublicAccessBlockConfiguration"]
        except Exception as exc:  # noqa: BLE001
            if _code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise
        return {k: bool(cfg.get(k)) for k in _BLOCK_KEYS}

    def fix(self, state: Any) -> Any:
        wanted = dict.fromkeys(_BLOCK_KEYS, True)
        return None if state == wanted else wanted

    def apply(self, session, t: dict, before: Any, after: Any) -> None:
        session.client("s3").put_public_access_block(Bucket=t["bucket"], PublicAccessBlockConfiguration=after)

    def revert(self, session, t: dict, before: Any, after: Any) -> None:
        s3 = session.client("s3")
        if before is None:
            s3.delete_public_access_block(Bucket=t["bucket"])
        else:
            s3.put_public_access_block(Bucket=t["bucket"], PublicAccessBlockConfiguration=before)

    def describe(self, before: Any, after: Any) -> str:
        was = "not set" if before is None else ", ".join(f"{k}={'on' if v else 'off'}" for k, v in before.items())
        return f"Now: {was}\nAfter: all four Block Public Access settings on"


class RevokeWorldIngress:
    """Remove the security group rules that open one port to the whole internet."""

    def __init__(self, port: int, label: str):
        self.port, self.label = port, label
        self.name = f"Remove internet access to {label} (port {port}) from the security group"
        self.warning = (
            f"Anyone who reaches {label} on resources in this group from outside your network will lose access. "
            "Make sure another way in exists (VPN, bastion, Session Manager)."
        )

    def target(self, finding: Finding, resource: Optional[CloudResource]) -> dict:
        group_id = (resource.config or {}).get("group_id") if resource else None
        if not group_id:
            raise RemediationError("The security group's ID is not in the synced inventory. Sync the account and try again.")
        return {"group_id": group_id, "region": (finding.metadata_ or {}).get("region")}

    def _covers(self, perm: dict) -> bool:
        proto = str(perm.get("IpProtocol"))
        if proto == "-1":
            return True
        return proto in ("tcp", "6") and perm.get("FromPort") is not None and perm["FromPort"] <= self.port <= perm.get("ToPort", -1)

    def read(self, session, t: dict) -> Any:
        ec2 = session.client("ec2", region_name=t["region"])
        group = ec2.describe_security_groups(GroupIds=[t["group_id"]])["SecurityGroups"][0]
        rules = []
        for perm in group.get("IpPermissions", []):
            if not self._covers(perm):
                continue
            v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == WORLD_V4]
            v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == WORLD_V6]
            if not (v4 or v6):
                continue
            rule: dict = {"IpProtocol": perm["IpProtocol"]}
            if perm.get("FromPort") is not None:
                rule["FromPort"], rule["ToPort"] = perm["FromPort"], perm["ToPort"]
            if v4:
                rule["IpRanges"] = [{k: r[k] for k in ("CidrIp", "Description") if r.get(k)} for r in v4]
            if v6:
                rule["Ipv6Ranges"] = [{k: r[k] for k in ("CidrIpv6", "Description") if r.get(k)} for r in v6]
            rules.append(rule)
        return sorted(rules, key=lambda r: json.dumps(r, sort_keys=True))

    def fix(self, state: Any) -> Any:
        return [] if state else None

    def apply(self, session, t: dict, before: Any, after: Any) -> None:
        session.client("ec2", region_name=t["region"]).revoke_security_group_ingress(GroupId=t["group_id"], IpPermissions=before)

    def revert(self, session, t: dict, before: Any, after: Any) -> None:
        session.client("ec2", region_name=t["region"]).authorize_security_group_ingress(GroupId=t["group_id"], IpPermissions=before)

    def describe(self, before: Any, after: Any) -> str:
        lines = ["Rules that will be removed:"]
        for rule in before:
            sources = [r["CidrIp"] for r in rule.get("IpRanges", [])] + [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
            if str(rule["IpProtocol"]) == "-1":
                ports = "ALL ports and protocols"
            elif rule["FromPort"] == rule["ToPort"]:
                ports = f"tcp port {rule['FromPort']}"
            else:
                ports = f"tcp ports {rule['FromPort']}-{rule['ToPort']} (the whole range, not only {self.port})"
            lines.append(f"  - {ports} from {', '.join(sources)}")
        lines.append("Rules for other sources and ports are not touched.")
        return "\n".join(lines)


class EnableEbsDefaultEncryption:
    name = "Turn on EBS encryption by default for the region"
    warning = "Only new volumes are affected. Existing unencrypted volumes stay as they are."

    def target(self, finding: Finding, resource: Optional[CloudResource]) -> dict:
        return {"region": (finding.metadata_ or {}).get("region")}

    def read(self, session, t: dict) -> Any:
        return bool(session.client("ec2", region_name=t["region"]).get_ebs_encryption_by_default()["EbsEncryptionByDefault"])

    def fix(self, state: Any) -> Any:
        return None if state else True

    def apply(self, session, t: dict, before: Any, after: Any) -> None:
        session.client("ec2", region_name=t["region"]).enable_ebs_encryption_by_default()

    def revert(self, session, t: dict, before: Any, after: Any) -> None:
        session.client("ec2", region_name=t["region"]).disable_ebs_encryption_by_default()

    def describe(self, before: Any, after: Any) -> str:
        return "Now: off\nAfter: on"


class EnableKmsRotation:
    name = "Turn on automatic rotation for the KMS key"
    warning = "Rotation adds new key material yearly. Old data stays readable; nothing needs re-encrypting."

    def target(self, finding: Finding, resource: Optional[CloudResource]) -> dict:
        return {"key_id": finding.resource_name, "region": (finding.metadata_ or {}).get("region")}

    def read(self, session, t: dict) -> Any:
        return bool(session.client("kms", region_name=t["region"]).get_key_rotation_status(KeyId=t["key_id"])["KeyRotationEnabled"])

    def fix(self, state: Any) -> Any:
        return None if state else True

    def apply(self, session, t: dict, before: Any, after: Any) -> None:
        session.client("kms", region_name=t["region"]).enable_key_rotation(KeyId=t["key_id"])

    def revert(self, session, t: dict, before: Any, after: Any) -> None:
        session.client("kms", region_name=t["region"]).disable_key_rotation(KeyId=t["key_id"])

    def describe(self, before: Any, after: Any) -> str:
        return "Now: off\nAfter: on"


ACTIONS = {
    "GN-AWS-S3-001": BlockBucketPublicAccess(),
    "GN-AWS-SG-001": RevokeWorldIngress(22, "SSH"),
    "GN-AWS-SG-002": RevokeWorldIngress(3389, "RDP"),
    "GN-AWS-REGION-001": EnableEbsDefaultEncryption(),
    "GN-AWS-KMS-001": EnableKmsRotation(),
}


# ── session ─────────────────────────────────────────────────────────

async def session_for(db: AsyncSession, organization_id: int, provider: str, account_id: str):
    """An AWS session using the credentials connected for this cloud account."""
    from app.core.encryption import decrypt_token
    from app.services.cloud_connectors.aws_connector import AWSConnector

    account = (await db.execute(
        select(CloudAccount).where(
            CloudAccount.organization_id == organization_id, CloudAccount.provider == provider,
            CloudAccount.account_identifier == account_id,
        )
    )).scalars().first()
    if account is None or not account.credentials_encrypted:
        raise RemediationError("The cloud account this finding belongs to is no longer connected.")
    creds = json.loads(decrypt_token(account.credentials_encrypted))
    try:
        return await asyncio.to_thread(AWSConnector(creds, regions=account.regions)._get_session)
    except ImportError as exc:
        raise RemediationError("The AWS SDK is not installed on the GuardNous server.") from exc


# ── plan / apply / rollback ─────────────────────────────────────────

async def plan(db: AsyncSession, organization_id: int, finding_id: int) -> dict:
    """Work out the change for a finding from the resource's live state. Writes nothing."""
    finding = (await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.organization_id == organization_id)
    )).scalar_one_or_none()
    if finding is None:
        raise RemediationError("Finding not found.")
    if finding.detected_by != DETECTED_BY:
        raise RemediationError(
            "This finding is about code, not a running cloud resource. Use a fix pull request for it instead."
        )
    if finding.is_fixed:
        raise RemediationError("This finding is already resolved.")
    action = ACTIONS.get(finding.rule_id)
    if action is None:
        raise RemediationError(
            f"GuardNous cannot fix {finding.rule_id} automatically. Automatic fixes exist for: {', '.join(sorted(ACTIONS))}."
        )
    meta = finding.metadata_ or {}
    resource = (await db.execute(
        select(CloudResource).where(
            CloudResource.organization_id == organization_id, CloudResource.resource_id == meta.get("resource_id"),
        )
    )).scalars().first()
    target = action.target(finding, resource)
    session = await session_for(db, organization_id, finding.cloud_provider, meta.get("account_id"))
    try:
        before = await asyncio.to_thread(action.read, session, target)
    except RemediationError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _explain(exc, "read the resource's current settings") from exc
    after = action.fix(before)
    if after is None:
        raise RemediationError(
            "The resource already has the correct setting in AWS. The finding will resolve on the next sync."
        )
    return {
        "finding_id": finding.id, "rule_id": finding.rule_id, "action": action.name, "warning": action.warning,
        "provider": finding.cloud_provider, "account_id": meta.get("account_id"), "region": meta.get("region"),
        "resource_id": meta.get("resource_id"), "resource_name": finding.resource_name,
        "target": target, "before": before, "after": after, "change": action.describe(before, after),
    }


async def apply(
    db: AsyncSession, organization_id: int, planned: dict, *, run_id: Optional[int] = None,
    requested_by: str = "", approved_by: str = "",
) -> dict:
    """Make an approved change, confirm it, and record how to undo it."""
    action = ACTIONS.get(planned.get("rule_id"))
    finding = (await db.execute(
        select(Finding).where(Finding.id == planned.get("finding_id"), Finding.organization_id == organization_id)
    )).scalar_one_or_none()
    if action is None or finding is None or (finding.metadata_ or {}).get("resource_id") != planned.get("resource_id"):
        raise RemediationError("The finding no longer matches the approved change.")
    target, before, after = planned["target"], planned["before"], planned["after"]
    session = await session_for(db, organization_id, planned["provider"], planned["account_id"])

    try:
        current = await asyncio.to_thread(action.read, session, target)
    except Exception as exc:  # noqa: BLE001
        raise _explain(exc, "read the resource's current settings") from exc
    if current != before:
        raise RemediationError("The resource changed in AWS after this fix was approved. Request the fix again.")
    try:
        await asyncio.to_thread(action.apply, session, target, before, after)
    except Exception as exc:  # noqa: BLE001
        raise _explain(exc, "make the change") from exc
    try:
        confirmed = await asyncio.to_thread(action.read, session, target)
    except Exception as exc:  # noqa: BLE001
        confirmed = None
        logger.warning("Could not read back %s after change: %s", planned["resource_id"], _code(exc))

    change = CloudChange(
        organization_id=organization_id, finding_id=finding.id, run_id=run_id, rule_id=planned["rule_id"],
        action=action.name, provider=planned["provider"], account_id=planned["account_id"], region=planned.get("region"),
        resource_id=planned["resource_id"], resource_name=planned["resource_name"], target=target,
        before=before, after=after, status="applied", requested_by=requested_by or None, approved_by=approved_by or None,
    )
    db.add(change)
    verified = confirmed == after
    finding.notes = [*(finding.notes or []), {
        "author": "GuardNous AI",
        "text": f"Changed in AWS: {action.name}." + ("" if verified else " The new setting could not be confirmed by reading it back.")
                + " The finding resolves on the next sync.",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }]
    if finding.status in (None, "open", "triaged"):
        finding.status = "in_progress"
    await db.commit()
    return {
        "status": "changed", "verified": verified, "change_id": change.id, "action": action.name,
        "resource": planned["resource_name"],
        "note": "Recorded with the previous settings, so it can be rolled back from the Cloud Posture page.",
    }


async def rollback(db: AsyncSession, organization_id: int, change_id: int, *, by: str) -> CloudChange:
    """Put a resource back to the state recorded before a change."""
    change = (await db.execute(
        select(CloudChange).where(CloudChange.id == change_id, CloudChange.organization_id == organization_id)
    )).scalar_one_or_none()
    if change is None:
        raise RemediationError("Change not found.")
    if change.status != "applied":
        raise RemediationError(f"This change is already {change.status.replace('_', ' ')}.")
    action = ACTIONS.get(change.rule_id)
    if action is None:
        raise RemediationError("This kind of change can no longer be rolled back automatically.")
    session = await session_for(db, organization_id, change.provider, change.account_id)
    try:
        current = await asyncio.to_thread(action.read, session, change.target)
    except Exception as exc:  # noqa: BLE001
        raise _explain(exc, "read the resource's current settings") from exc
    if current != change.after:
        raise RemediationError(
            "The resource has been changed again since GuardNous changed it, so the earlier state is not restored "
            "automatically. Review it in AWS."
        )
    try:
        await asyncio.to_thread(action.revert, session, change.target, change.before, change.after)
    except Exception as exc:  # noqa: BLE001
        raise _explain(exc, "restore the previous settings") from exc
    change.status, change.rolled_back_by, change.rolled_back_at = "rolled_back", by, datetime.now(timezone.utc)
    if change.finding_id:
        finding = await db.get(Finding, change.finding_id)
        if finding is not None:
            finding.notes = [*(finding.notes or []), {
                "author": by, "text": f"Rolled back in AWS: {change.action}.",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }]
            if finding.status == "in_progress":
                finding.status = "open"
    await db.commit()
    return change

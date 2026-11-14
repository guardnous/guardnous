"""Sync Orchestrator — coordinates resource discovery across cloud accounts,
persists to cloud_resources table, detects drift, and triggers governance re-assessment."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudAccount
from app.models.cloud_resource import CloudResource
from app.services.cloud_connectors.base import DiscoveredResource

logger = logging.getLogger(__name__)


class SyncResult:
    """Result of a single account sync operation."""

    def __init__(self, account_id: int, provider: str, account_name: str):
        self.account_id = account_id
        self.provider = provider
        self.account_name = account_name
        self.resources_discovered: int = 0
        self.resources_created: int = 0
        self.resources_updated: int = 0
        self.resources_removed: int = 0
        self.drift_detected: int = 0
        self.errors: list[str] = []
        self.started_at: datetime = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "provider": self.provider,
            "account_name": self.account_name,
            "resources_discovered": self.resources_discovered,
            "resources_created": self.resources_created,
            "resources_updated": self.resources_updated,
            "resources_removed": self.resources_removed,
            "drift_detected": self.drift_detected,
            "errors": self.errors,
            "duration_seconds": (
                (self.completed_at - self.started_at).total_seconds()
                if self.completed_at else None
            ),
        }


class SyncOrchestrator:
    """Orchestrates resource discovery across all connected cloud accounts."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def sync_account(
        self,
        account: CloudAccount,
        resource_types: list[str] | None = None,
    ) -> SyncResult:
        """Run resource discovery for a single cloud account and persist results."""
        from app.services.cloud_connectors import get_connector
        from app.core.encryption import decrypt_token

        result = SyncResult(
            account_id=account.id,
            provider=account.provider,
            account_name=account.name,
        )

        try:
            # Decrypt credentials
            creds = json.loads(decrypt_token(account.credentials_encrypted))

            # Create connector
            connector = get_connector(
                provider=account.provider,
                credentials=creds,
                regions=account.regions,
            )

            # Filter resource types if account has a filter
            effective_types = resource_types
            if account.resource_types_filter and not resource_types:
                effective_types = account.resource_types_filter

            # Run discovery
            logger.info(f"Starting discovery for {account.name} ({account.provider})")
            discovered = await connector.discover(resource_types=effective_types)
            result.resources_discovered = len(discovered)

            # Persist discovered resources (upsert)
            await self._persist_resources(
                account=account,
                discovered=discovered,
                result=result,
            )

            # Update account status
            account.status = "connected"
            account.last_synced_at = datetime.now(timezone.utc)
            account.resources_count = result.resources_discovered
            account.last_error = None

            logger.info(
                f"Sync complete for {account.name}: "
                f"{result.resources_created} created, "
                f"{result.resources_updated} updated, "
                f"{result.resources_removed} removed, "
                f"{result.drift_detected} drifted"
            )

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Sync failed for {account.name}: {error_msg}")
            result.errors.append(error_msg)
            account.status = "error"
            account.last_error = error_msg[:500]

        result.completed_at = datetime.now(timezone.utc)
        await self.db.commit()
        return result

    async def _persist_resources(
        self,
        account: CloudAccount,
        discovered: list[DiscoveredResource],
        result: SyncResult,
    ) -> None:
        """Upsert discovered resources into cloud_resources table.
        Tracks created/updated/removed counts and detects config drift."""
        now = datetime.now(timezone.utc)
        org_id = account.organization_id

        # Get existing resource IDs for this account
        existing_q = select(CloudResource.resource_id, CloudResource.config_hash).where(
            CloudResource.organization_id == org_id,
            CloudResource.provider == account.provider,
            CloudResource.account_id == account.account_identifier,
        )
        existing_rows = (await self.db.execute(existing_q)).all()
        existing_map = {row.resource_id: row.config_hash for row in existing_rows}

        discovered_ids = set()

        for res in discovered:
            discovered_ids.add(res.resource_id)
            new_hash = res.config_hash
            old_hash = existing_map.get(res.resource_id)

            if old_hash is None:
                # New resource — insert
                cr = CloudResource(
                    organization_id=org_id,
                    provider=res.provider,
                    resource_type=res.resource_type,
                    resource_id=res.resource_id,
                    resource_name=res.resource_name,
                    region=res.region,
                    account_id=account.account_identifier,
                    config=res.config,
                    config_hash=new_hash,
                    tags=res.tags,
                    status="active",
                    source="api_sync",
                    first_seen=now,
                    last_synced=now,
                )
                self.db.add(cr)
                result.resources_created += 1
            else:
                # Existing resource — update if config changed
                update_q = (
                    select(CloudResource)
                    .where(
                        CloudResource.organization_id == org_id,
                        CloudResource.provider == res.provider,
                        CloudResource.resource_id == res.resource_id,
                    )
                )
                row = (await self.db.execute(update_q)).scalars().first()
                if row:
                    if old_hash != new_hash:
                        row.config = res.config
                        row.config_hash = new_hash
                        result.resources_updated += 1
                        result.drift_detected += 1
                    row.resource_name = res.resource_name
                    row.region = res.region
                    row.tags = res.tags
                    row.status = "active"
                    row.last_synced = now

        # Remove resources that no longer exist in the cloud
        stale_ids = set(existing_map.keys()) - discovered_ids
        if stale_ids:
            await self.db.execute(
                delete(CloudResource).where(
                    CloudResource.organization_id == org_id,
                    CloudResource.provider == account.provider,
                    CloudResource.account_id == account.account_identifier,
                    CloudResource.resource_id.in_(stale_ids),
                )
            )
            result.resources_removed = len(stale_ids)

        await self.db.flush()

    async def sync_all_accounts(
        self,
        organization_id: int,
    ) -> list[SyncResult]:
        """Sync all enabled accounts for an organization."""
        q = select(CloudAccount).where(
            CloudAccount.organization_id == organization_id,
            CloudAccount.sync_enabled == True,
            CloudAccount.status != "disabled",
        )
        accounts = (await self.db.execute(q)).scalars().all()
        results = []

        for account in accounts:
            r = await self.sync_account(account)
            results.append(r)

        return results

    async def sync_due_accounts(self) -> list[SyncResult]:
        """Find and sync all accounts that are due for a scheduled sync.
        Called by the Celery beat task."""
        now = datetime.now(timezone.utc)
        q = select(CloudAccount).where(
            CloudAccount.sync_enabled == True,
            CloudAccount.status != "disabled",
            CloudAccount.credentials_encrypted.isnot(None),
        )
        all_accounts = (await self.db.execute(q)).scalars().all()
        results = []

        for account in all_accounts:
            # Check if sync is due
            if account.last_synced_at:
                hours_since = (now - account.last_synced_at).total_seconds() / 3600
                if hours_since < account.sync_interval_hours:
                    continue

            logger.info(f"Scheduled sync due for {account.name}")
            r = await self.sync_account(account)
            results.append(r)

        return results

"""Celery tasks for cloud resource sync — uses sync SQLAlchemy engine."""

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.models.cloud_account import CloudAccount
from app.models.cloud_resource import CloudResource
from app.services.cloud_connectors.base import DiscoveredResource

logger = logging.getLogger(__name__)

sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_size=3)


def _decrypt_creds(encrypted: str) -> dict:
    from app.core.encryption import decrypt_token
    return json.loads(decrypt_token(encrypted))


def _get_connector(provider: str, creds: dict, regions: list | None = None):
    from app.services.cloud_connectors import get_connector
    return get_connector(provider=provider, credentials=creds, regions=regions)


def _run_discovery_sync(connector, resource_types: list[str] | None) -> list[DiscoveredResource]:
    """Run the async discover() in a throwaway event loop (Celery is sync)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(connector.discover(resource_types=resource_types))
    finally:
        loop.close()


def _persist_resources_sync(
    session: Session,
    account: CloudAccount,
    discovered: list[DiscoveredResource],
) -> dict:
    """Upsert discovered resources into cloud_resources table (sync version)."""
    now = datetime.now(timezone.utc)
    org_id = account.organization_id
    stats = {"created": 0, "updated": 0, "removed": 0, "drift": 0}

    # Get existing resources for this account
    existing_rows = session.execute(
        select(CloudResource.resource_id, CloudResource.config_hash).where(
            CloudResource.organization_id == org_id,
            CloudResource.provider == account.provider,
            CloudResource.account_id == account.account_identifier,
        )
    ).all()
    existing_map = {r.resource_id: r.config_hash for r in existing_rows}

    discovered_ids = set()

    for res in discovered:
        discovered_ids.add(res.resource_id)
        new_hash = res.config_hash

        if res.resource_id not in existing_map:
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
            session.add(cr)
            stats["created"] += 1
        else:
            row = session.execute(
                select(CloudResource).where(
                    CloudResource.organization_id == org_id,
                    CloudResource.provider == res.provider,
                    CloudResource.resource_id == res.resource_id,
                )
            ).scalars().first()
            if row:
                if existing_map[res.resource_id] != new_hash:
                    row.config = res.config
                    row.config_hash = new_hash
                    stats["updated"] += 1
                    stats["drift"] += 1
                row.resource_name = res.resource_name
                row.region = res.region
                row.tags = res.tags
                row.status = "active"
                row.last_synced = now

    # Remove stale
    stale_ids = set(existing_map.keys()) - discovered_ids
    if stale_ids:
        for stale_id in stale_ids:
            session.execute(
                select(CloudResource).where(
                    CloudResource.organization_id == org_id,
                    CloudResource.provider == account.provider,
                    CloudResource.resource_id == stale_id,
                )
            )
        from sqlalchemy import delete as sql_delete
        session.execute(
            sql_delete(CloudResource).where(
                CloudResource.organization_id == org_id,
                CloudResource.provider == account.provider,
                CloudResource.account_id == account.account_identifier,
                CloudResource.resource_id.in_(stale_ids),
            )
        )
        stats["removed"] = len(stale_ids)

    session.flush()
    return stats


def _discovery_stage(started, finished, resources: int, connector) -> dict:
    from app.services.cloud_connectors.aws_connector import DEFAULT_AWS_REGIONS
    from app.services.cloud_posture.engine import discovery_stage

    regions = list(
        getattr(connector, "scanned_regions", None) or getattr(connector, "regions", None)
        or (DEFAULT_AWS_REGIONS if connector.PROVIDER == "aws" else [])
    )
    return discovery_stage(started, finished, resources, regions)


def _evaluate_posture(
    organization_id: int, provider: str, account_name: str, cloud_account_ids: list[str],
    sync_stage: dict | None = None,
) -> list[dict]:
    """Run the posture rules on what was just synced. A failure here does not fail the sync."""
    from app.services.cloud_posture.engine import evaluate_account
    from app.tasks.agent_runs import _run

    async def _work(db):
        return [
            await evaluate_account(db, organization_id, provider, cid, account_name=account_name, sync_stage=sync_stage)
            for cid in cloud_account_ids
        ]

    try:
        return _run(_work)
    except Exception as exc:  # noqa: BLE001
        logger.exception("[cloud_sync] Posture evaluation failed")
        return [{"evaluated": False, "reason": str(exc)[:300]}]


@celery_app.task(name="app.tasks.cloud_sync.sync_cloud_account", bind=True, max_retries=2)
def sync_cloud_account(self, account_id: int):
    """Sync resources for a single cloud account."""
    logger.info(f"[cloud_sync] Starting sync for account {account_id}")

    with Session(sync_engine) as session:
        account = session.get(CloudAccount, account_id)
        if not account:
            logger.error(f"[cloud_sync] Account {account_id} not found")
            return {"error": f"Account {account_id} not found"}

        if not account.credentials_encrypted:
            logger.error(f"[cloud_sync] Account {account_id} has no credentials")
            return {"error": "No credentials configured"}

        # One sync per account at a time. The scheduler, the connect flow and a
        # user's "Sync" click can all ask within the same minute.
        release = _claim_sync(account_id)
        if release is None:
            logger.info(f"[cloud_sync] Account {account_id} is already being synced; skipping")
            return {"skipped": "already syncing", "account_id": account_id}

        try:
            creds = _decrypt_creds(account.credentials_encrypted)
            connector = _get_connector(account.provider, creds, account.regions)

            effective_types = account.resource_types_filter or None
            discovery_started = datetime.now(timezone.utc)
            discovered = _run_discovery_sync(connector, effective_types)
            discovery_finished = datetime.now(timezone.utc)

            stats = _persist_resources_sync(session, account, discovered)

            # Update account
            account.status = "connected"
            account.last_synced_at = datetime.now(timezone.utc)
            account.resources_count = len(discovered)
            account.last_error = None

            session.commit()

            summary = {
                "account_id": account_id,
                "account_name": account.name,
                "provider": account.provider,
                "resources_discovered": len(discovered),
                **stats,
            }
            summary["posture"] = _evaluate_posture(
                account.organization_id, account.provider, account.name,
                sorted({r.account_id for r in discovered if r.account_id}),
                sync_stage=_discovery_stage(discovery_started, discovery_finished, len(discovered), connector),
            )
            logger.info(f"[cloud_sync] Sync complete: {summary}")
            return summary

        except Exception as exc:
            session.rollback()
            error_msg = str(exc)[:500]
            logger.error(f"[cloud_sync] Sync failed for account {account_id}: {error_msg}")
            # Update account error status
            with Session(sync_engine) as err_session:
                acc = err_session.get(CloudAccount, account_id)
                if acc:
                    acc.status = "error"
                    acc.last_error = error_msg
                    err_session.commit()

            raise self.retry(exc=exc, countdown=60)
        finally:
            release()


SYNC_LOCK_SECONDS = 30 * 60     # a crashed worker cannot block an account for longer than this


def _claim_sync(account_id: int):
    """Take the sync lock of one account. Returns a function that releases it,
    or ``None`` when another worker holds it. Without Redis the sync runs unlocked."""
    import uuid

    key, token = f"guardnous:cloud-sync:{account_id}", uuid.uuid4().hex
    try:
        import redis

        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2)
        if not client.set(key, token, nx=True, ex=SYNC_LOCK_SECONDS):
            return None
    except Exception as exc:  # noqa: BLE001 - a lock problem must not stop syncing
        logger.warning("[cloud_sync] Sync lock unavailable (%s); continuing without it", type(exc).__name__)
        return lambda: None

    def release() -> None:
        try:
            if client.get(key) == token.encode():      # only our own claim
                client.delete(key)
        except Exception:  # noqa: BLE001 - it expires by itself
            pass
    return release


@celery_app.task(name="app.tasks.cloud_sync.sync_all_due_accounts")
def sync_all_due_accounts():
    """Periodic task: find all accounts due for sync and trigger them."""
    logger.info("[cloud_sync] Checking for accounts due for sync...")
    now = datetime.now(timezone.utc)
    triggered = 0

    with Session(sync_engine) as session:
        accounts = session.execute(
            select(CloudAccount).where(
                CloudAccount.sync_enabled == True,
                CloudAccount.status != "disabled",
                CloudAccount.credentials_encrypted.isnot(None),
            )
        ).scalars().all()

        for account in accounts:
            if account.last_synced_at:
                hours_since = (now - account.last_synced_at).total_seconds() / 3600
                if hours_since < account.sync_interval_hours:
                    continue

            logger.info(f"[cloud_sync] Dispatching sync for {account.name} (id={account.id})")
            sync_cloud_account.delay(account.id)
            triggered += 1

    logger.info(f"[cloud_sync] Triggered {triggered} account syncs")
    return {"triggered": triggered}

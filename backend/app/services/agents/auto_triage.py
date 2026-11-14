"""Start a Triage Agent run by itself after an assessment (``AGENT_AUTO_TRIAGE_AFTER_SCAN``).

Nobody started such a run, so it is owned by nobody:

* it may read findings and *propose* triage decisions, and nothing else. It
  never gets a tool that acts outside GuardNous;
* its proposal waits for someone with ``agents:manage``. There is no requester
  who could confirm it;
* at most one such run per organization is open at a time, so scans that
  arrive while a list is waiting for review do not pile up more lists.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import func, select

from app.core.config import settings
from app.models.agent import AgentRun
from app.models.finding import Finding
from app.models.scan import Scan

logger = logging.getLogger(__name__)

AGENT_ID = "triage_agent"
OPEN_RUN_STATUSES = ("queued", "running", "awaiting_approval")
START_DELAY_SECONDS = 20        # let the scan's own transaction commit first


def _enabled() -> bool:
    return bool(settings.AGENT_AUTO_TRIAGE_AFTER_SCAN and settings.AGENT_ENABLED)


def _waiting(scan: Scan):
    return select(func.count(Finding.id)).where(
        Finding.scan_id == scan.id, Finding.status == "open",
        Finding.is_fixed == False, Finding.is_ignored == False,  # noqa: E712
    )


def _already_open(organization_id: int):
    from app.services.agents.runtime import TRIGGER_SCAN

    return select(func.count(AgentRun.id)).where(
        AgentRun.organization_id == organization_id, AgentRun.trigger == TRIGGER_SCAN,
        AgentRun.status.in_(OPEN_RUN_STATUSES),
    )


def _new_run(scan: Scan, waiting: int) -> AgentRun:
    from app.services.agents.registry import get_agent
    from app.services.agents.runtime import TRIGGER_SCAN, step_budget
    from app.services.agents.triage_tools import target_label

    target = target_label(scan)
    return AgentRun(
        organization_id=scan.organization_id, user_id=None, agent_id=AGENT_ID, trigger=TRIGGER_SCAN,
        goal=(
            f"Assessment #{scan.id} of {target} left {waiting} findings without a triage decision. "
            f"Triage the queue for this target (target: \"{target}\"), most severe first. Read the evidence, "
            "then propose your decisions as one list for a person to review."
        ),
        status="queued", messages=[], pending_outputs={}, max_steps=step_budget(get_agent(AGENT_ID)),
    )


def _enqueue(run_id: int) -> None:
    try:
        from app.tasks.agent_runs import execute_agent_run

        execute_agent_run.apply_async((run_id,), countdown=START_DELAY_SECONDS)
    except Exception:  # noqa: BLE001 - the periodic sweep picks up queued runs if the broker is briefly away
        logger.exception("Could not queue automatic triage run %s", run_id)


def start_after_scan_sync(db, scan: Scan) -> Optional[int]:
    """Worker (sync session). Returns the run id, or None when no run was started."""
    if not _enabled() or scan.organization_id is None:
        return None
    try:
        db.flush()
        waiting = db.execute(_waiting(scan)).scalar() or 0
        if not waiting or db.execute(_already_open(scan.organization_id)).scalar():
            return None
        run = _new_run(scan, waiting)
        db.add(run)
        db.flush()
        _enqueue(run.id)
        return run.id
    except Exception:  # noqa: BLE001 - triage is a convenience; it must never fail the scan
        logger.exception("Automatic triage could not be started for scan %s", scan.id)
        return None


async def start_after_scan(db, scan: Scan) -> Optional[int]:
    """API and async workers. Returns the run id, or None when no run was started."""
    if not _enabled() or scan.organization_id is None:
        return None
    try:
        await db.flush()
        waiting = (await db.execute(_waiting(scan))).scalar() or 0
        if not waiting or (await db.execute(_already_open(scan.organization_id))).scalar():
            return None
        run = _new_run(scan, waiting)
        db.add(run)
        await db.flush()
        _enqueue(run.id)
        return run.id
    except Exception:  # noqa: BLE001
        logger.exception("Automatic triage could not be started for scan %s", scan.id)
        return None

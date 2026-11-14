"""Worker tasks for durable agent runs."""
from __future__ import annotations

import asyncio
import logging

from app.core.config import settings
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _run(coro_factory):
    """Run async work in a worker with its own engine (one event loop per task)."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    async def _go():
        engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as db:
                return await coro_factory(db)
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def enqueue_run(run_id: int) -> None:
    execute_agent_run.delay(run_id)


@celery_app.task(name="app.tasks.agent_runs.execute_agent_run", acks_late=True)
def execute_agent_run(run_id: int) -> dict:
    from app.services.agents.runtime import execute_run

    async def _work(db):
        run = await execute_run(db, run_id)
        return {"run_id": run_id, "status": run.status if run else "missing"}

    return _run(_work)


@celery_app.task(name="app.tasks.agent_runs.sweep_agent_runs")
def sweep_agent_runs() -> dict:
    """Fail runs whose worker died, expire undecided approvals, resume what can continue."""
    from app.services.agents.runtime import sweep

    result = _run(sweep)
    for run_id in result.get("requeue", []):
        enqueue_run(run_id)
    return result

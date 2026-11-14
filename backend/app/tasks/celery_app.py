from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery_app = Celery(
    "guardnous",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    include=[
        "app.tasks.jobs",
        "app.tasks.chat_tasks",
        "app.tasks.cloud_sync",
        "app.tasks.agent_runs",
        "app.services.agents.autonomous",
        "app.services.plugins.health_monitor",
    ],
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "sync-cve-database": {
            "task": "app.tasks.jobs.sync_cve_database",
            "schedule": 86400.0,  # Daily
        },
        "run-scheduled-scans": {
            "task": "app.tasks.jobs.run_scheduled_scans",
            "schedule": 300.0,  # Every 5 minutes — runs scan schedules that are due
        },
        "run-scheduled-reports": {
            "task": "run_scheduled_reports",
            "schedule": 300.0,  # Every 5 minutes — runs report schedules that are due
        },
        "sweep-agent-runs": {
            "task": "app.tasks.agent_runs.sweep_agent_runs",
            "schedule": 300.0,
        },
        "sync-cloud-accounts": {
            "task": "app.tasks.cloud_sync.sync_all_due_accounts",
            "schedule": 1800.0,  # Every 30 minutes — checks which accounts need re-sync
        },
        # Autonomous agents (app/services/agents/autonomous.py)
        "agent-cve-watchdog": {
            "task": "agent.cve_watchdog",
            "schedule": crontab(minute=0, hour="*/6"),
        },
        "agent-posture-drift": {
            "task": "agent.posture_drift",
            "schedule": crontab(minute=30, hour="*/4"),
        },
        "agent-compliance-monitor": {
            "task": "agent.compliance_monitor",
            "schedule": crontab(minute=0, hour=8),
        },
        "agent-stale-finding-detector": {
            "task": "agent.stale_finding_detector",
            "schedule": crontab(minute=0, hour=9),
        },
        # Scanner plugin supply chain (app/services/plugins/health_monitor.py)
        "agent-plugin-supply-chain-monitor": {
            "task": "agent.plugin_supply_chain_monitor",
            "schedule": crontab(minute=0, hour="*/6"),
        },
        "agent-plugin-integrity-check": {
            "task": "agent.plugin_integrity_check",
            "schedule": crontab(minute=15, hour="*"),
        },
    },
)

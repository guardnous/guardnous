"""Bring the database schema up to date.

Usage: ``python -m app.core.migrations`` (also called on application startup).

The Alembic chain starts from tables that predate it, so it cannot build an
empty database. Three cases are handled:

* empty database      -> create the schema from the models, stamp it at head
* versioned database  -> ``alembic upgrade head``; a failure is an error
* tables but no version (created by older builds that never stamped)
                      -> create any missing tables and report columns the
                         models expect but the database lacks; not stamped,
                         because its real revision is unknown
"""
import logging
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.core.config import settings
from app.core.database import Base

logger = logging.getLogger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config() -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    # env.py calls logging.config.fileConfig when a config file name is set,
    # which would replace the application's log handlers.
    cfg.config_file_name = None
    return cfg


def _missing_columns(inspector) -> list[str]:
    missing = []
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        missing += [f"{table.name}.{c.name}" for c in table.columns if c.name not in existing]
    return missing


def bootstrap_schema() -> str:
    """Create or upgrade the schema. Returns 'created', 'upgraded' or 'legacy'."""
    import app.models  # noqa: F401  (register every model on Base.metadata)

    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        if "alembic_version" in tables:
            command.upgrade(_alembic_config(), "head")
            logger.info("Database schema upgraded to head")
            return "upgraded"

        if not tables:
            Base.metadata.create_all(engine)
            command.stamp(_alembic_config(), "head")
            logger.info("Empty database: created schema from models and stamped at head")
            return "created"

        Base.metadata.create_all(engine)
        missing = _missing_columns(inspect(engine))
        if missing:
            logger.error(
                "Database has no Alembic version and is missing %d column(s) the "
                "application expects: %s. Add them, then run `alembic stamp head`.",
                len(missing), ", ".join(missing),
            )
        else:
            command.stamp(_alembic_config(), "head")
            logger.info("Unversioned database matches the models: stamped at head")
        return "legacy"
    finally:
        engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        print(f"schema: {bootstrap_schema()}")
    except Exception as exc:  # noqa: BLE001
        print(f"schema bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)

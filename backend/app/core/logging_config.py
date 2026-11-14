"""
Structured JSON logging configuration.

Call ``setup_logging()`` once at startup. All subsequent ``logging.getLogger()``
calls will emit JSON lines suitable for log aggregation (ELK, Datadog, CloudWatch).
"""

import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Propagate extra fields (request_id, user_id, etc.)
        for key in ("request_id", "user_id", "tenant_id", "org_id", "scan_id"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        return json.dumps(log_entry, default=str)


def setup_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configure root logger with either JSON or human-readable output."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates on reload
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if json_output:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))

    root.addHandler(handler)

    # Quiet noisy libraries
    for name in ("uvicorn.access", "httpx", "httpcore", "urllib3", "sqlalchemy.engine"):
        logging.getLogger(name).setLevel(logging.WARNING)

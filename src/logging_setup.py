"""Structured (JSON) logging configuration for Net Sentry (N).

Call :func:`setup_logging` once at application startup.  When
``json_enabled=True`` every log record is emitted as a single JSON object
(compatible with Elasticsearch, Loki, Datadog, etc.).  When
``json_enabled=False`` a human-readable format is used instead, which is
the default for interactive / development use.

JSON fields emitted per record:
    timestamp   — ISO-8601 UTC datetime
    level       — log level name (INFO, WARNING, …)
    logger      — logger name
    message     — formatted log message
    (+ any extra kwargs passed to the logger)
"""

import logging
import sys
from typing import Any


def setup_logging(
    level: int = logging.INFO,
    json_enabled: bool = False,
) -> None:
    """Configure the root logger.

    Args:
        level: Minimum log level (e.g. ``logging.DEBUG``).
        json_enabled: Emit JSON-structured log records when ``True``;
            use a plain human-readable format when ``False``.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any handlers added during import of other modules so we start
    # from a clean slate.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if json_enabled:
        handler.setFormatter(_build_json_formatter())
    else:
        handler.setFormatter(_build_plain_formatter())

    root.addHandler(handler)


def _build_json_formatter() -> logging.Formatter:
    """Return a JSON log formatter.

    Returns:
        A :class:`logging.Formatter` that produces JSON output.
    """
    try:
        from pythonjsonlogger.json import JsonFormatter as _JsonFormatter

        class _CustomJsonFormatter(_JsonFormatter):
            def add_fields(
                self,
                log_record: dict[str, Any],
                record: logging.LogRecord,
                message_dict: dict[str, Any],
            ) -> None:
                super().add_fields(log_record, record, message_dict)
                # Rename fields to match common conventions
                if "asctime" in log_record:
                    log_record["timestamp"] = log_record.pop("asctime")
                if "levelname" in log_record:
                    log_record["level"] = log_record.pop("levelname")
                if "name" in log_record:
                    log_record["logger"] = log_record.pop("name")

        return _CustomJsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S+00:00",
        )
    except ImportError:
        # python-json-logger is optional; fall back gracefully.
        logging.getLogger(__name__).warning("python-json-logger not installed; falling back to plain formatter.")
        return _build_plain_formatter()


def _build_plain_formatter() -> logging.Formatter:
    """Return a human-readable log formatter.

    Returns:
        A :class:`logging.Formatter` suitable for interactive use.
    """
    return logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

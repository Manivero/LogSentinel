"""Application logging setup.

This configures logging for the *application itself* (progress, warnings,
errors) — not to be confused with the untrusted log *files* being analyzed.
Uses Rich for readable console output by default, with an optional
single-line JSON formatter for machine-parseable logs (e.g. shipping the
application's own operational logs to a SIEM alongside its findings).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.logging import RichHandler

_CONFIGURED = False
_ROOT_LOGGER_NAME = "ai_log_analyzer"


class _JSONFormatter(logging.Formatter):
    """Renders each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(
    level: str = "INFO",
    *,
    json_logs: bool = False,
    log_file: Path | None = None,
) -> None:
    """Configure the root application logger. Safe to call multiple times.

    Args:
        level: Standard logging level name (DEBUG, INFO, WARNING, ERROR).
        json_logs: If True, use single-line JSON output instead of Rich.
        log_file: Optional path to additionally write logs to a file.
    """
    global _CONFIGURED

    root = logging.getLogger(_ROOT_LOGGER_NAME)
    root.setLevel(level.upper())
    root.handlers.clear()
    root.propagate = False

    console_handler: logging.Handler
    if json_logs:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(_JSONFormatter())
    else:
        # markup=False: log messages may echo untrusted log content (e.g.
        # "could not parse line: <raw_line>"); disabling Rich markup parsing
        # prevents that content from being interpreted as formatting/escape
        # directives when rendered to the terminal.
        console_handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_path=False,
            markup=False,
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(console_handler)

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(_JSONFormatter())
            root.addHandler(file_handler)
        except OSError:
            root.warning("Could not open log file %s; continuing without it.", log_file)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger nested under the application root.

    Configures a sensible default (INFO, Rich console) if
    `configure_logging` has not been called yet, so modules/tests that
    import a logger before app startup still behave reasonably.
    """
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")

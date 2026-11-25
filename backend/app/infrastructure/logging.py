# ==========================#
# Logging.py
# ==========================#

"""
Central logging configuration for findspace.

Responsibilities:
- Configure application and infrastructure logging once at process startup.
- Resolve log verbosity from the application environment and LOG_LEVEL.
- Emit consistent UTC timestamps, severity levels, logger names, and messages.
- Route logs through a single stdout handler for platform log collection.
- Integrate Uvicorn and SQLAlchemy logging without duplicate handlers.
- Provide named standard-library loggers for services and other modules.

Not responsible for:
- Recording persistent security audit trails.
- Collecting metrics, tracing requests, or delivering logs to external services.
- Automatically identifying or redacting sensitive application data.
- Configuring logging each time a service or logger is created.

Invariants:
- Importing this module must not configure logging or load application settings.
- Loggers must share the central output configuration.
- Explicit LOG_LEVEL settings take precedence over environment defaults.
- Credentials, tokens, OTPs, personal information, and sensitive request
  payloads must not be passed to logging calls.
"""

from __future__ import annotations

import logging
import time
from logging.config import dictConfig


class UTCFormatter(logging.Formatter):
    """Format timestamps in UTC regardless of the host's local timezone."""

    converter = time.gmtime


def configure_logging() -> None:
    """Configure logging during application or worker startup.

    Development defaults to DEBUG; staging and production default to INFO.
    Repeated configuration replaces the managed handlers rather than adding
    new ones. Call before starting request handling or background work.
    """
    from app.infrastructure.config import settings

    development = settings.ENV == "dev"
    level = settings.LOG_LEVEL or ("DEBUG" if development else "INFO")

    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "()": UTCFormatter,
                    "format": (
                        "%(asctime)s.%(msecs)03dZ | %(levelname)s | "
                        "%(name)s | %(message)s"
                    ),
                    "datefmt": "%Y-%m-%dT%H:%M:%S",
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "level": level,
                    "formatter": "standard",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": level,
                "handlers": ["stdout"],
            },
            "loggers": {
                "app": {
                    "level": "NOTSET",
                    "handlers": [],
                    "propagate": True,
                },
                "uvicorn": {
                    "level": "NOTSET",
                    "handlers": [],
                    "propagate": True,
                },
                "uvicorn.error": {
                    "level": "NOTSET",
                    "handlers": [],
                    "propagate": True,
                },
                "uvicorn.access": {
                    "level": "NOTSET",
                    "handlers": [],
                    "propagate": True,
                },
                "sqlalchemy.engine": {
                    "level": "INFO" if development else "WARNING",
                    "handlers": [],
                    "propagate": True,
                },
                "httpx": {"level": "WARNING"},
                "httpcore": {"level": "WARNING"},
                "asyncio": {"level": "WARNING"},
            },
        }
    )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger without configuring or attaching handlers."""
    return logging.getLogger(name)

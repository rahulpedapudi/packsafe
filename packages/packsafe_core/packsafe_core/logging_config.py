"""Application-wide logging configuration.

``setup_logging()`` is the single entry point for PackSafe logging. It is idempotent, so
the CLI can call it at import time and again from its callback once the user has supplied
verbosity flags without ending up with duplicate handlers.

Output goes to a rotating file rather than the console: the CLI renders its verdict with
``rich`` on stdout, and log records interleaved there would corrupt it. Progress is meant
to be read from the log file while debugging.

Verbosity resolves in this order: explicit argument, ``PACKSAFE_LOG_LEVEL``, then INFO.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

DEFAULT_LOG_FILENAME = "app-dev.log"

LOG_LEVEL_ENV = "PACKSAFE_LOG_LEVEL"
LOG_FILE_ENV = "PACKSAFE_LOG_FILE"

# Millisecond precision: stage boundaries are often sub-millisecond apart, and a
# second-only timestamp cannot order two concurrent stages.
LOG_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)-55s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

MAX_LOG_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

_LEVEL_NAMES = {
    "NOTSET": logging.NOTSET,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "FATAL": logging.CRITICAL,
    "CRITICAL": logging.CRITICAL,
}

# Third-party loggers that restate what PackSafe traces itself: httpx announces every
# request, and PackSafe records the same call with a duration and outcome. Restored at
# DEBUG, where the raw request line is genuinely useful.
NOISY_LOGGERS = ("httpx",)

# Loggers that are pure noise even at DEBUG: httpcore dumps raw header bytes per frame
# and asyncio narrates the loop. Never restored.
ALWAYS_MUTED_LOGGERS = (
    "httpcore",
    "httpcore.connection",
    "httpcore.http11",
    "urllib3",
    "asyncio",
)

_configured_file: Path | None = None


def resolve_level(level: int | str | None = None) -> int:
    """Resolves a logging level from an argument, the environment, then the INFO default."""
    if isinstance(level, int):
        return level

    candidate = level or os.environ.get(LOG_LEVEL_ENV) or "INFO"
    resolved = _LEVEL_NAMES.get(str(candidate).strip().upper())
    if resolved is None:
        return logging.INFO
    return resolved


def resolve_log_file(log_file: str | Path | None = None) -> Path:
    """Resolves the log destination from an argument, the environment, then the default."""
    if log_file:
        return Path(log_file)
    return Path(os.environ.get(LOG_FILE_ENV) or DEFAULT_LOG_FILENAME)


def setup_logging(
    level: int | str | None = None,
    log_file: str | Path | None = None,
    *,
    reconfigure: bool = False,
) -> logging.Logger:
    """Configures root logging to a rotating file and returns the root logger.

    Safe to call repeatedly: handlers are only rebuilt when the destination changes or
    ``reconfigure`` is set, so a second call just updates the level. An unwritable
    destination falls back to ``logging.lastResort`` rather than breaking the CLI.
    """
    global _configured_file

    resolved_level = resolve_level(level)
    target = resolve_log_file(log_file)
    root = logging.getLogger()

    if reconfigure or target != _configured_file:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        _configured_file = target

        try:
            if target.parent and not target.parent.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                target,
                maxBytes=MAX_LOG_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
        except OSError:
            # Never let a logging problem take the CLI down with it.
            root.setLevel(resolved_level)
            return root

        handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
        handler.setLevel(resolved_level)
        root.addHandler(handler)
        root.setLevel(resolved_level)

    for handler in root.handlers:
        handler.setLevel(resolved_level)

    # Restore third-party verbosity when debugging, mute it otherwise.
    noisy_level = resolved_level if resolved_level <= logging.DEBUG else logging.WARNING
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(noisy_level)
    for name in ALWAYS_MUTED_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    root.setLevel(resolved_level)
    return root

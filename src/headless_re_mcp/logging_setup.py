"""Where diagnostic logs go, and how their timestamps are written.

Incident logs and telemetry logs are separate streams with different formats,
but they answer the same question during an incident -- what was this process
doing -- so they resolve to the same directory and rotate under the same limits.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from contextlib import suppress
from logging.handlers import RotatingFileHandler
from pathlib import Path

from platformdirs import user_log_path

LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 5


class UtcFormatter(logging.Formatter):
    """Format ``asctime`` in UTC so a trailing ``Z`` is not a lie."""

    converter = staticmethod(time.gmtime)


def resolve_log_dir(explicit: Path | None = None) -> Path:
    """Return a writable log directory, preferring the caller's choice.

    Falls back to the temp directory because a process that cannot write its
    logs must still start; losing logs is bad, refusing to run is worse.
    """
    configured = os.environ.get("HEADLESS_RE_LOG_DIR")
    root = (
        explicit
        or (Path(configured) if configured else None)
        or user_log_path("headless-re-mcp", appauthor=False)
    )
    try:
        # expanduser is inside the guard because it raises RuntimeError -- not
        # OSError -- when the tilde cannot be resolved (``~nosuchuser/logs``, or
        # a service account with no home). mkdir raises ValueError for a path
        # with an embedded NUL. Left uncaught, either one escaped through
        # install_global_exception_hooks and refused to start the very server
        # the sentence above says must start.
        root = root.expanduser()
        root.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError, ValueError):
        root = Path(tempfile.gettempdir()) / "headless-re-mcp" / "logs"
        # The fallback can fail too -- a full volume takes both with it -- and
        # raising here would defeat the sentence above. The handler is built
        # with delay=True, so a directory that does not exist costs the logs and
        # nothing else.
        with suppress(OSError):
            root.mkdir(parents=True, exist_ok=True)
    return root


def attach_rotating_handler(
    logger_name: str,
    path: Path,
    *,
    formatter: logging.Formatter,
    level: int = logging.INFO,
) -> Path:
    """Point one named logger at one rotating file and nothing else.

    ``propagate`` is disabled so these records never reach a root handler that
    an embedding application configured for its own purposes.
    """
    handler = RotatingFileHandler(
        path,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUPS,
        encoding="utf-8",
        # Opened on the first record rather than here. Built eagerly, a path the
        # process cannot open raised out of whichever entry point installed the
        # hooks, so a full volume stopped the service from starting at all --
        # and the supervisor restarts what exits during startup, so that became
        # a crash loop. Deferred, the failure surfaces in emit(), where
        # RotatingFileHandler already routes it to handleError.
        delay=True,
    )
    handler.setFormatter(formatter)
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    logger.propagate = False
    for existing in list(logger.handlers):
        existing.close()
    logger.handlers.clear()
    logger.addHandler(handler)
    return path

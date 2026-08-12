"""Last-resort error boundaries shared by every public transport and entry point.

Expected domain failures should still use their specific ``RpcError`` codes.  This
module only handles defects and unexpected runtime failures, gives callers a stable
incident id, and records the traceback in a rotating local log.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import re
import sys
import tempfile
import threading
import uuid
from collections.abc import Callable
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType
from typing import Any, ParamSpec, TypeVar

from platformdirs import user_log_path

P = ParamSpec("P")
R = TypeVar("R")
JsonObject = dict[str, Any]

_LOGGER_NAME = "headless_re_mcp.incidents"
_LOG_MAX_BYTES = 5 * 1024 * 1024
_LOG_BACKUPS = 5
_LOCK = threading.Lock()
_LOG_PATH: Path | None = None
_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+"),
)


def _redact_text(value: object, *, limit: int = 1000) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text[:limit]


def configure_incident_logging(log_dir: Path | None = None) -> Path:
    """Configure the process-wide rotating incident log exactly once."""

    global _LOG_PATH
    with _LOCK:
        if _LOG_PATH is not None:
            return _LOG_PATH
        configured = os.environ.get("HEADLESS_RE_LOG_DIR")
        root = (
            log_dir
            or (Path(configured) if configured else None)
            or user_log_path("headless-re-mcp", appauthor=False)
        ).expanduser()
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError:
            root = Path(tempfile.gettempdir()) / "headless-re-mcp" / "logs"
            root.mkdir(parents=True, exist_ok=True)
        path = (root / "incidents.log").resolve()
        handler = RotatingFileHandler(
            path,
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUPS,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s")
        )
        logger = logging.getLogger(_LOGGER_NAME)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.handlers.clear()
        logger.addHandler(handler)
        _LOG_PATH = path
        return path


def record_exception(
    exc: BaseException,
    *,
    context: str,
    traceback: TracebackType | None = None,
) -> JsonObject:
    """Write one traceback and return the safe fields exposed to callers."""

    incident_id = uuid.uuid4().hex
    log_path = configure_incident_logging()
    safe_message = _redact_text(exc)
    safe_exception = RuntimeError(f"{type(exc).__name__}: {safe_message}")
    logger = logging.getLogger(_LOGGER_NAME)
    logger.error(
        "incident_id=%s context=%s exception=%s message=%s",
        incident_id,
        _redact_text(context, limit=300),
        type(exc).__name__,
        safe_message,
        exc_info=(
            type(safe_exception),
            safe_exception,
            traceback if traceback is not None else exc.__traceback__,
        ),
    )
    return {
        "incident_id": incident_id,
        "context": _redact_text(context, limit=300),
        "exception_type": type(exc).__name__,
        "message": safe_message,
        "log_path": str(log_path),
    }


def exception_envelope(exc: BaseException, *, context: str) -> JsonObject:
    """Return the canonical AI-readable envelope for an unexpected exception."""

    incident = record_exception(exc, context=context)
    message = (
        f"Unexpected {incident['exception_type']}: {incident['message']}. "
        f"Incident {incident['incident_id']} was written to the local log."
    )
    return {
        "ok": False,
        "data": None,
        "error": {
            "code": "internal_error",
            "message": message,
            "details": incident,
            "retryable": False,
        },
        "meta": {"incident_id": incident["incident_id"]},
    }


def guard_tool_handler(
    handler: Callable[P, JsonObject],
    *,
    tool_name: str,
) -> Callable[P, JsonObject]:
    """Keep one broken tool invocation from tearing down MCP or Agent transports."""

    @functools.wraps(handler)
    def guarded(*args: P.args, **kwargs: P.kwargs) -> JsonObject:
        try:
            return handler(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - tool code cannot terminate the server
            return exception_envelope(exc, context=f"tool:{tool_name}")

    return guarded


def run_cli_safely(action: Callable[[], int], *, context: str) -> int:
    """Run a CLI action without emitting a raw traceback to an AI caller."""

    install_global_exception_hooks(context)
    try:
        return int(action())
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - public process boundary
        print(
            json.dumps(exception_envelope(exc, context=context), ensure_ascii=False),
            file=sys.stderr,
        )
        return 1


def install_asyncio_exception_handler(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Log task/callback failures that nobody awaited."""

    target = loop
    if target is None:
        try:
            target = asyncio.get_running_loop()
        except RuntimeError:
            return

    def handle(_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exc = context.get("exception")
        if not isinstance(exc, BaseException):
            exc = RuntimeError(str(context.get("message") or "unhandled asyncio exception"))
        record_exception(exc, context="asyncio")

    target.set_exception_handler(handle)


def install_global_exception_hooks(context: str = "process") -> Path:
    """Install process, thread and unraisable hooks and return the incident log path."""

    log_path = configure_incident_logging()

    def sys_hook(
        exc_type: type[BaseException],
        exc: BaseException,
        tb: TracebackType | None,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        incident = record_exception(exc, context=context, traceback=tb)
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "uncaught_exception",
                        "message": f"{exc_type.__name__}: {_redact_text(exc)}",
                        "details": incident,
                    },
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
            flush=True,
        )

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        exc = args.exc_value
        if exc is None:
            exc = RuntimeError("thread exception hook received no exception")
        record_exception(
            exc,
            context=f"thread:{getattr(args.thread, 'name', 'unknown')}",
            traceback=args.exc_traceback,
        )

    def unraisable_hook(args: Any) -> None:
        exc = args.exc_value
        if not isinstance(exc, BaseException):
            exc = RuntimeError(str(args.err_msg or "unraisable exception"))
        record_exception(exc, context=f"unraisable:{_redact_text(args.object, limit=200)}")

    sys.excepthook = sys_hook
    threading.excepthook = thread_hook
    sys.unraisablehook = unraisable_hook
    install_asyncio_exception_handler()
    return log_path


def register_fastapi_exception_boundary(app: Any) -> None:
    """Return unexpected Web failures as JSON while preserving FastAPI's HTTP errors."""

    from fastapi import Request
    from fastapi.responses import JSONResponse

    @app.exception_handler(Exception)  # type: ignore[untyped-decorator]
    async def unexpected_web_exception(request: Request, exc: Exception) -> JSONResponse:
        payload = exception_envelope(exc, context=f"web:{request.method}:{request.url.path}")
        return JSONResponse(payload, status_code=500)

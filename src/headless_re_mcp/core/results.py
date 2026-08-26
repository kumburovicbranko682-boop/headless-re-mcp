"""Shared Result/RpcError construction helpers.

These live in a leaf module so every service mixin can import the canonical
``_success`` / ``_failure`` implementations directly instead of lazily
re-importing them from ``core.service`` (which would create an import cycle).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut
from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.backends.x64dbg.stealth import StealthError
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.models import Result, RpcError, TargetMismatch
from headless_re_mcp.core.session import InvalidStateTransition, SessionNotFound
from headless_re_mcp.detection import PeFormatError
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.detection.exeinfope import ExeinfopeScanError
from headless_re_mcp.unpack.upx import UpxScanError

JsonObject = dict[str, Any]


def _success(data: JsonObject, **meta: object) -> Result[JsonObject]:
    return Result[JsonObject](ok=True, data=data, meta=dict(meta))


def _failure(exc: BaseException, **details: object) -> Result[JsonObject]:
    if isinstance(exc, BoundedCancelled):
        # A caller cancel is a control signal, not a fault. Endpoints that run a
        # bounded tool under a cancel scope re-raise this to their own handler
        # before reaching here; naming it in the canonical envelope keeps a path
        # that forgets that from filing a caller cancel as an internal_error with
        # a logged incident -- the exact miscasting the upx and net_reactor_slayer
        # adapters carried until each grew its own re-raise.
        error = RpcError(
            code="cancelled",
            message=str(exc) or "cancelled by caller",
            details={**details, "killed_pids": list(getattr(exc, "killed", []) or [])},
            retryable=True,
        )
    elif isinstance(exc, TimedOut):
        # Same reasoning for its sibling: outrunning the deadline is a bound the
        # run_bounded wrappers normally remap to a tool-specific timeout. One that
        # slips through must still not read as an unexpected internal fault.
        error = RpcError(
            code="timeout",
            message=str(exc),
            details={
                **details,
                "timeout_s": float(getattr(exc, "timeout", 0.0) or 0.0),
                "killed_pids": list(getattr(exc, "killed", []) or []),
            },
            retryable=True,
        )
    elif isinstance(exc, DieScanError):
        error = RpcError(
            code=exc.code,
            message=str(exc),
            details={**details, **exc.details},
            retryable=exc.code in {"timeout", "process_failed"},
        )
    elif isinstance(exc, UpxScanError):
        error = RpcError(
            code=exc.code,
            message=str(exc),
            details={**details, **exc.details},
            retryable=exc.retryable,
        )
    elif isinstance(exc, ExeinfopeScanError):
        # The sibling of DieScanError: detect_scan's outer handler routes both
        # into this envelope, but only DIE was named here. An Exeinfo PE error
        # (invalid_argument, executable_not_found, timeout, process_failed, ...)
        # then fell through to internal_error, minting an incident and hiding a
        # structured code the caller could have acted on -- the same miscasting
        # the bounded cancel/timeout cases carried until each was named.
        error = RpcError(
            code=exc.code,
            message=str(exc),
            details={**details, **exc.details},
            retryable=exc.retryable,
        )
    elif isinstance(exc, PeFormatError):
        error = RpcError(
            code="invalid_pe",
            message=str(exc),
            details=dict(details),
        )
    elif isinstance(exc, TargetMismatch):
        error = RpcError(
            code=exc.code,
            message=exc.message,
            details={**details, **exc.details},
        )
    elif isinstance(exc, AddressSyncError):
        error = RpcError(
            code=exc.code,
            message=str(exc),
            details={**details, **exc.details},
        )
    elif isinstance(exc, (StealthError, IdaWorkerError, XdbgRpcError)):
        error = RpcError(
            code=exc.code,
            message=str(exc),
            details={**details, **exc.details},
            retryable=exc.retryable,
        )
    elif isinstance(exc, SessionNotFound):
        # Only this type. Any KeyError used to become session_not_found, so a
        # missing key while reading a backend reply, or a cache eviction race,
        # told the caller its session was gone -- and recreating the session,
        # the reasonable response to that, is the wrong answer to a transient
        # internal fault.
        message = str(exc.args[0]) if exc.args else "session not found"
        error = RpcError(code="session_not_found", message=message, details=dict(details))
    elif isinstance(exc, FileNotFoundError):
        error = RpcError(code="file_not_found", message=str(exc), details=dict(details))
    elif isinstance(exc, TimeoutError):
        error = RpcError(
            code="workflow_timeout",
            message=str(exc),
            details=dict(details),
            retryable=True,
        )
    elif isinstance(exc, (InvalidStateTransition, ValueError)):
        error = RpcError(code="invalid_request", message=str(exc), details=dict(details))
    elif isinstance(exc, sqlite3.Error):
        # Named rather than left as internal_error: the store being unreachable,
        # read-only or corrupt says nothing about the request and everything
        # about the instance. An unattended caller that cannot tell them apart
        # retries a query that will never work again, or gives up on a database
        # that was only locked.
        error = RpcError(
            code="storage_unavailable",
            message=f"{type(exc).__name__}: {exc}",
            details=dict(details),
            retryable=isinstance(exc, sqlite3.OperationalError),
        )
    else:
        from headless_re_mcp.error_boundary import record_exception

        incident = record_exception(exc, context="service-result")
        error = RpcError(
            code="internal_error",
            message=(
                f"Unexpected {type(exc).__name__}: {incident['message']} "
                f"(incident {incident['incident_id']})"
            ),
            details={**details, **incident},
        )
    return Result[JsonObject](ok=False, error=error)

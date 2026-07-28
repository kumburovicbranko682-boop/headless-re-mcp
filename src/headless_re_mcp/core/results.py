"""Shared Result/RpcError construction helpers.

These live in a leaf module so every service mixin can import the canonical
``_success`` / ``_failure`` implementations directly instead of lazily
re-importing them from ``core.service`` (which would create an import cycle).
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.session import InvalidStateTransition
from headless_re_mcp.detection import PeFormatError
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.upx import UpxScanError

JsonObject = dict[str, Any]


def _success(data: JsonObject, **meta: object) -> Result[JsonObject]:
    return Result[JsonObject](ok=True, data=data, meta=dict(meta))


def _failure(exc: BaseException, **details: object) -> Result[JsonObject]:
    if isinstance(exc, DieScanError):
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
    elif isinstance(exc, PeFormatError):
        error = RpcError(
            code="invalid_pe",
            message=str(exc),
            details=dict(details),
        )
    elif isinstance(exc, AddressSyncError):
        error = RpcError(
            code=exc.code,
            message=str(exc),
            details={**details, **exc.details},
        )
    elif isinstance(exc, (IdaWorkerError, XdbgRpcError)):
        error = RpcError(
            code=exc.code,
            message=str(exc),
            details={**details, **exc.details},
            retryable=exc.retryable,
        )
    elif isinstance(exc, KeyError):
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
    else:
        error = RpcError(
            code="internal_error",
            message=f"{type(exc).__name__}: {exc}",
            details=dict(details),
        )
    return Result[JsonObject](ok=False, error=error)

"""service_ext's backend->RPC translation must forward the timeout signal.

r2, ghidra, frida and windbg all raise a ``"timeout"`` code when a tool outruns
its deadline (run_bounded, the cdb launcher, a frida call). service_ext used to
build the XdbgRpcError inline without a retryable flag, so those transient
timeouts reached the caller as permanent failures -- the same drop already
fixed in the jsre/web/device _as_rpc siblings. ``_rpc_error`` now derives
retryable from the code. A UiPidBoundaryError is a boundary/validation error
that never times out, so it stays non-retryable through the same path.
"""

from __future__ import annotations

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.backends.windbg.client import WindbgError
from headless_re_mcp.core.service_ext import _rpc_error
from headless_re_mcp.core.windows import UiPidBoundaryError


def test_rpc_error_marks_backend_timeouts_retryable() -> None:
    assert _rpc_error(R2Error("timeout", "r2 timed out")).retryable is True
    assert _rpc_error(GhidraError("timeout", "ghidra timed out")).retryable is True
    assert _rpc_error(WindbgError("timeout", "cdb timed out")).retryable is True
    assert _rpc_error(FridaError("timeout", "frida did not respond")).retryable is True


def test_rpc_error_keeps_permanent_failures_non_retryable() -> None:
    assert _rpc_error(R2Error("invalid_params", "bad command")).retryable is False
    assert _rpc_error(GhidraError("backend_error", "ghidra failed")).retryable is False
    assert _rpc_error(WindbgError("capability_unavailable", "no cdb")).retryable is False
    assert _rpc_error(FridaError("invalid_params", "bad address")).retryable is False
    # A boundary/validation error never times out; it rides the same path and
    # stays non-retryable.
    assert _rpc_error(UiPidBoundaryError("not_found", "no window")).retryable is False


def test_rpc_error_preserves_code_message_and_details() -> None:
    rpc = _rpc_error(WindbgError("timeout", "cdb timed out", timeout=30.0, killed_pids=[7]))
    assert rpc.code == "timeout"
    assert str(rpc) == "cdb timed out"
    assert rpc.details == {"timeout": 30.0, "killed_pids": [7]}

"""The canonical error envelope must name bounded outcomes, not bury them.

``_failure`` is the one place every service mixin turns an exception into an
RpcError. A caller cancel (``BoundedCancelled``) and a deadline
(``TimedOut``) are control signals from the bounded-run machinery, not
unexpected faults -- but until they were named here they fell through to the
generic branch and came back as ``internal_error`` with a logged incident.

That is exactly the miscasting the upx and net_reactor_slayer adapters each
carried until they grew their own re-raise: a caller cancel reported as a
server defect. Every current endpoint handles these before reaching
``_failure``; these tests pin the envelope itself so a path that forgets the
re-raise still answers honestly rather than filing an incident for a cancel.

Cross-platform: this is pure envelope construction, identical on POSIX and
Windows, so it runs and gates on both.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut
from headless_re_mcp.core.results import _failure
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeProcessError,
    ExeinfopeScanError,
)


def test_bounded_cancelled_is_a_clean_cancel_not_an_internal_error() -> None:
    result = _failure(BoundedCancelled([4321, 4322]), session_id="s", backend="upx")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "cancelled"
    # The whole point: a caller cancel must never be filed as an internal_error,
    # which would log a spurious incident and imply a server defect.
    assert result.error.code != "internal_error"
    assert result.error.retryable is True
    # Passed-through call details survive, and the killed tree is reported.
    assert result.error.details["session_id"] == "s"
    assert result.error.details["backend"] == "upx"
    assert result.error.details["killed_pids"] == [4321, 4322]
    # No incident id is minted for a control signal.
    assert "incident_id" not in result.error.details


def test_bounded_cancelled_with_no_killed_pids_still_reports_cleanly() -> None:
    result = _failure(BoundedCancelled())

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "cancelled"
    assert result.error.details["killed_pids"] == []


def test_timed_out_is_a_timeout_not_an_internal_error() -> None:
    result = _failure(TimedOut(30.0, [999]), session_id="s")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.code != "internal_error"
    assert result.error.retryable is True
    assert result.error.details["timeout_s"] == 30.0
    assert result.error.details["killed_pids"] == [999]
    assert "incident_id" not in result.error.details


def test_exeinfope_scan_error_keeps_its_code_like_its_die_sibling() -> None:
    """Exeinfo PE is the sibling of DIE; both reach this envelope from detect_scan.

    Only DieScanError was named here, so an ExeinfopeScanError fell through to
    internal_error -- minting an incident and hiding a structured code
    (invalid_argument, executable_not_found, timeout, process_failed) the caller
    could have acted on.
    """
    result = _failure(
        ExeinfopeScanError("invalid_argument", "bad mode", details={"mode": "weird"}),
        session_id="s",
        backend="detection",
    )

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_argument"
    assert result.error.code != "internal_error"
    assert result.error.details["session_id"] == "s"
    assert result.error.details["mode"] == "weird"
    # A structured tool error is not a server defect, so no incident is filed.
    assert "incident_id" not in result.error.details


def test_exeinfope_process_error_is_process_failed_not_internal_error() -> None:
    result = _failure(
        ExeinfopeProcessError("process_failed", "could not start Exeinfo PE: denied"),
        session_id="s",
    )

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "process_failed"
    assert result.error.code != "internal_error"
    assert "incident_id" not in result.error.details


def test_exeinfope_retryable_flag_travels_through_the_envelope() -> None:
    """The branch forwards exc.retryable; an unattended caller acts on it.

    A timeout is worth retrying (the tool was healthy, the deadline was not);
    a missing executable is not -- retrying cannot install it. Both flags are
    set at the raise site and must survive into the envelope unchanged.
    """
    from headless_re_mcp.detection.exeinfope import (
        ExeinfopeExecutableNotFoundError,
        ExeinfopeTimeoutError,
    )

    timed_out = _failure(ExeinfopeTimeoutError(30.0), session_id="s")
    assert timed_out.error is not None
    assert timed_out.error.code == "timeout"
    assert timed_out.error.retryable is True

    missing = _failure(ExeinfopeExecutableNotFoundError(Path("/opt/exeinfope")))
    assert missing.error is not None
    assert missing.error.code == "executable_not_found"
    assert missing.error.retryable is False


def test_a_genuinely_unexpected_error_is_still_an_internal_error() -> None:
    """The bounded-outcome cases must not weaken the catch-all.

    A plain exception the envelope does not recognise still becomes an
    internal_error with an incident, so a real fault is not quietly downgraded.
    """
    result = _failure(RuntimeError("something genuinely unexpected"))

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"
    assert "incident_id" in result.error.details


def _every_branch_cases() -> list[Any]:
    """One representative exception per branch of ``_failure``."""
    import sqlite3

    from headless_re_mcp.backends.ida.client import IdaWorkerError
    from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
    from headless_re_mcp.backends.x64dbg.stealth import StealthError
    from headless_re_mcp.core.addressing import AddressSyncError
    from headless_re_mcp.core.models import TargetMismatch
    from headless_re_mcp.core.session import InvalidStateTransition, SessionNotFound
    from headless_re_mcp.detection import PeFormatError
    from headless_re_mcp.detection.die import DieScanError
    from headless_re_mcp.unpack.upx import UpxScanError

    return [
        pytest.param(BoundedCancelled([1]), "cancelled", id="bounded_cancelled"),
        pytest.param(TimedOut(5.0, [1]), "timeout", id="timed_out"),
        pytest.param(DieScanError("protocol_error", "garbage"), "protocol_error", id="die"),
        pytest.param(UpxScanError("upx_failed", "boom"), "upx_failed", id="upx"),
        pytest.param(
            ExeinfopeScanError("invalid_argument", "bad mode"),
            "invalid_argument",
            id="exeinfope",
        ),
        pytest.param(PeFormatError("bad pe"), "invalid_pe", id="pe_format"),
        pytest.param(TargetMismatch("wrong kind"), "target_mismatch", id="target_mismatch"),
        pytest.param(
            AddressSyncError("va_out_of_range", "bad va"), "va_out_of_range", id="address_sync"
        ),
        pytest.param(StealthError("stealth_failed", "no"), "stealth_failed", id="stealth"),
        pytest.param(IdaWorkerError("worker_crashed", "gone"), "worker_crashed", id="ida"),
        pytest.param(XdbgRpcError("rpc_protocol_error", "junk"), "rpc_protocol_error", id="xdbg"),
        pytest.param(
            SessionNotFound("session not found: s"), "session_not_found", id="session_not_found"
        ),
        pytest.param(FileNotFoundError("missing.bin"), "file_not_found", id="file_not_found"),
        pytest.param(TimeoutError("workflow step"), "workflow_timeout", id="workflow_timeout"),
        pytest.param(
            InvalidStateTransition("cannot run while closing"),
            "invalid_request",
            id="invalid_state",
        ),
        pytest.param(ValueError("bad argument"), "invalid_request", id="value_error"),
        pytest.param(
            sqlite3.OperationalError("database is locked"),
            "storage_unavailable",
            id="sqlite_locked",
        ),
        pytest.param(RuntimeError("boom"), "internal_error", id="catch_all"),
    ]


@pytest.mark.parametrize("exc, expected_code", _every_branch_cases())
def test_every_branch_keeps_the_callers_details_and_a_stable_code(
    exc: BaseException, expected_code: str
) -> None:
    """No branch may drop the call details the service mixin passed in.

    Every mixin calls ``_failure(exc, session_id=..., backend=...)`` and the
    dashboard, the audit trail and the caller's retry logic all key off those
    fields plus a stable code. A branch that rebuilt its details dict without
    spreading ``**details`` would silently detach its error family from the
    session that produced it -- per-branch tests each pin their own family, so
    this is the one place the shape is asserted across all of them.
    """
    result = _failure(exc, session_id="s", backend="b")

    assert result.ok is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == expected_code
    assert result.error.message, "an empty message is useless to an unattended caller"
    assert result.error.details["session_id"] == "s"
    assert result.error.details["backend"] == "b"
    if expected_code != "internal_error":
        # Only the catch-all files an incident; a structured or control-signal
        # failure must never imply a server defect.
        assert "incident_id" not in result.error.details

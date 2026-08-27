"""Contract tests for the shared ``_success`` / ``_failure`` envelope helpers.

``core.results._failure`` is a precedence-ordered ``isinstance`` dispatch that
every service failure in the codebase flows through. Its own comments record a
run of past bugs where an exception was miscast into the wrong code: a caller
cancel filed as an ``internal_error`` incident, an Exeinfo PE error falling
through to ``internal_error`` while its DIE sibling was named, and a raw
``KeyError`` read as ``session_not_found`` (which tells a caller to recreate a
session that never went away). Several of the arms sit *above* the generic
``ValueError`` arm precisely because they match ``ValueError`` subclasses.

These tests pin the observable envelope -- ``(code, retryable, merged
details)`` -- for each arm so the next reorder, rename, or new exception
subclass cannot silently regress what an unattended caller reads and acts on.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut
from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.backends.x64dbg.stealth import StealthError
from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.models import RpcError, TargetMismatch
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.session import InvalidStateTransition, SessionNotFound
from headless_re_mcp.detection import PeFormatError
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.detection.exeinfope import ExeinfopeScanError
from headless_re_mcp.unpack.upx import UpxScanError


def _error(exc: BaseException, **details: object) -> RpcError:
    """Run ``_failure`` and return the ``RpcError`` after checking the envelope."""
    result = _failure(exc, **details)
    assert result.ok is False
    assert result.data is None
    assert result.error is not None
    return result.error


# --------------------------------------------------------------------------- #
# _success
# --------------------------------------------------------------------------- #


def test_success_wraps_data_and_meta() -> None:
    result = _success({"a": 1}, session="s1", count=3)
    assert result.ok is True
    assert result.error is None
    assert result.data == {"a": 1}
    assert result.meta == {"session": "s1", "count": 3}


def test_success_defaults_to_empty_meta() -> None:
    result = _success({"only": "data"})
    assert result.ok is True
    assert result.meta == {}


# --------------------------------------------------------------------------- #
# Control signals: caller cancel and deadline are not internal faults
# --------------------------------------------------------------------------- #


def test_bounded_cancelled_is_a_control_signal_not_an_incident() -> None:
    error = _error(BoundedCancelled(killed=[11, 22]), tool="upx")
    assert error.code == "cancelled"
    assert error.retryable is True
    # str(BoundedCancelled()) already carries the default text, and _failure
    # falls back to the same phrase, so the message is stable either way.
    assert error.message == "cancelled by caller"
    assert error.details["tool"] == "upx"
    assert error.details["killed_pids"] == [11, 22]


def test_bounded_cancelled_without_kills_reports_an_empty_list() -> None:
    error = _error(BoundedCancelled())
    assert error.code == "cancelled"
    assert error.details["killed_pids"] == []


def test_timed_out_carries_the_deadline_and_kills() -> None:
    error = _error(TimedOut(timeout=2.5, killed=[7]), tool="jadx")
    assert error.code == "timeout"
    assert error.retryable is True
    assert error.details["timeout_s"] == 2.5
    assert error.details["killed_pids"] == [7]
    assert error.details["tool"] == "jadx"
    assert "timed out" in error.message


# --------------------------------------------------------------------------- #
# Structured scan errors keep their own code
# --------------------------------------------------------------------------- #


def test_die_scan_retryability_is_derived_from_code_not_the_attribute() -> None:
    # The DIE arm computes retryability from the code, deliberately ignoring the
    # exception's own ``retryable`` flag: a "timeout" is retryable even when the
    # error was constructed with retryable=False.
    exc = DieScanError("timeout", "die stalled", details={"phase": "scan"}, retryable=False)
    assert exc.retryable is False
    error = _error(exc, path="/x")
    assert error.code == "timeout"
    assert error.retryable is True
    assert error.details["phase"] == "scan"
    assert error.details["path"] == "/x"


def test_die_scan_non_timeout_code_is_not_retryable() -> None:
    error = _error(DieScanError("bad_output", "garbage"))
    assert error.code == "bad_output"
    assert error.retryable is False


def test_upx_scan_error_uses_its_own_code_and_retryable_flag() -> None:
    error = _error(UpxScanError("upx_stub", "no stub", details={"n": 1}, retryable=True))
    assert error.code == "upx_stub"
    assert error.retryable is True
    assert error.details["n"] == 1


def test_exeinfope_scan_error_is_named_not_internal_error() -> None:
    # Regression guard for the bug the source comment records: this sibling of
    # DieScanError once fell through to ``internal_error`` and minted an
    # incident instead of returning its structured code.
    error = _error(ExeinfopeScanError("invalid_argument", "bad flag", retryable=False))
    assert error.code == "invalid_argument"
    assert error.retryable is False


# --------------------------------------------------------------------------- #
# ValueError subclasses must resolve before the generic ValueError arm
# --------------------------------------------------------------------------- #


def test_pe_format_error_maps_to_invalid_pe_despite_being_a_valueerror() -> None:
    exc = PeFormatError("truncated optional header")
    assert isinstance(exc, ValueError)  # documents the precedence hazard
    error = _error(exc, path="/sample.exe")
    assert error.code == "invalid_pe"
    assert error.details["path"] == "/sample.exe"


def test_address_sync_error_maps_to_its_code_despite_being_a_valueerror() -> None:
    exc = AddressSyncError("addr_desync", "rebase drift", rva=16)
    assert isinstance(exc, ValueError)
    error = _error(exc, session="s2")
    assert error.code == "addr_desync"
    assert error.details["rva"] == 16
    assert error.details["session"] == "s2"


# --------------------------------------------------------------------------- #
# Target/worker/stealth structured errors
# --------------------------------------------------------------------------- #


def test_target_mismatch_uses_its_structured_code_and_message() -> None:
    exc = TargetMismatch("cannot run on this target")
    error = _error(exc, tool="apk")
    assert error.code == "target_mismatch"
    assert error.message == "cannot run on this target"
    assert error.details["expected_targets"] == []
    assert error.details["actual_target"] is None
    assert error.details["tool"] == "apk"


def test_stealth_error_maps_to_its_code_with_default_retryable() -> None:
    error = _error(StealthError("hide_failed", "profile write failed", details={"ini": "x"}))
    assert error.code == "hide_failed"
    assert error.retryable is False
    assert error.details["ini"] == "x"


def test_ida_worker_error_carries_its_retryable_flag() -> None:
    error = _error(IdaWorkerError("ida_busy", "worker busy", retryable=True))
    assert error.code == "ida_busy"
    assert error.retryable is True


def test_xdbg_rpc_error_carries_its_retryable_flag() -> None:
    error = _error(XdbgRpcError("xdbg_gone", "pipe closed", retryable=False))
    assert error.code == "xdbg_gone"
    assert error.retryable is False


# --------------------------------------------------------------------------- #
# session_not_found is a single named type, not "any KeyError"
# --------------------------------------------------------------------------- #


def test_session_not_found_reports_the_first_arg_without_key_repr_quoting() -> None:
    # SessionNotFound subclasses KeyError; reading args[0] avoids KeyError's
    # habit of wrapping its str in quotes.
    error = _error(SessionNotFound("sess-123"))
    assert error.code == "session_not_found"
    assert error.message == "sess-123"


def test_session_not_found_without_args_uses_a_default_message() -> None:
    error = _error(SessionNotFound())
    assert error.code == "session_not_found"
    assert error.message == "session not found"


def test_a_plain_keyerror_is_an_internal_error_not_session_not_found() -> None:
    # The comment on the session_not_found arm records the bug this guards: any
    # KeyError used to be read as a missing session, telling the caller to
    # recreate a session that was never gone.
    error = _error(KeyError("some_dict_key"))
    assert error.code == "internal_error"
    assert error.details["exception_type"] == "KeyError"


# --------------------------------------------------------------------------- #
# Builtin OS/timeout/value errors
# --------------------------------------------------------------------------- #


def test_file_not_found_maps_to_file_not_found() -> None:
    error = _error(FileNotFoundError("missing.bin"))
    assert error.code == "file_not_found"


def test_builtin_timeout_error_maps_to_workflow_timeout() -> None:
    # The bounded TimedOut above and the builtin TimeoutError deliberately map
    # to different codes; TimedOut is not a subclass of TimeoutError, so the
    # earlier TimedOut arm does not swallow this one.
    assert not issubclass(TimedOut, TimeoutError)
    error = _error(TimeoutError("navigation stalled"))
    assert error.code == "workflow_timeout"
    assert error.retryable is True


def test_invalid_state_transition_and_value_error_map_to_invalid_request() -> None:
    for exc in (InvalidStateTransition("bad move"), ValueError("nope")):
        error = _error(exc)
        assert error.code == "invalid_request"
        assert error.retryable is False


# --------------------------------------------------------------------------- #
# Storage faults are distinguished from request faults
# --------------------------------------------------------------------------- #


def test_sqlite_operational_error_is_retryable_storage_unavailable() -> None:
    error = _error(sqlite3.OperationalError("database is locked"))
    assert error.code == "storage_unavailable"
    assert error.retryable is True
    assert "OperationalError" in error.message


def test_other_sqlite_errors_are_non_retryable_storage_unavailable() -> None:
    error = _error(sqlite3.DatabaseError("file is not a database"))
    assert error.code == "storage_unavailable"
    assert error.retryable is False
    assert "DatabaseError" in error.message


# --------------------------------------------------------------------------- #
# The catch-all mints an incident
# --------------------------------------------------------------------------- #


def test_unknown_exception_becomes_internal_error_with_an_incident() -> None:
    error = _error(RuntimeError("boom"), tool="whatever")
    assert error.code == "internal_error"
    assert error.retryable is False
    assert "RuntimeError" in error.message
    assert error.details["exception_type"] == "RuntimeError"
    assert isinstance(error.details["incident_id"], str)
    assert error.details["incident_id"]
    # Call-site details are merged alongside the incident fields.
    assert error.details["tool"] == "whatever"


def test_call_site_details_survive_across_a_plain_branch() -> None:
    detail: dict[str, Any] = {"session": "s9", "attempt": 2}
    error = _error(ValueError("bad"), **detail)
    assert error.details["session"] == "s9"
    assert error.details["attempt"] == 2

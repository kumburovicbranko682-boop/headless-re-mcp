"""_failure is the one place a raised exception becomes an error envelope.

Every service method funnels its except-block through it, and unattended
callers branch on the resulting ``code`` and ``retryable`` -- a storage fault
they may retry, an invalid_request they must not. The mapping is an ordered
isinstance chain; reordering it or dropping a branch silently changes the code
a caller sees. Nothing pinned the table, so pin the load-bearing rows and the
internal_error fallback's redaction.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from headless_re_mcp.core.addressing import AddressSyncError
from headless_re_mcp.core.models import TargetKind, TargetMismatch
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.session import InvalidStateTransition, SessionNotFound


def test_success_carries_data_and_meta() -> None:
    result = _success({"value": 1}, session_id="s", backend="web")
    assert result.ok is True
    assert result.data == {"value": 1}
    assert result.meta == {"session_id": "s", "backend": "web"}


def test_session_not_found_is_its_own_code_and_not_retryable() -> None:
    result = _failure(SessionNotFound("session not found: s1"), session_id="s1")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "session_not_found"
    assert result.error.retryable is False
    assert result.error.details["session_id"] == "s1"


def test_invalid_state_and_value_errors_map_to_invalid_request() -> None:
    for exc in (InvalidStateTransition("cannot run in closed state"), ValueError("bad arg")):
        result = _failure(exc)
        assert result.error is not None
        assert result.error.code == "invalid_request", type(exc).__name__
        assert result.error.retryable is False


def test_a_missing_file_maps_to_file_not_found() -> None:
    result = _failure(FileNotFoundError("no such artifact"))
    assert result.error is not None
    assert result.error.code == "file_not_found"


def test_a_timeout_is_retryable_workflow_timeout() -> None:
    result = _failure(TimeoutError("deadline"))
    assert result.error is not None
    assert result.error.code == "workflow_timeout"
    assert result.error.retryable is True


def test_a_locked_database_is_retryable_but_a_corrupt_one_is_not() -> None:
    """storage_unavailable distinguishes 'try later' from 'this will never work'."""
    locked = _failure(sqlite3.OperationalError("database is locked"))
    assert locked.error is not None
    assert locked.error.code == "storage_unavailable"
    assert locked.error.retryable is True

    corrupt = _failure(sqlite3.DatabaseError("file is not a database"))
    assert corrupt.error is not None
    assert corrupt.error.code == "storage_unavailable"
    assert corrupt.error.retryable is False


def test_domain_errors_keep_their_own_codes_and_details() -> None:
    mismatch = _failure(
        TargetMismatch("needs a PE", expected=(TargetKind.PE,), actual=TargetKind.WEB)
    )
    assert mismatch.error is not None
    assert mismatch.error.code == "target_mismatch"
    assert mismatch.error.details["expected_targets"] == ["pe"]
    assert mismatch.error.details["actual_target"] == "web"

    addr = _failure(AddressSyncError("address_out_of_range", "outside", address=0x10))
    assert addr.error is not None
    assert addr.error.code == "address_out_of_range"
    assert addr.error.details["address"] == 0x10


def test_an_unmapped_exception_becomes_a_redacted_internal_error(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """The fallback must file an incident and never echo a secret in the message."""
    import logging

    import headless_re_mcp.error_boundary as boundary

    logger = logging.getLogger("headless_re_mcp.incidents")
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    monkeypatch.setattr(boundary, "_LOG_PATH", None)
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path))

    secret = "sk-live-" + "0123456789abcdef"
    result = _failure(RuntimeError(f"upstream said api_key={secret}"))

    assert result.error is not None
    assert result.error.code == "internal_error"
    assert "incident_id" in result.error.details
    assert secret not in result.error.message
    assert "[REDACTED]" in result.error.message
    assert secret not in (tmp_path / "incidents.log").read_text(encoding="utf-8")

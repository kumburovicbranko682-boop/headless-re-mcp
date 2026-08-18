"""How a refused idalib open is described to the caller.

idalib opens a binary in place, so one sample has one database and a second
process asking for it is refused. That is a lock clearing on its own, and
telling an unattended caller it is permanent costs it the sample.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ida.client import (
    IdaWorkerError,
    next_receive_deadline,
    startup_receive_remaining,
)
from headless_re_mcp.backends.ida.worker import (
    _DATABASE_IN_USE,
    _complete_idb_exists,
    _discard_crash_idb,
    _open_database_error,
    _should_reuse_idb,
    _unpacked_idb_paths,
)


def test_a_database_held_elsewhere_is_named_and_marked_retryable() -> None:
    """Code 4 was reported as a bare number and as permanent.

    Measured with two processes cycling one fixture, 40 of 50 opens failed this
    way, and none did when the same cycles ran one after another. batch.analyze
    opens up to eight static sessions at once, so the collision is something the
    surface invites rather than an accident.
    """
    error = _open_database_error(_DATABASE_IN_USE, Path(r"C:\samples\packed.exe"))

    assert "packed.exe" in str(error), "the caller has to know which sample"
    assert "already open in another process" in str(error)
    assert getattr(error, "retryable", False) is True


def test_any_other_open_failure_keeps_its_code_and_stays_permanent() -> None:
    """Only the one condition proven transient is described as transient."""
    error = _open_database_error(1, Path("sample.exe"))

    assert "code 1" in str(error), "an unclassified failure must still name its code"
    assert getattr(error, "retryable", False) is False


def test_the_worker_envelope_carries_retryable_through_to_the_client() -> None:
    """The flag is only useful if it survives the hop out of the worker."""
    payload = {
        "code": "worker_start_failed",
        "message": "RuntimeError: the IDA database for packed.exe is already open",
        "details": {},
        "retryable": True,
    }

    parsed = IdaWorkerError.from_payload(payload)

    assert parsed.code == "worker_start_failed"
    assert parsed.retryable is True


def test_an_unpacked_id0_is_a_crash_leftover_not_a_reusable_database(tmp_path: Path) -> None:
    binary = tmp_path / "AW8.17.exe"
    binary.write_bytes(b"MZ")
    leftover = tmp_path / "AW8.17.exe.id0"
    leftover.write_bytes(b"idb")
    assert _should_reuse_idb(binary) is False
    assert leftover in _unpacked_idb_paths(binary)
    removed = _discard_crash_idb(binary)
    assert str(leftover) in removed
    assert leftover.is_file() is False


def test_a_packed_i64_is_the_only_reusable_database(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    binary.with_suffix(".i64").write_bytes(b"idb")
    assert _complete_idb_exists(binary) is True
    assert _should_reuse_idb(binary) is True
    assert _discard_crash_idb(binary) == []


def test_startup_waits_on_the_absolute_cap_when_the_worker_is_silent() -> None:
    remaining = startup_receive_remaining(
        now=100.0,
        idle_deadline=110.0,
        absolute_deadline=340.0,
        extend_on_progress=True,
    )
    assert remaining == 240.0
    idle = startup_receive_remaining(
        now=100.0,
        idle_deadline=110.0,
        absolute_deadline=340.0,
        extend_on_progress=False,
    )
    assert idle == 10.0


def test_progress_slides_the_idle_deadline_but_not_past_the_cap() -> None:
    slid = next_receive_deadline(
        now=100.0,
        deadline=110.0,
        idle_timeout=300.0,
        absolute_deadline=1000.0,
        message={"event": "progress"},
        extend_on_progress=True,
    )
    assert slid == 400.0
    capped = next_receive_deadline(
        now=100.0,
        deadline=110.0,
        idle_timeout=300.0,
        absolute_deadline=250.0,
        message={"event": "progress"},
        extend_on_progress=True,
    )
    assert capped == 250.0


def test_progress_does_not_extend_a_request_wait() -> None:
    deadline = next_receive_deadline(
        now=100.0,
        deadline=110.0,
        idle_timeout=300.0,
        absolute_deadline=1000.0,
        message={"event": "progress"},
        extend_on_progress=False,
    )
    assert deadline == 110.0


def test_non_progress_events_leave_the_deadline_alone() -> None:
    deadline = next_receive_deadline(
        now=100.0,
        deadline=110.0,
        idle_timeout=300.0,
        absolute_deadline=1000.0,
        message={"event": "ready"},
        extend_on_progress=True,
    )
    assert deadline == 110.0

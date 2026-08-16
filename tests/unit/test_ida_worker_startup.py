"""How a refused idalib open is described to the caller.

idalib opens a binary in place, so one sample has one database and a second
process asking for it is refused. That is a lock clearing on its own, and
telling an unattended caller it is permanent costs it the sample.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.ida.worker import (
    _DATABASE_IN_USE,
    _open_database_error,
    _page_items,
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


def test_a_static_page_at_the_cap_is_not_the_whole_list() -> None:
    """150 items with limit=100 used to come back as returned=100, no has_more.

    Every static.* list goes through this pager. A page sitting at the cap
    looked like the whole database, so the rest of the functions, strings or
    xrefs disappeared from whoever was supposed to walk them overnight.
    """
    items = [{"n": index} for index in range(150)]
    page = _page_items(items, 0, 100)
    assert page["returned"] == 100
    assert page["total"] == 150
    assert page["has_more"] is True
    tail = _page_items(items, 100, 100)
    assert tail["returned"] == 50
    assert tail["has_more"] is False


def test_a_static_page_that_exactly_fills_is_complete() -> None:
    items = [{"n": index} for index in range(100)]
    page = _page_items(items, 0, 100)
    assert page["returned"] == 100
    assert page["total"] == 100
    assert page["has_more"] is False

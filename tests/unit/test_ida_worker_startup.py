"""How a refused idalib open is described to the caller.

idalib opens a binary in place, so one sample has one database and a second
process asking for it is refused. That is a lock clearing on its own, and
telling an unattended caller it is permanent costs it the sample.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.ida.worker import _DATABASE_IN_USE, _open_database_error


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


class TestIdaPagedListsSayWhenTheyStopped:
    """IDA list pages had total but no has_more.

    Measured: 80 items with limit=10 came back as returned=10 and total=80,
    with no has_more, so a caller reading only the list would stop after
    the first page of xrefs, names, or search hits.
    """

    def test_hitting_the_cap_is_reported(self) -> None:
        from headless_re_mcp.backends.ida.worker import _page_items

        page = _page_items([{"i": index} for index in range(80)], 0, 10)
        assert page["returned"] == 10
        assert page["total"] == 80
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        from headless_re_mcp.backends.ida.worker import _page_items

        page = _page_items([{"i": index} for index in range(3)], 0, 10)
        assert page["has_more"] is False

    def test_the_last_page_is_not_labelled_partial(self) -> None:
        from headless_re_mcp.backends.ida.worker import _page_items

        page = _page_items([{"i": index} for index in range(80)], 70, 10)
        assert page["returned"] == 10
        assert page["has_more"] is False

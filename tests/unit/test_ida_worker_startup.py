"""How a refused idalib open is described to the caller.

idalib opens a binary in place, so one sample has one database and a second
process asking for it is refused. That is a lock clearing on its own, and
telling an unattended caller it is permanent costs it the sample.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.ida.worker import (
    _DATABASE_IN_USE,
    _bytes_read,
    _functions,
    _open_database_error,
    _page_items,
    _strings,
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


def test_a_function_page_says_what_was_left_out() -> None:
    """500 items and limit=100 came back as returned=100, total=500, no has_more."""
    result = _page_items([{"i": index} for index in range(500)], 0, 100)
    assert result["returned"] == 100
    assert result["total"] == 500
    assert result["has_more"] is True
    assert len(result["items"]) == 100


def test_the_last_function_page_is_complete() -> None:
    result = _page_items([{"i": index} for index in range(500)], 400, 100)
    assert result["returned"] == 100
    assert result["has_more"] is False


def test_a_short_byte_read_says_so(monkeypatch: Any) -> None:
    """Asked 64, got 16, truncated=False — the rest of the range vanished."""
    import sys
    import types

    ida = types.ModuleType("ida_bytes")
    ida.is_loaded = lambda addr: True  # type: ignore[attr-defined]
    ida.get_bytes = lambda addr, size: b"\x00" * 16  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_bytes", ida)
    result = _bytes_read({"address": 0x1000, "size": 64})
    assert result["size"] == 16
    assert result["requested"] == 64
    assert result["truncated"] is True
    assert len(result["hex"]) == 32


def test_a_function_list_page_says_what_was_left_out(monkeypatch: Any) -> None:
    """The live list does not use _page_items; 500/100 had total and no has_more."""
    import sys
    import types

    idautils = types.ModuleType("idautils")
    idautils.Functions = lambda: list(range(500))  # type: ignore[attr-defined]
    ida_funcs = types.ModuleType("ida_funcs")

    class Func:
        def __init__(self, ea: int) -> None:
            self.start_ea = ea
            self.end_ea = ea + 1
            self.flags = 0

    ida_funcs.get_func = lambda ea: Func(int(ea))  # type: ignore[attr-defined]
    ida_name = types.ModuleType("ida_name")
    ida_name.get_name = lambda ea: f"f{ea}"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_name", ida_name)
    result = _functions({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 500
    assert result["has_more"] is True


def test_a_string_list_page_says_what_was_left_out(monkeypatch: Any) -> None:
    import sys
    import types

    class Item:
        def __init__(self, index: int) -> None:
            self.ea = index
            self.length = 1
            self.strtype = 0

        def __str__(self) -> str:
            return f"s{self.ea}"

    idautils = types.ModuleType("idautils")
    idautils.Strings = lambda: [Item(index) for index in range(500)]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    result = _strings({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 500
    assert result["has_more"] is True


def test_a_full_byte_read_is_complete(monkeypatch: Any) -> None:
    import sys
    import types

    ida = types.ModuleType("ida_bytes")
    ida.is_loaded = lambda addr: True  # type: ignore[attr-defined]
    ida.get_bytes = lambda addr, size: b"\x00" * size  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_bytes", ida)
    result = _bytes_read({"address": 0x1000, "size": 64})
    assert result["size"] == 64
    assert result["requested"] == 64
    assert result["truncated"] is False

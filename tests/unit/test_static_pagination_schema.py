"""static.functions and static.strings must advertise the IDA worker's paging bounds."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.core import build_static_core_tools


def _props(name: str) -> dict[str, dict[str, object]]:
    handler = next(
        binding.handler
        for binding in build_static_core_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]


def _worker_source() -> str:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")


def test_static_functions_schema_advertises_the_worker_paging_bounds() -> None:
    """The catalog accepted any integer offset and limit.

    Measured: static.functions passed offset and limit straight through the
    service to the idalib worker, whose _paging rejects offset < 0 and
    limit outside 1..1000. A caller asking for limit=100000 or offset=-1
    paid a whole subprocess round-trip only to be answered invalid_argument,
    and the schema never hinted at the real range.
    """
    props = _props("static.functions")
    assert props["offset"]["minimum"] == 0
    assert props["offset"]["default"] == 0
    assert props["limit"]["minimum"] == 1
    assert props["limit"]["maximum"] == 1000
    assert props["limit"]["default"] == 100

    worker = _worker_source()
    paging = worker[worker.index("def _paging") : worker.index("return offset, limit")]
    assert "offset must be non-negative" in paging
    assert "limit must be between 1 and 1000" in paging


def test_static_strings_schema_advertises_the_worker_paging_and_length_bounds() -> None:
    """The catalog accepted any integer offset, limit and max_length.

    Measured: static.strings passed max_length straight through to the
    idalib worker, whose _strings rejects max_length outside 1..65536 on
    top of the shared _paging bounds. A caller asking for max_length far
    over the cap paid a subprocess round-trip only to be answered
    invalid_argument.
    """
    props = _props("static.strings")
    assert props["offset"]["minimum"] == 0
    assert props["limit"]["minimum"] == 1
    assert props["limit"]["maximum"] == 1000
    assert props["max_length"]["minimum"] == 1
    assert props["max_length"]["maximum"] == 65536
    assert props["max_length"]["default"] == 4096

    worker = _worker_source()
    start = worker.index("def _strings")
    strings = worker[start : worker.index("def _decompile", start)]
    assert "max_length must be between 1 and 65536" in strings

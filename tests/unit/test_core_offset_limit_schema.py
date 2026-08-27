"""Core paginated tools must bound offset (and limit) at the tool schema.

The repo-wide "refuse a negative list offset at the schema" pass reached apk.*,
web.*, artifacts.*, audit.list, timeline.list and the rest, but three core
tools were left behind:

- session.list echoed the request through list_sessions, which clamps with
  start = max(0, int(offset)) and reports that clamped start back -- so
  offset=-1 was answered as page 0 with the request under-reported, the same
  silent-undershoot every sibling now refuses outright.
- static.functions and static.strings forwarded offset/limit straight to the
  IDA worker. The worker's _paging helper already rejects a negative offset and
  a limit outside 1..1000 with invalid_argument, and _strings rejects a
  max_length outside 1..65536 -- but only after a full worker round-trip. The
  schema carried no bound at all, so the catalog advertised an unbounded limit
  and accepted negatives that the worker would then refuse.

These pin the boundary to the value the runtime already enforces, so an
out-of-range page is rejected at the MCP edge like every other paged tool
rather than one dispatch later.
"""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.core import build_core_session_tools, build_static_core_tools


def _props(builder: object, name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in builder(object())  # type: ignore[operator, arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]


def test_session_list_schema_refuses_a_negative_offset() -> None:
    """session.list accepted any integer offset; pin the lower bound to 0."""
    offset = _props(build_core_session_tools, "session.list")["offset"]
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset


def test_static_functions_schema_bounds_offset_and_limit() -> None:
    """static.functions offset >= 0 and limit in 1..1000, matching the worker."""
    props = _props(build_static_core_tools, "static.functions")
    offset = props["offset"]
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset
    limit = props["limit"]
    assert limit.get("minimum") == 1
    assert limit.get("maximum") == 1000


def test_static_strings_schema_bounds_offset_limit_and_max_length() -> None:
    """static.strings adds max_length in 1..65536, the same range _strings enforces."""
    props = _props(build_static_core_tools, "static.strings")
    offset = props["offset"]
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset
    limit = props["limit"]
    assert limit.get("minimum") == 1
    assert limit.get("maximum") == 1000
    max_length = props["max_length"]
    assert max_length.get("minimum") == 1
    assert max_length.get("maximum") == 65536

"""static.functions/static.strings/session.list must bound paging at the schema.

Every other paginated tool in the catalog -- including the sibling static.*
tools in this very module (static.segments, static.imports) -- declares
``offset: Annotated[int, Field(ge=0)]`` and ``limit: Annotated[int, Field(ge=1,
le=1000)]`` so the generated MCP schema advertises the valid page window and
rejects an out-of-range value before a backend is touched. static.functions,
static.strings and session.list were left with bare ``int`` params, so their
schema accepted any integer (including negatives and values far past what the
IDA worker will serve).

The IDA worker's ``_paging`` already refuses ``offset < 0`` and ``limit``
outside ``1..1000``, and ``_strings`` refuses ``max_length`` outside
``1..65536`` -- so the schema bound is not a new limit, it is the same limit
moved to the boundary and made visible to a schema-driven client. These tests
pin the schema to the worker's contract so the two cannot drift apart.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core.limits import MAX_STATIC_INLINE_TEXT
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.core import (
    build_core_session_tools,
    build_static_core_tools,
)


def _props(builder: Any, name: str) -> dict[str, Any]:
    handler = next(
        binding.handler
        for binding in builder(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return dict(input_schema_for(handler)["properties"])


def test_max_length_ceiling_matches_the_worker_contract() -> None:
    # The schema ceiling is derived from the same constant the worker uses, so
    # a future change to one is caught here rather than silently diverging.
    assert MAX_STATIC_INLINE_TEXT == 65536


def test_static_functions_schema_bounds_the_page_window() -> None:
    props = _props(build_static_core_tools, "static.functions")
    offset = props["offset"]
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset
    limit = props["limit"]
    assert limit.get("minimum") == 1
    assert limit.get("maximum") == 1000


def test_static_strings_schema_bounds_offset_limit_and_max_length() -> None:
    props = _props(build_static_core_tools, "static.strings")
    offset = props["offset"]
    assert offset.get("minimum") == 0
    assert "maximum" not in offset
    limit = props["limit"]
    assert limit.get("minimum") == 1
    assert limit.get("maximum") == 1000
    max_length = props["max_length"]
    assert max_length.get("type") == "integer"
    assert max_length.get("minimum") == 1
    assert max_length.get("maximum") == MAX_STATIC_INLINE_TEXT


def test_session_list_schema_refuses_a_negative_offset() -> None:
    props = _props(build_core_session_tools, "session.list")
    offset = props["offset"]
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset

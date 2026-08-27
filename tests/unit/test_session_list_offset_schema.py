"""session.list must refuse a negative page offset at the schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.core import build_core_session_tools


def _offset_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_core_session_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["offset"]


def test_session_list_schema_refuses_a_negative_offset() -> None:
    """`limit` was `Field`-bounded but `offset` was a bare `int`.

    Every sibling paginated tool (apk.classes/methods/strings, js.unpack_bundle)
    declares offset with `Field(ge=0)`; this shared session pager, the one the
    web and APK lines list their sessions through, left it open. The backend
    clamps with `max(0, int(offset))`, so a negative offset does not corrupt a
    page -- but it is silently served page zero instead of being refused, which
    is the footgun the floor exists to catch. The MCP schema should reject a
    negative offset as `invalid_params` the way the other list tools do, rather
    than clamping it out of sight.
    """
    offset = _offset_schema("session.list")
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset

"""js.unpack_bundle must refuse a negative page offset at the tool schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _offset_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_js_wasm_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["offset"]


def test_js_unpack_bundle_schema_refuses_a_negative_offset() -> None:
    """The catalog accepted a negative page offset for js.unpack_bundle alone.

    Every sibling paginated tool (apk.*, web.*, proxy.flows) already carries
    minimum 0 on offset from the repo-wide "refuse a negative list offset at
    the schema" pass; js.unpack_bundle was the one paged tool left without it.
    The webcrack client clamps with start = max(0, int(offset)) and echoes
    that clamped start back, so offset=-1 was answered as page 0 with the
    request under-reported -- a caller that asked for the negative page it
    named silently reread the first module page. Pin the boundary to the same
    minimum the rest of the surface uses.
    """
    offset = _offset_schema("js.unpack_bundle")
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset

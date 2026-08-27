"""js.unpack_bundle must refuse a negative page offset at the schema."""

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
    """js.unpack_bundle was the last paginated tool with an unconstrained offset.

    Every sibling -- apk.classes/methods/strings, web.network.list, web.scripts,
    web.wasm.list, proxy.flows -- declares offset as Field(ge=0), so the schema
    a client inspects rejects a negative page. js.unpack_bundle alone advertised
    a plain integer; the backend clamps with max(0, offset), but the advertised
    contract disagreed with the rest, so a client honouring the schema could send
    offset=-1 believing it valid. Pin the boundary to match its siblings.
    """
    offset = _offset_schema("js.unpack_bundle")
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset

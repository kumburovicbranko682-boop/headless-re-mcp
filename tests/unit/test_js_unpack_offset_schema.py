"""js.unpack_bundle must refuse a negative page offset at the schema.

Every other paginated tool -- apk.classes/methods/strings, web.network.list,
web.scripts, web.wasm.list, proxy.flows -- constrains ``offset`` with
``Field(ge=0)``, so the advertised JSON schema carries ``minimum: 0`` and a
negative offset is an ``invalid_params`` rejection at the boundary.
js.unpack_bundle was the one that declared a bare ``offset: int`` with no
minimum. The webcrack backend already clamps with ``max(0, int(offset))``, so
this is the boundary half of that guard: the tool schema should reject a
negative offset like its siblings rather than accept it and lean on the clamp.
"""

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
    offset = _offset_schema("js.unpack_bundle")
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset

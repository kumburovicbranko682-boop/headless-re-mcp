"""apk list tools must refuse a negative page offset at the schema."""

from __future__ import annotations

from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for


def _offset_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_apk_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["offset"]


def test_apk_list_schema_refuses_a_negative_offset() -> None:
    """The catalog accepted any integer offset, including negatives.

    Measured: apk.classes/methods/strings schema offset has no minimum.
    The client pages with names[offset:offset+limit], so offset=-1 is a
    tail slice (ten names, offset -1, limit 100 -> last name only), not a
    rejection. An overnight pass that undershot zero silently read the
    end of the DEX as page zero and treated has_more as the rest of the
    list.
    """
    names = [f"L{index};" for index in range(10)]
    assert names[-1 : -1 + 100] == ["L9;"]
    for name in ("apk.classes", "apk.deep_links", "apk.methods", "apk.strings"):
        offset = _offset_schema(name)
        assert offset.get("type") == "integer"
        assert offset.get("minimum") == 0
        assert "maximum" not in offset

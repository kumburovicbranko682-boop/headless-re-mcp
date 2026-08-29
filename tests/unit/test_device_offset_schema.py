"""device.packages must refuse a negative page offset at the schema.

device.packages joined the sorted-then-windowed readers: the client pages with
names[offset:offset+limit], so a negative offset would be a tail slice (a page
read from the end of the sorted package list) rather than a rejection. The
schema's ge=0 is what turns that into an honest invalid_params before the
client ever slices.
"""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.device import build_device_tools


def _offset_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_device_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["offset"]


def test_device_packages_schema_refuses_a_negative_offset() -> None:
    offset = _offset_schema("device.packages")
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset

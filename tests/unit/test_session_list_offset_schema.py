"""session.list must refuse a negative page offset at the schema."""

from __future__ import annotations

from typing import Any

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.core import build_core_session_tools


def _offset_schema() -> dict[str, Any]:
    handler = next(
        binding.handler
        for binding in build_core_session_tools(object())  # type: ignore[arg-type]
        if binding.name == "session.list"
    )
    props = input_schema_for(handler)["properties"]
    assert isinstance(props, dict)
    offset = props["offset"]
    assert isinstance(offset, dict)
    return offset


def test_session_list_schema_refuses_a_negative_offset() -> None:
    """session.list was the last protocol-independent pager without the floor.

    Every other paged reader (apk.classes/methods/strings, device.list,
    web/proxy lists, the frida probes) declares minimum 0 on offset, so a
    negative page is an invalid_params rejection. session.list left offset an
    unbounded integer: the service floors it with max(0, offset), so offset=-5
    was silently served as page zero instead of refused, which hides a caller
    that computed prev_offset - limit and undershot. The schema now carries the
    same floor its siblings do.
    """
    offset = _offset_schema()
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset
    assert offset.get("default") == 0

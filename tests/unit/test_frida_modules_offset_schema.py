"""frida.modules must expose a floored offset so its pages are reachable."""

from __future__ import annotations

from typing import Any

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools


def _props(name: str) -> dict[str, Any]:
    handler = next(
        binding.handler
        for binding in build_frida_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    props = input_schema_for(handler)["properties"]
    assert isinstance(props, dict)
    return props


def test_frida_modules_offset_is_floored_at_zero() -> None:
    """The catalog gave modules a limit but no offset at all.

    modules already reported total and has_more, yet with no offset the
    modules past the first page were unreachable -- has_more promised more
    with no way to ask for it. Add offset floored at 0 (a negative would
    slice from the tail), matching every other paged reader on the surface.
    """
    props = _props("frida.modules")
    offset = props["offset"]
    assert isinstance(offset, dict)
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert offset.get("default") == 0
    limit = props["limit"]
    assert isinstance(limit, dict)
    assert limit.get("minimum") == 1
    assert limit.get("maximum") == 256

"""Every paged non-PE tool must bound its page window at the schema.

``test_apk_offset_schema`` pinned this for the apk tools after a bare
``offset: int`` let an overnight pass undershoot zero: the client pages with
``names[offset:offset+limit]``, so ``offset=-1`` is a tail slice, not a
rejection. The same bare parameter existed on ``js.unpack_bundle`` (Web) and
``session.list`` (the session list every Web/Android session shows up in), and
nothing stopped a future paged tool from reintroducing it.

This is the surface-wide guard: for the Android, Web, device and shared
session-management tool sets, an integer ``offset`` must declare ``minimum: 0``
and an integer ``limit`` must declare ``minimum: 1`` and an upper bound, so a
hostile or fat-fingered page request is refused at the boundary rather than
silently read as a tail slice or an unbounded scan.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import BoundTool, input_schema_for
from headless_re_mcp.tools.core import build_core_session_tools
from headless_re_mcp.tools.device import build_device_tools
from headless_re_mcp.tools.frida import build_frida_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools
from headless_re_mcp.tools.proxy import build_proxy_tools
from headless_re_mcp.tools.web import build_web_tools

# The non-PE domains (Android, Web, device instrumentation) plus the shared
# session list those sessions appear in. Deliberately excludes the PE static.*
# tool sets, which are a separate line.
_NON_PE_TOOL_BUILDERS: tuple[Callable[[object], tuple[BoundTool, ...]], ...] = (
    build_core_session_tools,
    build_apk_tools,
    build_js_wasm_tools,
    build_web_tools,
    build_proxy_tools,
    build_device_tools,
    build_frida_tools,
)


def _paged_properties() -> list[tuple[str, str, dict[str, object]]]:
    """(tool name, parameter name, schema) for every offset/limit parameter."""
    found: list[tuple[str, str, dict[str, object]]] = []
    for builder in _NON_PE_TOOL_BUILDERS:
        for binding in builder(object()):  # type: ignore[arg-type]
            properties = input_schema_for(binding.handler).get("properties", {})
            for param in ("offset", "limit"):
                schema = properties.get(param)
                if isinstance(schema, dict):
                    found.append((binding.name, param, schema))
    return found


def test_paged_non_pe_tools_bound_their_window() -> None:
    paged = _paged_properties()
    # Guard against the introspection silently finding nothing and passing.
    assert any(param == "offset" for _, param, _ in paged)
    assert any(param == "limit" for _, param, _ in paged)
    for tool_name, param, schema in paged:
        # Only integer page controls are constrained here; a tool that models a
        # window differently is not forced into this shape.
        if schema.get("type") != "integer":
            continue
        if param == "offset":
            assert schema.get("minimum") == 0, (
                f"{tool_name} offset must declare minimum 0, got {schema!r}"
            )
        else:
            assert schema.get("minimum") == 1, (
                f"{tool_name} limit must declare minimum 1, got {schema!r}"
            )
            assert "maximum" in schema, (
                f"{tool_name} limit must declare an upper bound, got {schema!r}"
            )


@pytest.mark.parametrize("tool_name", ["js.unpack_bundle", "session.list"])
def test_regressed_offsets_are_now_bounded(tool_name: str) -> None:
    """Direct regression pins for the two offsets that were bare int."""
    schema = next(
        input_schema_for(binding.handler)["properties"]["offset"]
        for builder in _NON_PE_TOOL_BUILDERS
        for binding in builder(object())  # type: ignore[arg-type]
        if binding.name == tool_name
    )
    assert schema.get("type") == "integer"
    assert schema.get("minimum") == 0

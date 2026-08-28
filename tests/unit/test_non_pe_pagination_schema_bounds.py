"""Every non-PE paginated reader must bound its `limit` (and floor its `offset`).

The non-PE list readers all page: ``web.network.list`` / ``web.console`` /
``web.scripts`` / ``web.wasm.list``, ``proxy.flows``, ``apk.classes`` /
``apk.methods`` / ``apk.strings`` / ``apk.xrefs``, ``frida.modules`` /
``frida.exports`` / ``frida.applications`` / ``frida.java.classes`` /
``frida.java.methods`` and ``device.properties`` / ``device.packages``. Each
takes a caller ``limit`` (a page size), and the offset-style readers a caller
``offset``. Both are numeric caller inputs with the same exposure the ``port``
params have: the MCP path runs the pydantic schema, but the agent and
OpenAI-bridge transports call the handlers directly and skip it, so the schema
bound is the fail-fast/advertised contract while the backend clamp
(``max(1, min(int(limit), MAX))`` / ``max(0, int(offset))``) is the runtime
backstop.

This pins the schema half as a drift guard, the sibling of
test_non_pe_port_schema_bounds: it scans the whole non-PE surface and fails if
any tool exposes a ``limit`` that is not an integer with a lower bound of 1 and
some declared upper bound, or an ``offset`` that is not an integer floored at 0.
An unbounded ``limit`` is the one that matters -- it is what a transport that
skips the schema would hand straight to a reader as "return everything",
turning a page size into an unbounded fetch -- so a new paginated tool cannot
ship a bare ``int`` page size without a deliberate ceiling. ``offset`` needs
only the floor: a huge offset is safe because it slices past the end and returns
an empty page, so no upper bound is required (and none is asserted).

A third guard here pins the *documented* half of the offset contract: every
offset reader's docstring must name ``total`` / ``offset`` / ``has_more``, the
fields that keep a page which filled the limit from being read as the whole
list. That is the layer the agent actually consumes, and the class of gap this
catches is exactly the one ``apk.xrefs`` and ``frida.applications`` each shipped
with before -- an offset-less cap whose first page looked complete.
"""

from __future__ import annotations

from typing import Any, cast

from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.device import build_device_tools
from headless_re_mcp.tools.frida import build_frida_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools
from headless_re_mcp.tools.proxy import build_proxy_tools
from headless_re_mcp.tools.web import build_web_tools
from headless_re_mcp.tools.workspace import build_workspace_tools

# The same non-PE surface the port guard scans. input_schema_for reads the
# handler signature alone, so a dummy service stands in and no backend is needed.
_NON_PE_BUILDERS = (
    build_web_tools,
    build_proxy_tools,
    build_device_tools,
    build_frida_tools,
    build_apk_tools,
    build_js_wasm_tools,
    build_workspace_tools,
)


def _non_pe_param_properties(param: str) -> dict[str, dict[str, Any]]:
    """Map every non-PE tool that declares ``param`` to that param's schema."""
    found: dict[str, dict[str, Any]] = {}
    for builder in _NON_PE_BUILDERS:
        for bound in builder(cast(Any, object())):
            schema = input_schema_for(bound.handler)
            prop = schema.get("properties", {}).get(param)
            if prop is not None:
                found[bound.name] = prop
    return found


def _non_pe_offset_tool_docstrings() -> dict[str, str]:
    """Map every non-PE tool that declares ``offset`` to its normalized docstring."""
    found: dict[str, str] = {}
    for builder in _NON_PE_BUILDERS:
        for bound in builder(cast(Any, object())):
            schema = input_schema_for(bound.handler)
            if "offset" in schema.get("properties", {}):
                found[bound.name] = " ".join((bound.handler.__doc__ or "").split())
    return found


def test_every_non_pe_limit_param_is_bounded() -> None:
    limits = _non_pe_param_properties("limit")

    # The scan must see paginated readers from every backend that has them --
    # otherwise a broken enumeration would make this guard vacuously pass.
    assert {
        "web.network.list",
        "proxy.flows",
        "apk.classes",
        "frida.modules",
        "device.properties",
    } <= set(limits), f"expected the known paginated readers in the scan, saw {sorted(limits)}"

    for name, limit in limits.items():
        # A page size is an integer floored at 1 (0 or negative is not a page)
        # with a declared ceiling. A new reader that forgets the ceiling (a bare
        # int -> no maximum) trips here, because that is the value a transport
        # skipping the schema would treat as an unbounded fetch.
        assert limit.get("type") == "integer", f"{name}: limit must be an integer, got {limit}"
        assert limit.get("minimum") == 1, (
            f"{name}: limit minimum must be 1, got {limit.get('minimum')}"
        )
        maximum = limit.get("maximum")
        assert isinstance(maximum, int) and maximum >= 1, (
            f"{name}: limit must declare a positive maximum, got {maximum}"
        )


def test_every_non_pe_offset_param_is_floored_at_zero() -> None:
    offsets = _non_pe_param_properties("offset")

    # The offset-style readers span web / proxy / apk; seeing one from each keeps
    # this from passing vacuously if the enumeration breaks.
    assert {
        "web.network.list",
        "proxy.flows",
        "apk.classes",
    } <= set(offsets), f"expected the known offset readers in the scan, saw {sorted(offsets)}"

    for name, offset in offsets.items():
        # An integer floored at 0. No upper bound is required: a huge offset
        # slices past the end and yields an empty page, so it cannot be abused
        # the way an unbounded limit can.
        assert offset.get("type") == "integer", f"{name}: offset must be an integer, got {offset}"
        assert offset.get("minimum") == 0, (
            f"{name}: offset minimum must be 0, got {offset.get('minimum')}"
        )


def test_every_non_pe_offset_reader_documents_the_honest_page_fields() -> None:
    """An offset reader's docstring must name ``total``, ``offset`` and ``has_more``.

    The two guards above pin that ``offset`` is *bounded*; this pins that the tool
    tells the agent the page is *honest*. Every offset reader returns an envelope
    with ``total`` (how many exist), ``offset`` (where this page starts) and
    ``has_more`` (whether a further page still has rows) -- the fields that keep a
    page which filled the limit from being read as the whole list. This is the
    contract the agent actually consumes when it decides "these are all of them",
    so a docstring that describes a page without them is the dishonest-page gap
    itself: ``apk.xrefs`` and ``frida.applications`` each shipped, earlier, as an
    offset-less cap whose first page looked complete, and the fix in both was
    exactly these fields. A new offset reader that documents a page but not its
    ``total`` / ``has_more`` trips here, at the layer the agent reads -- alongside
    the schema guard (offset is bounded) and each backend's envelope test (the
    fields are really returned), the three together pin bound + promise + payload.
    """
    docs = _non_pe_offset_tool_docstrings()

    # Non-vacuous: the offset readers span web / proxy / apk / frida, and the two
    # that motivated this guard must be in the scan -- a broken enumeration would
    # otherwise make the check pass by finding nothing to check.
    assert {
        "web.network.list",
        "proxy.flows",
        "apk.classes",
        "apk.xrefs",
        "frida.applications",
    } <= set(docs), f"expected the known offset readers in the scan, saw {sorted(docs)}"

    missing: dict[str, list[str]] = {}
    for name, doc in docs.items():
        absent = [field for field in ("total", "offset", "has_more") if field not in doc]
        if absent:
            missing[name] = absent
    assert missing == {}, (
        f"offset readers whose docstring omits an honest-page field: {missing}"
    )

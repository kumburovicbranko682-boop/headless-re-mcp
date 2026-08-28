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

A fourth guard generalises the ``limit`` ceiling to *every* numeric caller
input, whatever it is named. The by-name ``limit`` guard could not see
``device.logcat``'s ``lines`` -- a page size called something else -- which is
why that one needed its own dedicated bounds test; this scans all integer /
number params so the next such escapee (``depth``, ``count``, ``rows`` ...)
trips the general guard rather than shipping unbounded until someone notices.
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


def _non_pe_numeric_params() -> dict[tuple[str, str], dict[str, Any]]:
    """Map every ``(tool, param)`` whose schema type is integer/number to its schema."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for builder in _NON_PE_BUILDERS:
        for bound in builder(cast(Any, object())):
            schema = input_schema_for(bound.handler)
            for param, prop in schema.get("properties", {}).items():
                if prop.get("type") in ("integer", "number"):
                    found[(bound.name, param)] = prop
    return found


# (tool, param) numeric inputs that legitimately carry no upper bound. Kept as a
# fail-closed allowlist keyed by the exact pair, not the bare name: a *new*
# unbounded numeric param -- even one reusing "address" on another tool -- trips
# the guard until it is added here with a reason, which is the deliberate
# decision we want rather than a silent pass.
_UNBOUNDED_NUMERIC_OK = frozenset(
    {
        # A raw debuggee memory address spans the whole address space, so a
        # maximum is meaningless (the backend validates reachability, not
        # magnitude). Debuggee-scoped, but the frida surface is scanned whole.
        ("frida.memory.read", "address"),
    }
)


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


def test_every_non_pe_numeric_param_declares_an_upper_bound() -> None:
    """Every integer/number parameter on a non-PE tool must cap its maximum.

    The two guards above pin ``limit`` and ``offset`` by name; this generalises
    to the next numeric caller input whatever it is called. A page-size- or
    resource-shaped number with no ceiling is what a transport skipping the
    schema hands a backend as "give me everything": billions of rows, a
    10^9-second timeout, a 4 GiB logcat. ``device.logcat``'s ``lines`` escaped
    the by-name guards for exactly this reason -- it is not called ``limit`` --
    and only a dedicated test caught it; this catches the class, not the instance.

    ``offset`` is excluded by rule: it is floored at 0 and unbounded above by
    design (you page until has_more is false, so a ceiling would strand the
    tail), and it is pinned positively by the offset guard above. The only other
    exception is the explicit, fail-closed ``_UNBOUNDED_NUMERIC_OK`` allowlist
    for a raw memory address, whose magnitude is not the thing to bound.
    """
    numeric = _non_pe_numeric_params()

    # Non-vacuous: the scan must reach numeric params across several backends,
    # including the resource-shaped ones that are not named ``limit`` -- a broken
    # enumeration would otherwise pass by finding nothing to check.
    assert {
        ("device.logcat", "lines"),
        ("frida.memory.read", "size"),
        ("proxy.start", "port"),
        ("web.wait", "timeout"),
        ("apk.classes", "limit"),
    } <= set(numeric), f"the numeric-param scan looks broken, saw {sorted(numeric)}"

    unbounded: list[tuple[str, str]] = []
    for (tool, param), prop in numeric.items():
        if param == "offset":
            continue  # floored at 0, unbounded above by design (see the offset guard)
        if (tool, param) in _UNBOUNDED_NUMERIC_OK:
            continue
        if not isinstance(prop.get("maximum"), (int, float)):
            unbounded.append((tool, param))
    assert unbounded == [], (
        "these non-PE numeric params declare no maximum, so a transport skipping "
        "the schema could hand a backend an absurd value as a page size or "
        f"resource bound: {sorted(unbounded)}"
    )

"""A non-PE paged tool's advertised ``limit`` maximum must equal the cap the
backend actually enforces.

Every non-PE list endpoint carries a ``limit`` (or, for ``device.logcat``,
``lines``) bounded in its schema -- ``Field(ge=1, le=N)`` -- and every backend
independently re-clamps that value with ``max(1, min(limit, _MAX_...))``. The
re-clamp exists because the agent and OpenAI-bridge transports call handlers
directly and skip the pydantic schema (only the MCP path runs it), so a backend
that trusted the schema alone would hand an unbounded page to a transport that
bypassed it -- the same reason ``apk._clamp_page`` and ``ghidra._MAX_LIST_PAGE``
grew their guards.

That leaves two numbers per tool that must agree: the schema ceiling an agent
reads to decide how large a page to request, and the constant the backend
clamps to. If they drift, the tool silently misleads: a schema raised to 4000
against a backend still capped at 2000 tells the agent it can pull 4000 rows in
one page when it never will (the extra rows read as absent, or force needless
extra offset paging); a backend cap raised past a stale schema wastes capacity
the agent is told it cannot use. The apk, ghidra and jsre backends all carry a
comment promising their cap is "kept equal to the schema", but nothing enforced
it. This test does, for the whole non-PE surface, and fails if a new paged tool
appears without being accounted for here.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.adb.client import (
    _MAX_LOGCAT_LINES,
    _MAX_PACKAGES,
    _MAX_PROPERTIES,
)
from headless_re_mcp.backends.apk.client import (
    _MAX_CLASSES_PAGE,
    _MAX_METHODS_PAGE,
    _MAX_STRINGS_PAGE,
    _MAX_XREFS_PAGE,
)
from headless_re_mcp.backends.frida.client import (
    _MAX_APPLICATIONS_PAGE,
    _MAX_EXPORTS_PAGE,
    _MAX_JAVA_PAGE,
    _MAX_MODULES_PAGE,
)
from headless_re_mcp.backends.ghidra.client import _MAX_LIST_PAGE
from headless_re_mcp.backends.jsre.client import _MAX_LISTED_FILES
from headless_re_mcp.backends.proxy.client import _MAX_FLOWS_PAGE
from headless_re_mcp.backends.web.client import _MAX_CONSOLE, _MAX_PAGE
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog

# tool name -> (schema parameter, the backend constant it must equal). Each
# constant is imported straight from the backend that clamps with it, so a
# change on either side (schema ceiling or backend cap) breaks the equality.
_EXPECTED: dict[str, tuple[str, int]] = {
    "web.network.list": ("limit", _MAX_PAGE),
    "web.console": ("limit", _MAX_CONSOLE),
    "web.scripts": ("limit", _MAX_PAGE),
    "web.wasm.list": ("limit", _MAX_PAGE),
    "web.har.read": ("limit", _MAX_PAGE),
    "proxy.flows": ("limit", _MAX_FLOWS_PAGE),
    "frida.modules": ("limit", _MAX_MODULES_PAGE),
    "frida.exports": ("limit", _MAX_EXPORTS_PAGE),
    "frida.applications": ("limit", _MAX_APPLICATIONS_PAGE),
    "frida.java.classes": ("limit", _MAX_JAVA_PAGE),
    "frida.java.methods": ("limit", _MAX_JAVA_PAGE),
    "apk.classes": ("limit", _MAX_CLASSES_PAGE),
    "apk.methods": ("limit", _MAX_METHODS_PAGE),
    "apk.strings": ("limit", _MAX_STRINGS_PAGE),
    "apk.xrefs": ("limit", _MAX_XREFS_PAGE),
    "js.unpack_bundle": ("limit", _MAX_LISTED_FILES),
    "ghidra.functions": ("limit", _MAX_LIST_PAGE),
    "ghidra.symbols": ("limit", _MAX_LIST_PAGE),
    "ghidra.xrefs": ("limit", _MAX_LIST_PAGE),
    "device.properties": ("limit", _MAX_PROPERTIES),
    "device.packages": ("limit", _MAX_PACKAGES),
    "device.logcat": ("lines", _MAX_LOGCAT_LINES),
}

_NON_PE_PREFIXES = (
    "apk.",
    "device.",
    "frida.",
    "js.",
    "wasm.",
    "proxy.",
    "web.",
    "r2.",
    "ghidra.",
)

# The paging parameters this rule governs. ``size`` (frida.memory.read) and
# ``count`` (r2.disasm) are deliberately excluded: they name an exact quantity
# the caller wants, so their backends *reject* an out-of-range value rather than
# silently clamp it to a page cap, a different contract from the list endpoints.
_PAGING_PARAMS = ("limit", "lines")


def _discover_paged_tools() -> dict[str, tuple[str, int, int]]:
    """Map each non-PE tool with a bounded paging parameter to (param, min, max)."""
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        found: dict[str, tuple[str, int, int]] = {}
        for binding in bindings:
            if not binding.name.startswith(_NON_PE_PREFIXES):
                continue
            spec = catalog.require(binding.name)
            props = (spec.input_schema or {}).get("properties") or {}
            for param in _PAGING_PARAMS:
                prop = props.get(param)
                if not isinstance(prop, dict):
                    continue
                maximum = prop.get("maximum")
                if maximum is None:
                    continue
                found[binding.name] = (param, int(prop.get("minimum", 1)), int(maximum))
                break
        return found
    finally:
        analysis.close_all()


_DISCOVERED = _discover_paged_tools()


def test_discovery_found_the_representative_paged_surface() -> None:
    # Guards against the equality test passing vacuously if binding or schema
    # extraction ever stops surfacing these parameters.
    names = set(_DISCOVERED)
    assert {
        "web.network.list",
        "frida.modules",
        "apk.classes",
        "ghidra.functions",
        "device.logcat",
    } <= names, sorted(names)


def test_every_non_pe_paged_tool_is_accounted_for() -> None:
    """No non-PE paging cap may be added or renamed without landing in the map,
    so the alignment invariant cannot quietly skip a new endpoint."""
    discovered = set(_DISCOVERED)
    expected = set(_EXPECTED)
    missing = discovered - expected
    assert not missing, (
        f"these non-PE tools advertise a paging limit but are not pinned here: "
        f"{sorted(missing)}. Add each to _EXPECTED with the backend cap it clamps to."
    )
    stale = expected - discovered
    assert not stale, (
        f"these tools are pinned but no longer expose a paging limit: {sorted(stale)}. "
        "Remove them from _EXPECTED (or restore the parameter)."
    )


@pytest.mark.parametrize(
    ("name", "param", "cap"),
    [(name, param, cap) for name, (param, cap) in _EXPECTED.items()],
    ids=list(_EXPECTED),
)
def test_advertised_limit_maximum_equals_the_backend_cap(
    name: str, param: str, cap: int
) -> None:
    assert name in _DISCOVERED, f"{name} no longer exposes a paging parameter"
    discovered_param, minimum, maximum = _DISCOVERED[name]
    assert discovered_param == param, (
        f"{name} pages on {discovered_param!r}, not the pinned {param!r}"
    )
    assert maximum == cap, (
        f"{name}.{param} advertises a maximum of {maximum} but its backend clamps to "
        f"{cap}. An agent asking for {maximum} would only ever get {cap} rows. Keep the "
        f"schema `le=` and the backend cap equal (see the backend's _MAX_* constant)."
    )
    assert minimum == 1, (
        f"{name}.{param} advertises a minimum of {minimum}; the non-PE paging contract "
        "is ge=1 (the backends clamp with max(1, ...))."
    )

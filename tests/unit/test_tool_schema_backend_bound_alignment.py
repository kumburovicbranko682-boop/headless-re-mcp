"""Every non-PE numeric schema ceiling must equal the bound its backend enforces.

Two families of caller-supplied number are advertised by a tool schema and then
re-enforced by the backend, because the agent transport bypasses the schema and
calls the service directly:

* ``timeout`` -- each CLI/browser backend clamps to a named constant:
  r2/ghidra/jsre/jadx/apktool through ``clamp_cli_timeout(maximum=_MAX_TIMEOUT_S)``
  (jsre also ``_MAX_UNPACK_TIMEOUT_S`` for ``js.unpack_bundle``), web through
  ``_bound_nav_timeout`` and ``_MAX_NAV_TIMEOUT_S``. The schema advertises
  ``0 < timeout <= le``. A schema clamped below the backend makes the agent time
  out earlier than it asked; above it, the backend silently shortens the deadline.

* ``limit`` -- each paginated reader clamps rows per page to a named cap
  (``_MAX_PAGE``/``_MAX_CONSOLE`` for web, ``_MAX_FLOWS_PAGE`` for proxy,
  ``_MAX_*_PAGE`` for apk, ``_MAX_LISTED_FILES`` for jsre, ``_MAX_LIST_PAGE`` for
  ghidra, ``_MAX_{MODULES,EXPORTS,APPLICATIONS,JAVA}_PAGE`` for frida,
  ``_MAX_PROPERTIES``/``_MAX_PACKAGES`` for adb). The schema advertises
  ``1 <= limit <= le``. When the schema ``le`` exceeds the backend cap an agent
  asks for a page the backend silently trims; ``has_more`` keeps the paging
  correct, but the requested page size is not honoured, contradicting the tool
  contract.

The per-backend clamp tests prove each backend clamps to *its own* constant, but
nothing checks that the schema the agent reads advertises the *same* number. So a
schema ``le`` bumped without the backend constant (or the reverse) passes every
existing test while drifting from what is enforced. This pins each advertised
ceiling to the enforced one -- read from the real generated JSON schema and the
live backend constant -- so drift is a failing test, not a field surprise. Both
maps are self-auditing: a new non-PE tool exposing ``timeout`` or ``limit`` must
be added to the matching map or its coverage test fails.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import client as adb_mod
from headless_re_mcp.backends.apk import client as apk_mod
from headless_re_mcp.backends.apktool import client as apktool_mod
from headless_re_mcp.backends.frida import client as frida_mod
from headless_re_mcp.backends.ghidra import client as ghidra_mod
from headless_re_mcp.backends.jadx import client as jadx_mod
from headless_re_mcp.backends.jsre import client as jsre_mod
from headless_re_mcp.backends.proxy import client as proxy_mod
from headless_re_mcp.backends.r2 import client as r2_mod
from headless_re_mcp.backends.web import client as web_mod
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.device import build_device_tools
from headless_re_mcp.tools.frida import build_frida_tools
from headless_re_mcp.tools.ghidra import build_ghidra_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools
from headless_re_mcp.tools.proxy import build_proxy_tools
from headless_re_mcp.tools.r2 import build_r2_tools
from headless_re_mcp.tools.web import build_web_tools

# tool name -> the live backend constant its timeout ceiling must equal. Each apk
# tool is tied to its own backend: decompile/export_sources are jadx, and
# decode/repack/sign are apktool, so a change to one does not silently license
# the other.
_EXPECTED_TIMEOUT_CEILING: dict[str, float] = {
    "r2.info": r2_mod._MAX_TIMEOUT_S,
    "r2.open": r2_mod._MAX_TIMEOUT_S,
    "r2.functions": r2_mod._MAX_TIMEOUT_S,
    "r2.strings": r2_mod._MAX_TIMEOUT_S,
    "r2.imports": r2_mod._MAX_TIMEOUT_S,
    "r2.exports": r2_mod._MAX_TIMEOUT_S,
    "r2.disasm": r2_mod._MAX_TIMEOUT_S,
    "r2.xrefs": r2_mod._MAX_TIMEOUT_S,
    "ghidra.analyze": ghidra_mod._MAX_TIMEOUT_S,
    "ghidra.functions": ghidra_mod._MAX_TIMEOUT_S,
    "ghidra.symbols": ghidra_mod._MAX_TIMEOUT_S,
    "ghidra.xrefs": ghidra_mod._MAX_TIMEOUT_S,
    "ghidra.decompile": ghidra_mod._MAX_TIMEOUT_S,
    "js.deobfuscate": jsre_mod._MAX_TIMEOUT_S,
    "js.beautify": jsre_mod._MAX_TIMEOUT_S,
    "wasm.wat": jsre_mod._MAX_TIMEOUT_S,
    "wasm.info": jsre_mod._MAX_TIMEOUT_S,
    "js.unpack_bundle": jsre_mod._MAX_UNPACK_TIMEOUT_S,
    "apk.decompile": jadx_mod._MAX_TIMEOUT_S,
    "apk.export_sources": jadx_mod._MAX_TIMEOUT_S,
    "apk.decode": apktool_mod._MAX_TIMEOUT_S,
    "apk.repack": apktool_mod._MAX_TIMEOUT_S,
    "apk.sign": apktool_mod._MAX_TIMEOUT_S,
    "web.open": web_mod._MAX_NAV_TIMEOUT_S,
    "web.navigate": web_mod._MAX_NAV_TIMEOUT_S,
}

# tool name -> the live backend page cap its limit ceiling must equal.
_EXPECTED_LIMIT_CEILING: dict[str, float] = {
    "proxy.flows": proxy_mod._MAX_FLOWS_PAGE,
    "web.network.list": web_mod._MAX_PAGE,
    "web.scripts": web_mod._MAX_PAGE,
    "web.wasm.list": web_mod._MAX_PAGE,
    "web.har.read": web_mod._MAX_PAGE,
    "web.console": web_mod._MAX_CONSOLE,
    "apk.classes": apk_mod._MAX_CLASSES_PAGE,
    "apk.methods": apk_mod._MAX_METHODS_PAGE,
    "apk.strings": apk_mod._MAX_STRINGS_PAGE,
    "apk.xrefs": apk_mod._MAX_XREFS_PAGE,
    "js.unpack_bundle": jsre_mod._MAX_LISTED_FILES,
    "ghidra.functions": ghidra_mod._MAX_LIST_PAGE,
    "ghidra.symbols": ghidra_mod._MAX_LIST_PAGE,
    "ghidra.xrefs": ghidra_mod._MAX_LIST_PAGE,
    "frida.modules": frida_mod._MAX_MODULES_PAGE,
    "frida.exports": frida_mod._MAX_EXPORTS_PAGE,
    "frida.applications": frida_mod._MAX_APPLICATIONS_PAGE,
    "frida.java.classes": frida_mod._MAX_JAVA_PAGE,
    "frida.java.methods": frida_mod._MAX_JAVA_PAGE,
    "device.properties": adb_mod._MAX_PROPERTIES,
    "device.packages": adb_mod._MAX_PACKAGES,
}

_FACTORIES = (
    build_r2_tools,
    build_ghidra_tools,
    build_js_wasm_tools,
    build_apk_tools,
    build_web_tools,
    build_proxy_tools,
    build_device_tools,
    build_frida_tools,
)


@pytest.fixture(scope="module")
def tool_schema_props() -> Iterator[dict[str, dict[str, Any]]]:
    """The generated JSON-schema ``properties`` map for every non-PE tool."""
    with tempfile.TemporaryDirectory() as tmp:
        svc = AnalysisService(
            replace(Settings.load(), artifact_root=Path(tmp) / "artifacts")
        )
        try:
            props_by_tool: dict[str, dict[str, Any]] = {}
            for factory in _FACTORIES:
                for binding in factory(svc):
                    props_by_tool[binding.name] = (
                        input_schema_for(binding.handler).get("properties") or {}
                    )
            yield props_by_tool
        finally:
            svc.close_all()


def _bounded_nodes(
    props_by_tool: dict[str, dict[str, Any]], param: str
) -> dict[str, dict[str, Any]]:
    """Every tool's ``param`` schema node that declares a ``maximum`` ceiling."""
    nodes: dict[str, dict[str, Any]] = {}
    for name, props in props_by_tool.items():
        node = props.get(param)
        if isinstance(node, dict) and "maximum" in node:
            nodes[name] = node
    return nodes


@pytest.mark.parametrize("name", sorted(_EXPECTED_TIMEOUT_CEILING))
def test_the_timeout_schema_ceiling_equals_the_backend_constant(
    name: str, tool_schema_props: dict[str, dict[str, Any]]
) -> None:
    # KeyError here means a mapped tool lost its timeout parameter -- also drift
    # worth catching, not a test bug to paper over.
    node = _bounded_nodes(tool_schema_props, "timeout")[name]
    assert node["maximum"] == _EXPECTED_TIMEOUT_CEILING[name], (
        f"{name} advertises timeout<= {node['maximum']} but its backend clamps to "
        f"{_EXPECTED_TIMEOUT_CEILING[name]}; the schema and the enforced ceiling drifted"
    )
    # gt=0 in the schema mirrors every backend rejecting a non-positive deadline
    # (clamp_cli_timeout raises InvalidTimeout, _bound_nav_timeout raises WebError).
    assert node.get("exclusiveMinimum") == 0


def test_every_non_pe_timeout_tool_is_pinned(
    tool_schema_props: dict[str, dict[str, Any]]
) -> None:
    # Self-audit: the set of tools that actually expose a timeout must be exactly
    # the set this contract pins. A new non-PE tool with a timeout has to be added
    # here (and given the right backend ceiling) rather than drift unchecked.
    assert set(_bounded_nodes(tool_schema_props, "timeout")) == set(
        _EXPECTED_TIMEOUT_CEILING
    )


@pytest.mark.parametrize("name", sorted(_EXPECTED_LIMIT_CEILING))
def test_the_limit_schema_ceiling_equals_the_backend_cap(
    name: str, tool_schema_props: dict[str, dict[str, Any]]
) -> None:
    node = _bounded_nodes(tool_schema_props, "limit")[name]
    assert node["maximum"] == _EXPECTED_LIMIT_CEILING[name], (
        f"{name} advertises limit<= {node['maximum']} but its backend clamps pages to "
        f"{_EXPECTED_LIMIT_CEILING[name]}; the schema and the enforced cap drifted"
    )
    # ge=1 in the schema mirrors every reader's ``max(1, min(limit, cap))`` floor:
    # a page of at least one row, never zero or negative.
    assert node.get("minimum") == 1


def test_every_non_pe_limit_tool_is_pinned(
    tool_schema_props: dict[str, dict[str, Any]]
) -> None:
    # Self-audit: the set of tools that expose a limit must be exactly the set
    # this contract pins, so a new paginated non-PE tool cannot drift unchecked.
    assert set(_bounded_nodes(tool_schema_props, "limit")) == set(
        _EXPECTED_LIMIT_CEILING
    )

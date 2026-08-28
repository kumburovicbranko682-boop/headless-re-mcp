"""Every non-PE timeout schema must equal the ceiling its backend enforces.

Each non-PE CLI/browser backend clamps a caller-supplied timeout to a named
constant -- r2/ghidra/jsre/jadx/apktool through
``clamp_cli_timeout(maximum=_MAX_TIMEOUT_S)`` (jsre also ``_MAX_UNPACK_TIMEOUT_S``
for ``js.unpack_bundle``), web through ``_bound_nav_timeout`` and
``_MAX_NAV_TIMEOUT_S``. The matching tool schema advertises ``0 < timeout <= le``
to the agent. The two are kept equal by hand and documented only in a comment
beside each constant ("matches the X tool schema le=Y").

``test_cli_adapter_timeout_bounds.py`` proves each backend clamps to *its own*
constant, but nothing checks that the tool schema the agent reads advertises the
*same* number. So a schema ``le`` bumped without the backend constant (or the
reverse) passes every existing test while an agent sends a schema-valid timeout
that the backend then silently clamps down to a smaller value, or the backend
advertises headroom the schema forbids. This pins the advertised ceiling to the
enforced one -- read from the real generated JSON schema and the live backend
constant -- so drift is a failing test, not a field surprise. It is
self-auditing: a new non-PE tool that exposes a timeout must be added to the map
or the coverage test fails.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_mod
from headless_re_mcp.backends.ghidra import client as ghidra_mod
from headless_re_mcp.backends.jadx import client as jadx_mod
from headless_re_mcp.backends.jsre import client as jsre_mod
from headless_re_mcp.backends.r2 import client as r2_mod
from headless_re_mcp.backends.web import client as web_mod
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ghidra import build_ghidra_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools
from headless_re_mcp.tools.r2 import build_r2_tools
from headless_re_mcp.tools.web import build_web_tools

# tool name -> the live backend constant its schema ceiling must equal. Each apk
# tool is tied to its own backend: decompile/export_sources are jadx, and
# decode/repack/sign are apktool, so a change to one does not silently license
# the other.
_EXPECTED_CEILING: dict[str, float] = {
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

_FACTORIES = (
    build_r2_tools,
    build_ghidra_tools,
    build_js_wasm_tools,
    build_apk_tools,
    build_web_tools,
)


@pytest.fixture(scope="module")
def timeout_schema_nodes() -> Iterator[dict[str, dict[str, Any]]]:
    """The generated ``timeout`` JSON-schema node for every non-PE tool that has one."""
    with tempfile.TemporaryDirectory() as tmp:
        svc = AnalysisService(
            replace(Settings.load(), artifact_root=Path(tmp) / "artifacts")
        )
        try:
            nodes: dict[str, dict[str, Any]] = {}
            for factory in _FACTORIES:
                for binding in factory(svc):
                    props = input_schema_for(binding.handler).get("properties") or {}
                    node = props.get("timeout")
                    if isinstance(node, dict) and "maximum" in node:
                        nodes[binding.name] = node
            yield nodes
        finally:
            svc.close_all()


@pytest.mark.parametrize("name", sorted(_EXPECTED_CEILING))
def test_the_schema_ceiling_equals_the_backend_constant(
    name: str, timeout_schema_nodes: dict[str, dict[str, Any]]
) -> None:
    # KeyError here means a mapped tool lost its timeout parameter -- also drift
    # worth catching, not a test bug to paper over.
    node = timeout_schema_nodes[name]
    assert node["maximum"] == _EXPECTED_CEILING[name], (
        f"{name} advertises timeout<= {node['maximum']} but its backend clamps to "
        f"{_EXPECTED_CEILING[name]}; the schema and the enforced ceiling drifted"
    )
    # gt=0 in the schema mirrors every backend rejecting a non-positive deadline
    # (clamp_cli_timeout raises InvalidTimeout, _bound_nav_timeout raises WebError).
    assert node.get("exclusiveMinimum") == 0


def test_every_non_pe_timeout_tool_is_pinned(
    timeout_schema_nodes: dict[str, dict[str, Any]]
) -> None:
    # Self-audit: the set of tools that actually expose a timeout must be exactly
    # the set this contract pins. A new non-PE tool with a timeout has to be added
    # here (and given the right backend ceiling) rather than drift unchecked.
    assert set(timeout_schema_nodes) == set(_EXPECTED_CEILING)

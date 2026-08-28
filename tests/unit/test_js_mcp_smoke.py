"""End-to-end smoke test for the pure-Python js.* scanners through the MCP wiring.

test_js_scan_invariants.py drives the scan_js_* backend functions directly. This
test instead exercises the layers stacked on top of them: the
AnalysisService.js_* methods (which wrap each scanner in JsReError handling and a
success/failure Result) and the bound tool handlers (which serialize that Result
envelope for the transport). The static catalog test only checks that a handler
*names* the right service method; here each one is actually executed on a real
source file and on a missing path, so a broken wiring -- wrong argument passing, a
mismatched error code, a serialization fault -- is caught rather than shipped.

The three webcrack-backed js.* tools (js.beautify / js.deobfuscate /
js.unpack_bundle) are excluded: they shell out to Node, which this test does not
assume is installed. A newly added node-free scanner that is not registered below
trips the coverage assertion.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog

# One source that exercises all five scanners: string literals for js.strings, a
# schemed URL for js.endpoints, an ESM import and a require for js.imports, a
# line and block comment for js.comments, and a fetch call for js.capabilities.
_SOURCE = """// entry point of the app
import React from 'react';
const http = require('http');
/* configuration block */
const endpoint = 'https://api.example.com/v1/status';
const label = "dashboard-widget";
fetch(endpoint);
"""

# (service method, the key its payload must carry, extra kwargs beyond path).
_SERVICE_CASES: tuple[tuple[str, str, dict[str, int]], ...] = (
    ("js_strings", "strings", {}),
    ("js_endpoints", "endpoints", {}),
    ("js_secrets", "secrets", {}),
    ("js_imports", "imports", {}),
    ("js_comments", "comments", {}),
    ("js_capabilities", "capabilities", {}),
    ("js_summary", "capabilities", {}),
)

# The payload key each dotted tool name must return. Keyed by the public tool
# name so a newly added node-free scanner shows up as a coverage gap here.
_TOOL_KEYS: dict[str, str] = {
    "js.strings": "strings",
    "js.endpoints": "endpoints",
    "js.secrets": "secrets",
    "js.imports": "imports",
    "js.comments": "comments",
    "js.capabilities": "capabilities",
    "js.summary": "capabilities",
}

# Shell out to Node, so out of scope for a wiring smoke that assumes no Node.
_NODE_TOOLS = {"js.beautify", "js.deobfuscate", "js.unpack_bundle"}


@pytest.fixture()
def source(tmp_path: Path) -> Path:
    target = tmp_path / "app.js"
    target.write_text(_SOURCE, encoding="utf-8")
    return target


@pytest.fixture()
def analysis() -> Iterator[AnalysisService]:
    service = AnalysisService()
    try:
        yield service
    finally:
        service.close_all()


def test_service_methods_succeed_on_a_real_source(analysis: AnalysisService, source: Path) -> None:
    for method_name, key, extra in _SERVICE_CASES:
        method = getattr(analysis, method_name)
        result = method(str(source), **extra)
        assert result.ok is True, f"{method_name} failed: {result.error}"
        assert result.error is None
        assert result.meta.get("backend") == "jsre"
        assert result.data is not None and key in result.data


def test_service_methods_map_missing_file_to_not_found(
    analysis: AnalysisService, tmp_path: Path
) -> None:
    missing = tmp_path / "nope.js"
    for method_name, _key, extra in _SERVICE_CASES:
        method = getattr(analysis, method_name)
        result = method(str(missing), **extra)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"


def test_bound_tool_handlers_round_trip_the_envelope(source: Path) -> None:
    analysis = AnalysisService()
    try:
        bindings = bind_all_tools(analysis, CommandCatalog())
        js_handlers = {
            binding.name: binding.handler
            for binding in bindings
            if binding.name.startswith("js.") and binding.name not in _NODE_TOOLS
        }

        # Every node-free js scanner is covered here; a new one must be added.
        assert set(js_handlers) == set(_TOOL_KEYS)

        for name, handler in js_handlers.items():
            envelope = handler(str(source))
            assert isinstance(envelope, dict)
            assert envelope["ok"] is True, f"{name} envelope not ok: {envelope}"
            assert envelope["error"] is None
            assert envelope["meta"].get("backend") == "jsre"
            assert _TOOL_KEYS[name] in envelope["data"]
    finally:
        analysis.close_all()

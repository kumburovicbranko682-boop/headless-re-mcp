"""End-to-end smoke test for the wasm.* tools through the MCP wiring.

test_wasm_suite_integration.py drives the parse_wasm_* backend functions
directly. This test instead exercises the layers stacked on top of them: the
AnalysisService.wasm_* methods (which wrap each parser in JsReError handling and
a success/failure Result) and the bound tool handlers (which serialize that
Result envelope for the transport). The static catalog test only checks that a
handler *names* the right service method; here each one is actually executed on
a real module and on malformed input, so a broken wiring -- wrong argument
passing, a mismatched error code, a serialization fault -- is caught rather than
shipped.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import CommandCatalog
from tests.unit.test_wasm_suite_integration import _build_module

# (service method, the key its payload must carry, extra kwargs beyond path).
# The two wabt-backed tools (wasm.info / wasm.wat) are excluded: they shell out
# to an external binary this test does not assume is installed.
_SERVICE_CASES: tuple[tuple[str, str, dict[str, int]], ...] = (
    ("wasm_imports", "imports", {}),
    ("wasm_exports", "exports", {}),
    ("wasm_sections", "sections", {}),
    ("wasm_names", "functions", {}),
    ("wasm_functions", "functions", {}),
    ("wasm_strings", "strings", {}),
    ("wasm_globals", "globals", {}),
    ("wasm_data", "segments", {}),
    ("wasm_elements", "entries", {}),
    ("wasm_memory", "memories", {}),
    ("wasm_tables", "tables", {}),
    ("wasm_calls", "functions", {}),
    ("wasm_callers", "callers", {"function": 0}),
    ("wasm_producers", "producers", {}),
    ("wasm_features", "features", {}),
    ("wasm_start", "has_start_section", {}),
    ("wasm_opcodes", "categories", {}),
    ("wasm_locals", "functions", {}),
    ("wasm_custom_sections", "custom_sections", {}),
)

# The payload key each dotted tool name must return, and the extra call kwargs
# its handler needs beyond path. Keyed by the public tool name so a newly added
# wasm.* tool that is not listed here trips the coverage assertion below.
_TOOL_KEYS: dict[str, str] = {
    "wasm.imports": "imports",
    "wasm.exports": "exports",
    "wasm.sections": "sections",
    "wasm.names": "functions",
    "wasm.functions": "functions",
    "wasm.strings": "strings",
    "wasm.globals": "globals",
    "wasm.data": "segments",
    "wasm.elements": "entries",
    "wasm.memory": "memories",
    "wasm.tables": "tables",
    "wasm.calls": "functions",
    "wasm.callers": "callers",
    "wasm.producers": "producers",
    "wasm.features": "features",
    "wasm.start": "has_start_section",
    "wasm.opcodes": "categories",
    "wasm.locals": "functions",
    "wasm.custom_sections": "custom_sections",
}
_TOOL_EXTRA: dict[str, dict[str, int]] = {"wasm.callers": {"function": 0}}
_WABT_TOOLS = {"wasm.info", "wasm.wat"}


@pytest.fixture()
def module(tmp_path: Path) -> Path:
    target = tmp_path / "everything.wasm"
    target.write_bytes(_build_module())
    return target


@pytest.fixture()
def analysis() -> Iterator[AnalysisService]:
    service = AnalysisService()
    try:
        yield service
    finally:
        service.close_all()


def test_service_methods_succeed_on_a_real_module(
    analysis: AnalysisService, module: Path
) -> None:
    for method_name, key, extra in _SERVICE_CASES:
        method = getattr(analysis, method_name)
        result = method(str(module), **extra)
        assert result.ok is True, f"{method_name} failed: {result.error}"
        assert result.error is None
        assert result.meta.get("backend") == "jsre"
        assert result.data is not None and key in result.data


def test_service_methods_map_non_wasm_to_invalid_params(
    analysis: AnalysisService, tmp_path: Path
) -> None:
    bogus = tmp_path / "x.bin"
    bogus.write_bytes(b"not a wasm module")
    for method_name, _key, extra in _SERVICE_CASES:
        method = getattr(analysis, method_name)
        result = method(str(bogus), **extra)
        assert result.ok is False, f"{method_name} accepted a non-wasm file"
        assert result.error is not None
        assert result.error.code == "invalid_params"


def test_service_methods_map_missing_file_to_not_found(
    analysis: AnalysisService, tmp_path: Path
) -> None:
    missing = tmp_path / "nope.wasm"
    for method_name, _key, extra in _SERVICE_CASES:
        method = getattr(analysis, method_name)
        result = method(str(missing), **extra)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"


def test_bound_tool_handlers_round_trip_the_envelope(module: Path) -> None:
    analysis = AnalysisService()
    try:
        bindings = bind_all_tools(analysis, CommandCatalog())
        wasm_handlers = {
            binding.name: binding.handler
            for binding in bindings
            if binding.name.startswith("wasm.")
            and binding.name not in _WABT_TOOLS
        }

        # Every pure-Python wasm tool is covered here; a new one must be added.
        assert set(wasm_handlers) == set(_TOOL_KEYS)

        for name, handler in wasm_handlers.items():
            envelope = handler(str(module), **_TOOL_EXTRA.get(name, {}))
            assert isinstance(envelope, dict)
            assert envelope["ok"] is True, f"{name} envelope not ok: {envelope}"
            assert envelope["error"] is None
            assert envelope["meta"].get("backend") == "jsre"
            assert _TOOL_KEYS[name] in envelope["data"]
    finally:
        analysis.close_all()

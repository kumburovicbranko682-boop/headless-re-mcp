"""Ghidra + ghidra-wasm-plugin gate: decompile a real WebAssembly module.

The README advertises WASM decompilation as "复用 ghidra.* + ghidra-wasm-plugin",
and there is a ``ghidra_wasm_plugin`` config field, but nothing verified the claim:
Ghidra has no built-in WebAssembly loader, so ``ghidra.*`` can only touch a .wasm
when the extension is installed. This gate proves the capability end to end through
the product surface -- ``session.create`` on a .wasm (a ``web`` target that is
still a local file) -> ``ghidra.analyze`` / ``ghidra.functions`` / ``ghidra.decompile``
-- and asserts the recovered function decompiles to its actual arithmetic.

skip != pass: skips when Ghidra/Java are not configured, when the WebAssembly
extension is not installed under the Ghidra home, or when the Ghidra in use cannot
run the Jython ExportJson postScript -- all install choices, not defects.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient, wasm_plugin_installed
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

# A minimal, valid Wasm module exporting add(i32, i32) -> i32 with a real body
# (local.get 0, local.get 1, i32.add). Kept as raw bytes so the gate needs no
# wabt to build it; Ghidra's Wasm loader imports it and the decompiler recovers
# the addition.
_WASM_ADD = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
    ]
)


def _skip_if_no_jython(result: Result) -> None:
    if result.ok:
        return
    error = result.error
    if error is not None and error.code == "backend_error" and "missing" in error.message:
        pytest.skip(
            "Ghidra ran but its postScript produced no export "
            "(Jython not available?) — export gate not run (skip != pass)"
        )


@pytest.mark.integration
def test_ghidra_decompiles_a_wasm_module(tmp_path: Path) -> None:
    home = getattr(Settings.load(), "ghidra_home", None)
    if not GhidraClient(home=home).available:
        pytest.skip("Ghidra/Java not configured (HEADLESS_RE_GHIDRA_HOME) — not run (skip != pass)")
    if wasm_plugin_installed(home) is None:
        pytest.skip(
            "ghidra-wasm-plugin not installed under ghidra_home — WASM/Ghidra gate "
            "not run (skip != pass)"
        )

    module = tmp_path / "add.wasm"
    module.write_bytes(_WASM_ADD)

    service = AnalysisService()
    try:
        created = service.create_session(str(module))
        assert created.ok, created.error
        # A local .wasm is a web target that still carries a binary file, which is
        # what lets a portable backend reach it.
        assert created.data["session"]["target"] == "web"
        session_id = created.data["session"]["id"]

        analyzed = service.ghidra_analyze(session_id, timeout=300.0)
        # A Ghidra without the Wasm loader would fail the import here; the plugin
        # check above already gated that, so a failure now is real.
        assert analyzed.ok, analyzed.error
        assert analyzed.data.get("project_dir")

        functions = service.ghidra_functions(session_id, limit=64, timeout=300.0)
        _skip_if_no_jython(functions)
        assert functions.ok, functions.error
        assert functions.data.get("count", 0) >= 1, functions.data
        items = functions.data.get("items") or []
        # The module exports exactly one function, add.
        add_fn = next((it for it in items if "add" in str(it.get("name") or "").lower()), None)
        assert add_fn is not None, [it.get("name") for it in items]
        entry = add_fn.get("entry")
        assert entry, add_fn

        decompiled = service.ghidra_decompile(session_id, entry, timeout=300.0)
        _skip_if_no_jython(decompiled)
        assert decompiled.ok, decompiled.error
        assert decompiled.data.get("found") is True, decompiled.data
        body = decompiled.data.get("decompiled") or ""
        assert isinstance(body, str) and body.strip(), "decompilation produced no C text"
        # add(i32, i32) -> i32 must come back as an addition of its two parameters.
        assert "return" in body, body
        assert "+" in body, body
        assert "param" in body.lower(), body
    finally:
        service.close_all()

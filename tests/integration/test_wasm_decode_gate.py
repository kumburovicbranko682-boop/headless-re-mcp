"""WASM static-decode gate: prove wabt actually decodes a real module.

The web RE gate already touches ``wasm.wat``, but only against the smallest
possible module (magic + version, no sections) and only asserts the word
"module" appears -- which ``wasm2wat`` prints for an empty ``(module)`` too. So
"wabt genuinely decodes functions, opcodes and exports" was unproven, and
``wasm.info`` (wasm-objdump) had no live coverage at all.

This gate hands the service a hand-encoded module that exports an ``add``
function ``(i32, i32) -> i32`` and asserts, from the real tool output, that:

  * ``wasm.wat`` reconstructs the function body -- the ``local.get`` operands
    and the ``i32.add`` opcode -- and the named export, not just ``(module)``;
  * ``wasm.info`` lists the Type / Function / Export / Code sections and names
    the ``add`` export.

The module is built in-test from documented bytes so the gate has no build-time
dependency on ``wat2wasm``. skip != pass: with wabt absent it skips loudly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.core.service import AnalysisService

# A complete WebAssembly module exporting add(i32, i32) -> i32, section by
# section, so the assertions below correspond to bytes visible right here.
_ADD_WASM = bytes.fromhex(
    "0061736d01000000"  # magic "\0asm" + version 1
    "01070160027f7f017f"  # Type   : (func (param i32 i32) (result i32))
    "03020100"  # Function: one func, type index 0
    "070701036164640000"  # Export : "add" -> func 0
    "0a09010700200020016a0b"  # Code   : local.get 0; local.get 1; i32.add; end
)


@pytest.mark.integration
def test_wasm_wat_decodes_a_real_function_and_export(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Decode Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_ADD_WASM)

    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        # A real decode, not just the empty "(module)" shell.
        assert "(func" in wat, wat
        assert "i32.add" in wat, wat
        assert "local.get 0" in wat and "local.get 1" in wat, wat
        assert '(export "add"' in wat, wat
        assert result.data["bytes"] > 0, result.data
        assert result.data.get("tool_failed") is not True, result.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_lists_sections_and_the_export(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt not installed — WASM Decode Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_ADD_WASM)

    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x prints the section table and the details;
        # a genuine parse names every section this module carries.
        for section in ("Type", "Function", "Export", "Code"):
            assert section in objdump, (section, objdump)
        # The export table resolves func 0 to the name "add".
        assert "add" in objdump, objdump
        assert result.data.get("tool_failed") is not True, result.data
    finally:
        service.close_all()

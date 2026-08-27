"""WASM live gate: wasm2wat + wasm-objdump over a real module, not empty bytes.

``test_web_re_gate`` runs ``wasm_wat`` only on the empty magic+version header
(``\\x00asm\\x01\\x00\\x00\\x00``) and asserts just ``"module" in wat`` -- almost
none of wasm2wat's disassembly is exercised, and ``wasm_info`` (wasm-objdump)
has no live coverage at all. Both are version-sensitive external CLIs (wabt): a
flag or output-layout drift, or a stop producing section detail, would pass every
fake-based test and only fail at runtime against a real module.

This gate uses the committed real module (``fixtures/web/fixture.wasm``, compiled
by wabt's wat2wasm from ``fixture.wat``: two exported functions, a memory, a
mutable global, a data segment) and drives the full ``AnalysisService`` stack,
pinning that wasm2wat renders the real functions / exports / instructions and that
wasm-objdump dumps the real sections and symbol names. Skips (skip != pass) when
wabt is absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.core.service import AnalysisService

_FIXTURE_WASM = Path(__file__).resolve().parents[2] / "fixtures" / "web" / "fixture.wasm"


@pytest.mark.integration
def test_wasm_wat_over_a_real_module() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM wat Gate not run (skip != pass)")
    if not _FIXTURE_WASM.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_WASM}")

    service = AnalysisService()
    try:
        result = service.wasm_wat(str(_FIXTURE_WASM))
        assert result.ok, result.error
        wat = result.data["wat"]
        # Real disassembly: the two functions, their exports, the add instruction,
        # the memory, the global, and the data segment all round-trip to text.
        assert "(module" in wat
        assert wat.count("(func") >= 2
        assert "i32.add" in wat
        assert '(export "add"' in wat
        assert '(export "inc"' in wat
        assert '(export "mem"' in wat
        assert "(memory" in wat
        assert "(global" in wat
        assert "wasm-fixture-marker" in wat
        assert result.data["bytes"] > 0
        assert result.data["truncated"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_over_a_real_module() -> None:
    client = WasmClient()
    if client._objdump is None:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    if not _FIXTURE_WASM.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_WASM}")

    service = AnalysisService()
    try:
        result = service.wasm_info(str(_FIXTURE_WASM))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x must enumerate the real sections this module has.
        for section in ("Type", "Function", "Memory", "Global", "Export", "Code", "Data"):
            assert section in objdump, f"section {section!r} missing from objdump"
        # Section Details must name the real functions and exports, proving the
        # -x detail pass parsed the module, not just listed headers.
        assert "<add>" in objdump
        assert "<inc>" in objdump
        assert '"add"' in objdump
        assert '"mem"' in objdump
    finally:
        service.close_all()

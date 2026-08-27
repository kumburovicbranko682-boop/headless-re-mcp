"""WASM inspection gate: wabt-backed wasm2wat / wasm-objdump end to end on Linux.

The Web line's WebAssembly surface (wasm.wat, wasm.info) had one thin check: the
empty "\\0asm\\x01" header round-tripping through wasm2wat. That never touches
wasm.info at all, never sees a module with real sections, and never proves the
service maps a backend refusal to the right error code. This gate reads a
committed, multi-section module (fixtures/web/gate_module.wasm, built from the
.wat beside it) so wasm2wat emits real text and wasm-objdump lists real sections,
then drives both through AnalysisService.

The real-tool tests skip with an explicit "skip != pass" when wabt is absent, so
the gate is honest on a bare machine and real where wasm2wat/wasm-objdump exist.
The degradation test needs no tool and always runs: a missing backend must map to
capability_unavailable rather than crash the call.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "gate_module.wasm"
_NON_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
_MARKER = "headless-re wasm gate fixture"


def _wabt_available() -> bool:
    return WasmClient().available


@pytest.mark.integration
def test_wasm_wat_decompiles_a_real_module() -> None:
    """wasm2wat turns the committed module back into text the gate can read.

    The fixture carries an import, a memory, a mutable global, a data segment
    and three exported functions, so a successful conversion is more than the
    single "(module" the empty-header check settles for.
    """
    if not _wabt_available():
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"

    service = AnalysisService()
    try:
        result = service.wasm_wat(str(_WASM_FIXTURE))
        assert result.ok, result.error
        assert result.data is not None
        wat = result.data["wat"]
        assert isinstance(wat, str)
        # Structure the empty header can never show.
        assert "(module" in wat
        assert "import" in wat
        assert "env" in wat and "log" in wat
        assert "memory" in wat
        assert "global" in wat
        assert "data" in wat
        for export in ("add", "bump", "greet"):
            assert export in wat, f"export missing from wat: {export}"
        # The data segment's literal survives the round trip verbatim.
        assert _MARKER in wat
        # A clean pass is not a truncated one, and the length field agrees
        # with the text so a caller can tell a short module from a cut one.
        assert result.data["truncated"] is False
        assert "tool_failed" not in result.data
        assert result.data["bytes"] == len(wat.encode("utf-8"))
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_lists_the_real_sections() -> None:
    """wasm-objdump names every section and function the fixture defines.

    wasm.info was never exercised end to end. A module with all nine major
    sections proves the objdump output reaches the caller intact rather than
    only that the call did not error.
    """
    if not _wabt_available():
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"

    service = AnalysisService()
    try:
        result = service.wasm_info(str(_WASM_FIXTURE))
        assert result.ok, result.error
        assert result.data is not None
        objdump = result.data["objdump"]
        assert isinstance(objdump, str)
        for section in (
            "Type",
            "Import",
            "Function",
            "Table",
            "Memory",
            "Global",
            "Export",
            "Code",
            "Data",
        ):
            assert section in objdump, f"section missing from objdump: {section}"
        # Named symbols and the imported function resolve in the detail dump.
        assert "env.log" in objdump
        for name in ("<add>", "<bump>", "<greet>"):
            assert name in objdump, f"function name missing from objdump: {name}"
        # The data segment's bytes show in the hex/ascii dump.
        assert "headless-re wasm" in objdump
        assert result.data["truncated"] is False
        assert "tool_failed" not in result.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_tools_reject_a_non_wasm_file() -> None:
    """A mistargeted path is refused before a subprocess ever launches.

    The magic check turns a cryptic wasm2wat/wasm-objdump failure on a JS or
    PE file into a precise invalid_params, and the gate proves the service
    surfaces that code rather than a generic backend_error.
    """
    if not _wabt_available():
        pytest.skip("wabt not installed — WASM Gate not run (skip != pass)")
    assert _NON_WASM_FIXTURE.is_file(), f"fixture missing: {_NON_WASM_FIXTURE}"

    service = AnalysisService()
    try:
        wat = service.wasm_wat(str(_NON_WASM_FIXTURE))
        assert not wat.ok
        assert wat.error is not None
        assert wat.error.code == "invalid_params"
        assert "webassembly" in wat.error.message.lower()
        assert "magic" in wat.error.message.lower()

        info = service.wasm_info(str(_NON_WASM_FIXTURE))
        assert not info.ok
        assert info.error is not None
        assert info.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_tools_report_a_missing_file() -> None:
    """A path that does not exist is not_found, distinct from a bad module."""
    if not _wabt_available():
        pytest.skip("wabt not installed — WASM Gate not run (skip != pass)")

    service = AnalysisService()
    try:
        missing = str(_WASM_FIXTURE.parent / "definitely_absent.wasm")
        wat = service.wasm_wat(missing)
        assert not wat.ok
        assert wat.error is not None
        assert wat.error.code == "not_found"

        info = service.wasm_info(missing)
        assert not info.ok
        assert info.error is not None
        assert info.error.code == "not_found"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_tools_degrade_when_wabt_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No wabt on the box degrades to capability_unavailable, never a crash.

    This runs on any machine: it forces the absent-tool case by pinning
    settings.wabt to None and emptying PATH so discovery finds nothing, then
    checks the whole service call still answers with a structured refusal.
    """
    monkeypatch.setenv("PATH", "")
    assert WasmClient().available is False

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        wabt=None,
        health_check_interval_s=0.0,
    )
    service = AnalysisService(settings)
    try:
        # A real module still refuses cleanly: the tool, not the input, is missing.
        module = tmp_path / "empty.wasm"
        module.write_bytes(b"\x00asm\x01\x00\x00\x00")

        wat = service.wasm_wat(str(module))
        assert not wat.ok
        assert wat.error is not None
        assert wat.error.code == "capability_unavailable"

        info = service.wasm_info(str(module))
        assert not info.ok
        assert info.error is not None
        assert info.error.code == "capability_unavailable"
    finally:
        service.close_all()

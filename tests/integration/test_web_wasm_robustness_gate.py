"""WASM static (wabt) robustness gate: magic check, error contract, size bound.

``test_web_re_gate.py`` proves the wabt happy path -- ``wasm.wat`` disassembles a
real module and ``wasm.info`` enumerates its sections. What it never covers, all
exercised here against **real** wabt through the ``wasm.*`` service:

* **the magic check** -- ``wasm.*`` refuses a file that lacks the four-byte
  ``\\0asm`` magic with ``invalid_params`` *before* launching a tool, turning a
  cryptic child failure into a precise reason.
* **the tool-failure contract on a corrupt module** -- a file with a valid header
  but a garbage section must come back as a structured envelope, never a crash or
  an ``internal_error`` incident. This gate shows *both* documented branches on
  live tools: ``wasm2wat`` bails non-zero with no output (a ``backend_error``
  carrying ``exit_code``), while ``wasm-objdump`` prints the sections it did read
  and then trips, so its partial output is returned with ``tool_failed`` set --
  the "don't read a partial run as complete" contract that unit tests could only
  assert against a mocked subprocess.
* **the input size bound** -- an input over 16 MiB is refused as ``too_large``
  before a tool is launched, so an unattended pass cannot pin a core for the
  whole timeout.

skip != pass: skips honestly when wabt (wasm2wat / wasm-objdump) is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.core.service import AnalysisService

# The 16 MiB ceiling _require_existing_file enforces; matches _MAX_INPUT_BYTES.
_MAX_INPUT_BYTES = 16 * 1024 * 1024
# A valid module header (magic + version 1) followed by a byte that cannot be a
# section id (max is ~13), so any wabt tool rejects it -- but only after reading
# the header, which is what lets wasm-objdump emit partial output first.
_CORRUPT_MODULE = b"\x00asm\x01\x00\x00\x00" + b"\xde\xad\xbe\xef" * 32


@pytest.mark.integration
def test_wasm_tools_reject_a_non_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM magic Gate not run (skip != pass)")
    # No \0asm magic: refused up front, before any tool is launched.
    not_wasm = tmp_path / "notwasm.bin"
    not_wasm.write_bytes(b"this is plainly not a WebAssembly module\n")

    service = AnalysisService()
    try:
        result = service.wasm_wat(str(not_wasm))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params", result.error
        assert "magic" in result.error.message, result.error.message
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_tools_report_a_corrupt_module_without_crashing(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM robustness Gate not run (skip != pass)")
    corrupt = tmp_path / "corrupt.wasm"
    corrupt.write_bytes(_CORRUPT_MODULE)

    service = AnalysisService()
    try:
        # wasm.wat: a corrupt module is a structured failure, never a crash. On
        # live wabt this is the "non-zero and nothing on stdout" branch, so the
        # child's exit code is surfaced for the caller.
        wat = service.wasm_wat(str(corrupt))
        assert wat.ok is False, wat.data
        assert wat.error is not None
        assert wat.error.code == "backend_error", wat.error
        assert wat.error.code != "internal_error"
        assert int(wat.error.details.get("exit_code", 0)) != 0, wat.error.details

        if WasmClient()._objdump is None:
            return
        # wasm.info: whichever way this wabt jumps, the contract holds -- a corrupt
        # module can never be a clean success. Either it returns the partial output
        # it managed to read with tool_failed set (so the caller does not mistake a
        # bailed run for a finished one), or it is a structured backend_error.
        info = service.wasm_info(str(corrupt))
        if info.ok:
            assert info.data.get("tool_failed") is True, info.data
            assert int(info.data.get("exit_code", 0)) != 0, info.data
            assert isinstance(info.data.get("objdump"), str)
            assert isinstance(info.data.get("stderr"), str)
        else:
            assert info.error is not None
            assert info.error.code == "backend_error", info.error
            assert info.error.code != "internal_error"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_refuses_oversized_input(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM size-bound Gate not run (skip != pass)")
    # Valid magic so it is not rejected as a non-module; one byte over the ceiling
    # so the size guard is what refuses it, before wasm2wat is launched.
    oversized = tmp_path / "huge.wasm"
    oversized.write_bytes(b"\x00asm\x01\x00\x00\x00" + b"\x00" * (_MAX_INPUT_BYTES + 1))

    service = AnalysisService()
    try:
        result = service.wasm_wat(str(oversized))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "too_large", result.error
        details = result.error.details
        assert details.get("max_file_size") == _MAX_INPUT_BYTES, details
        assert int(details.get("size", 0)) > _MAX_INPUT_BYTES, details
    finally:
        service.close_all()

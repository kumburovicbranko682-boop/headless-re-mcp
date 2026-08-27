"""Live gate: wabt actually decodes a real WebAssembly module.

The existing web-RE gate only feeds ``wasm.wat`` the degenerate empty module
(magic + version, no sections) and never exercises ``wasm.info`` at all, so a
green run proved little more than that four magic bytes survived. This gate
compiles a genuine module from WAT with ``wat2wasm`` at test time and drives the
real ``wasm.*`` service path, so a pass means ``wasm2wat`` recovered the function
bodies and ``wasm-objdump`` recovered every section and export name. It skips
honestly (skip != pass) when any wabt binary is absent, so a bare machine cannot
masquerade as a pass.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.core.service import AnalysisService

# Two functions, a memory, an exported global and a data segment: enough that
# wasm2wat emits real bodies and wasm-objdump lists every section kind.
# wat2wasm compiles this to ~107 bytes.
_WAT_SOURCE = """(module
  (memory (export "mem") 1)
  (data (i32.const 0) "hello wasm gate")
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $mul (export "mul") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.mul)
  (global (export "answer") i32 (i32.const 42)))
"""

_SKIP = "wabt binary {name} not installed — WASM live gate not run (skip != pass)"


def _require_wabt() -> str:
    """Return wat2wasm's path, skipping honestly if any wabt tool is missing."""
    wat2wasm = ""
    for name in ("wat2wasm", "wasm2wat", "wasm-objdump"):
        found = shutil.which(name)
        if found is None:
            pytest.skip(_SKIP.format(name=name))
        if name == "wat2wasm":
            wat2wasm = found
    return wat2wasm


def _build_module(tmp_path: Path) -> Path:
    """Compile the WAT source into a real .wasm module with wat2wasm."""
    wat2wasm = _require_wabt()
    wat = tmp_path / "gate.wat"
    wat.write_text(_WAT_SOURCE, encoding="utf-8")
    module = tmp_path / "gate.wasm"
    proc = subprocess.run(
        [wat2wasm, str(wat), "-o", str(module)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, f"wat2wasm could not build the fixture: {proc.stderr}"
    assert module.is_file(), "wat2wasm produced no output"
    assert module.read_bytes()[:4] == b"\x00asm", "fixture lacks the wasm magic"
    return module


@pytest.mark.integration
def test_wasm_wat_recovers_real_function_bodies(tmp_path: Path) -> None:
    module = _build_module(tmp_path)
    # The direct client must also report the tools resolved, or the service
    # success below would be meaningless.
    assert WasmClient().available is True

    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        # Real bodies, not just "(module)": both arithmetic ops must survive.
        assert "i32.add" in wat
        assert "i32.mul" in wat
        assert "(memory" in wat
        assert "(global" in wat
        # Honest length bookkeeping on a real (non-empty) module.
        assert result.data["bytes"] > len("(module)")
        assert result.data["truncated"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_recovers_sections_and_exports(tmp_path: Path) -> None:
    module = _build_module(tmp_path)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x lists every section kind this module carries.
        for section in ("Type", "Function", "Memory", "Global", "Export", "Code", "Data"):
            assert section in objdump, f"section {section} missing from objdump"
        # Export names come straight from the module's export section.
        for name in ("mem", "add", "mul", "answer"):
            assert name in objdump, f"export {name} missing from objdump"
        # The data segment's bytes are decoded, not just counted.
        assert "hello wasm gate" in objdump
        assert result.data["truncated"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_service_rejects_hostile_inputs(tmp_path: Path) -> None:
    # Requires wabt present so a failure here is a real contract break, not a
    # missing tool.
    _require_wabt()
    service = AnalysisService()
    try:
        # A non-wasm file is refused by the magic gate *before* any tool runs:
        # a launched-then-failed tool would surface as backend_error instead.
        not_wasm = tmp_path / "not.wasm"
        not_wasm.write_bytes(b"MZ this is a PE header, not a wasm module")
        rejected = service.wasm_wat(str(not_wasm))
        assert rejected.ok is False
        assert rejected.error is not None
        assert rejected.error.code == "invalid_params"

        # A path that does not exist is a structured not_found, never a crash.
        missing = service.wasm_info(str(tmp_path / "absent.wasm"))
        assert missing.ok is False
        assert missing.error is not None
        assert missing.error.code == "not_found"

        # Valid magic followed by garbage: wasm2wat bails. Either it produces
        # nothing (structured backend_error) or emits partial output and must
        # then flag tool_failed with a non-zero exit — both are honest.
        broken = tmp_path / "broken.wasm"
        broken.write_bytes(b"\x00asm\x01\x00\x00\x00\xff\xff\xff\xff")
        result = service.wasm_wat(str(broken))
        if result.ok:
            assert result.data.get("tool_failed") is True
            assert result.data.get("exit_code") not in (None, 0)
        else:
            assert result.error is not None
            assert result.error.code == "backend_error"
    finally:
        service.close_all()

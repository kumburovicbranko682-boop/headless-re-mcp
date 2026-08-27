"""WebAssembly gate: decode a real module through wabt, end to end.

The existing Web gate only runs ``wasm.wat`` against an empty module (magic +
version, no sections), so nothing proves wabt actually decodes functions or an
export table, and ``wasm.info`` (wasm-objdump) has no coverage at all -- the same
"empty fixture proves nothing" gap that let two Ghidra bugs through. This gate
assembles a genuine module with wat2wasm (a function that adds two i32s, exported
alongside a memory) and drives ``wasm.wat`` / ``wasm.info`` through
``AnalysisService``, asserting the recovered text carries the real instruction
and export and that objdump lists the section and export tables.

skip != pass: it skips only when wabt (wasm2wat/objdump) or wat2wasm is missing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MODULE_WAT = """(module
  (func $add (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (export "add" (func $add))
  (memory (export "mem") 1))
"""


def _find_wat2wasm(settings: Settings) -> str | None:
    """Locate wat2wasm the way WasmClient locates its own wabt tools."""
    wabt = getattr(settings, "wabt", None)
    if wabt is not None:
        for candidate in (wabt / "wat2wasm", wabt / "bin" / "wat2wasm"):
            if candidate.is_file():
                return str(candidate)
    return shutil.which("wat2wasm")


def _build_wasm(wat2wasm: str, work: Path) -> Path | None:
    work.mkdir(parents=True, exist_ok=True)
    source = work / "module.wat"
    source.write_text(_MODULE_WAT, encoding="utf-8")
    wasm = work / "module.wasm"
    try:
        subprocess.run(
            [wat2wasm, str(source), "-o", str(wasm)],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return wasm if wasm.is_file() else None


@pytest.mark.integration
def test_wasm_info_and_wat_decode_a_real_module(tmp_path: Path) -> None:
    settings = Settings.load()
    if not WasmClient(getattr(settings, "wabt", None)).available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    wat2wasm = _find_wat2wasm(settings)
    if wat2wasm is None:
        pytest.skip("wat2wasm not available to build a module — WASM Gate not run (skip != pass)")

    wasm = _build_wasm(wat2wasm, tmp_path / "build")
    if wasm is None:
        pytest.skip("wat2wasm could not assemble the fixture — WASM Gate not run (skip != pass)")

    service = AnalysisService(settings)
    try:
        wat = service.wasm_wat(str(wasm))
        assert wat.ok and wat.data is not None, wat.error
        text = wat.data["wat"]
        # A real instruction and the export table must survive the round trip,
        # not merely the "(module" header an empty file also produces.
        assert "i32.add" in text
        assert "local.get" in text
        assert '(export "add"' in text
        assert int(wat.data["bytes"]) > 0

        info = service.wasm_info(str(wasm))
        assert info.ok and info.data is not None, info.error
        objdump = info.data["objdump"]
        # wasm-objdump -h -x lists sections and the export table by name.
        assert "Sections:" in objdump
        assert "Export" in objdump
        assert "add" in objdump
        assert "mem" in objdump
    finally:
        service.close_all()

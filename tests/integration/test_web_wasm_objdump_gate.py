"""Live wabt gate: wasm-objdump section/import/export detail on a rich module.

The WASM static-chain gate exercises ``WasmClient.info`` (wasm-objdump) but only
on a trivial single-export ``add`` module with no imports, memory, globals or
data -- and it needs a browser to capture that module first. So the parts of
wasm-objdump that matter for real WASM triage (which host functions does it
import? what does it export? does it carry an embedded data segment / string?)
are never asserted, and a regression in the ``-h -x`` handling would go unnoticed
on any non-trivial module.

This gate assembles, browser-free, a module that imports a host function, exports
two functions and its memory, holds a mutable global and an embedded data string,
then drives both wabt views and cross-checks them: ``wat`` (wasm2wat) must render
every construct, and ``info`` (wasm-objdump -h -x) must list each section and
resolve the import to ``env.log_value``, the export names, the memory limits, the
global's mutability/init, the function signatures and the data segment (including
the embedded marker bytes).

Skips honestly when wabt (wat2wasm to assemble, plus wasm2wat / wasm-objdump) is
missing. skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import WasmClient

_MARKER = "H3adl3ss-wasm-marker-2f8"
# One module carrying every section a real target uses: an imported host
# function, a mutable global, a memory with an embedded data string, and two
# exported functions (one reads the global, one calls the import).
_WAT = """(module
  (import "env" "log_value" (func $log_value (param i32)))
  (memory (export "memory") 1)
  (global $counter (mut i32) (i32.const 7))
  (data (i32.const 16) "H3adl3ss-wasm-marker-2f8")
  (func $compute (export "compute") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
    global.get $counter
    i32.add)
  (func $emit (export "emit") (param i32)
    local.get 0
    call $log_value)
)
"""


def _assemble(wat_text: str, dest: Path) -> Path | None:
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        return None
    wat_path = dest / "module.wat"
    wat_path.write_text(wat_text, encoding="utf-8")
    wasm_path = dest / "module.wasm"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local wat2wasm
            [wat2wasm, str(wat_path), "-o", str(wasm_path)],
            check=True,
            capture_output=True,
            timeout=60.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return wasm_path if wasm_path.is_file() else None


@pytest.mark.integration
def test_web_wasm_objdump_reports_sections_imports_exports_and_data(tmp_path: Path) -> None:
    wasm = WasmClient()
    if not wasm.available or shutil.which("wasm-objdump") is None:
        pytest.skip(
            "wabt (wasm2wat/wasm-objdump) not installed — objdump Gate not run (skip != pass)"
        )
    module = _assemble(_WAT, tmp_path)
    if module is None:
        pytest.skip("wat2wasm missing — cannot assemble the WASM fixture (skip != pass)")

    # wat (wasm2wat): every construct round-trips into readable text.
    wat_text = str(wasm.wat(module)["wat"])
    assert '(import "env" "log_value"' in wat_text, wat_text
    assert "(memory" in wat_text, wat_text
    assert "(global (;0;) (mut i32) (i32.const 7))" in wat_text, wat_text
    assert '(export "compute" (func 1))' in wat_text, wat_text
    assert '(export "emit"' in wat_text and '(export "memory"' in wat_text, wat_text
    assert f'(data (;0;) (i32.const 16) "{_MARKER}")' in wat_text, wat_text
    assert "(param i32 i32) (result i32)" in wat_text, wat_text

    # info (wasm-objdump -h -x): the structural view of the same module.
    dump = str(wasm.info(module)["objdump"])
    assert "file format wasm" in dump, dump

    # -h: every section this module uses is listed.
    for section in ("Type", "Import", "Function", "Memory", "Global", "Export", "Code", "Data"):
        assert section in dump, (section, dump)

    # -x details: the import is resolved to its host module.function.
    assert "env.log_value" in dump, dump
    # export names map to memory and both functions.
    assert '"compute"' in dump and '"emit"' in dump and '"memory"' in dump, dump
    # memory limits, and the mutable global with its init value.
    assert "pages: initial=1" in dump, dump
    assert "mutable=1" in dump and "init i32=7" in dump, dump
    # a function signature is reported the objdump way.
    assert "(i32, i32) -> i32" in dump, dump
    # the data segment: its init offset, byte size and embedded marker bytes.
    assert "init i32=16" in dump, dump
    assert "size=24" in dump, dump
    assert _MARKER[:16] in dump, dump  # ASCII column of the data hex dump

"""wasm-objdump live gate: real section/detail inspection of a module.

The wabt line has two tools. ``wasm.wat`` (wasm2wat) has a live gate; its
sibling ``wasm.info`` (wasm-objdump) only ever ran against a fake binary in
unit tests, so the ``-h -x`` invocation and the way its output is wrapped were
never checked against the real tool. There is also a latent asymmetry worth
pinning: ``WasmClient.available`` is decided solely by wasm2wat, yet ``info``
needs a separately resolved wasm-objdump, so "available" does not by itself
guarantee ``info`` can run.

The module is embedded as bytes (built once with wat2wasm), so the gate depends
only on the tool under test. It has two functions, a memory, a global and four
named exports, and the gate asserts wasm-objdump recovered that real structure
-- the section table and the export/function names -- not merely non-empty text.

Skip != pass: the gate skips with a reason when wasm-objdump is absent and runs
for real when present. CI installs wabt, so a skip there is a genuine regression
rather than a bare machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import WasmClient

# wat2wasm output for a module with two exported functions (add, mul), an
# exported memory (mem) and an exported global (answer):
#   (module
#     (func $add (export "add") (param i32 i32) (result i32) ... i32.add)
#     (func $mul (export "mul") (param i32 i32) (result i32) ... i32.mul)
#     (memory (export "mem") 1)
#     (global (export "answer") i32 (i32.const 42)))
_WASM_MODULE = bytes.fromhex(
    "0061736d0100000001070160027f7f017f030302000005030100010606017f00412a0b"
    "071c04036164640000036d756c0001036d656d020006616e7377657203000a11020700"
    "200020016a0b0700200020016c0b"
)


@pytest.mark.integration
def test_wasm_objdump_reports_sections_and_exports(tmp_path: Path) -> None:
    client = WasmClient()
    if client._objdump is None:
        pytest.skip("wasm-objdump (wabt) not installed — info Gate not run (skip != pass)")

    module = tmp_path / "m.wasm"
    module.write_bytes(_WASM_MODULE)

    result = client.info(module)
    dump = str(result.get("objdump", ""))
    assert not result.get("tool_failed"), result.get("stderr")

    # The section table (-h) must list the real sections this module has.
    for section in ("Type", "Function", "Memory", "Global", "Export", "Code"):
        assert section in dump, f"section {section!r} missing from wasm-objdump output"

    # The detail dump (-x) must name the two functions and all four exports.
    assert "<add>" in dump
    assert "<mul>" in dump
    for export in ("add", "mul", "mem", "answer"):
        assert export in dump, f"export {export!r} missing from wasm-objdump output"

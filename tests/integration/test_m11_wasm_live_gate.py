"""M11 WASM live gate: wasm2wat / wasm-objdump against a real module.

The jsre WASM path (wabt) had no live coverage: the unit tests mock the CLI, so
a wabt whose wasm2wat / wasm-objdump output drifted would pass them while the
real tool returned something the client mishandled. This drives both tools
against a tiny embedded module -- an exported ``add`` function plus a memory --
and asserts the WAT round-trips with that export and the objdump lists the
sections. Portable: it resolves wabt from settings/PATH exactly as the service
does and skips (skip != pass) when wabt is absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.config import Settings

# wat2wasm of:
#   (module
#     (func $add (export "add") (param i32 i32) (result i32)
#       local.get 0
#       local.get 1
#       i32.add)
#     (memory (export "mem") 1))
# Embedded as bytes so the gate needs only wasm2wat/wasm-objdump, not wat2wasm.
_WASM = bytes.fromhex(
    "0061736d0100000001070160027f7f017f030201000503010001"
    "070d02036164640000036d656d02000a09010700200020016a0b"
)

# A spec-valid module carrying an Import section (which the export-only module
# above lacks): type (i32,i32)->i32; imports env.log (func#0), env.memory
# (memory min 1) and js.g (mutable i32 global); export run (func#0).
_WASM_WITH_IMPORTS = bytes.fromhex(
    "0061736d0100000001070160027f7f017f"
    "02210303656e76036c6f67000003656e76066d656d6f7279020001026a730167037f01"
    "0707010372756e0000"
)


def _wasm_client() -> WasmClient:
    return WasmClient(getattr(Settings.load(), "wabt", None))


@pytest.mark.integration
def test_m11_wasm_live_wat_and_objdump(tmp_path: Path) -> None:
    client = _wasm_client()
    if not client.available:
        pytest.skip("wabt (wasm2wat) not installed/configured — WASM Gate not run (skip != pass)")
    fixture = tmp_path / "module.wasm"
    fixture.write_bytes(_WASM)

    wat = client.wat(fixture)
    assert wat.get("truncated") is False
    # A clean module must not be flagged as a tool failure.
    assert "tool_failed" not in wat
    text = wat["wat"]
    assert "(module" in text
    assert 'export "add"' in text
    assert "i32.add" in text

    # wasm-objdump ships alongside wasm2wat in a real wabt install; a partial
    # PATH with only wasm2wat still exercises the wat path above.
    if client._objdump is not None:
        info = client.info(fixture)
        assert "tool_failed" not in info
        dump = info["objdump"]
        assert "Export" in dump
        assert "add" in dump
        # -h lists section headers and -x expands them; Type and Code prove the
        # section walk parsed rather than only the file header being read.
        assert "Type" in dump
        assert "Code" in dump


@pytest.mark.integration
def test_m11_wasm_imports_exports_read_from_bytes(tmp_path: Path) -> None:
    """wasm.imports / wasm.exports parse real module bytes with no wabt.

    Unlike wat/info these read the binary Import/Export sections in-process, so
    this test does not skip when wabt is absent -- it must run everywhere. It
    validates against the same real wat2wasm module the gate above uses (an
    exported add() + memory, no imports) and against a second module carrying an
    Import section, proving the parser resolves the host boundary end to end.
    """
    client = WasmClient(None)  # deliberately no wabt: imports/exports never need it

    export_only = tmp_path / "exports.wasm"
    export_only.write_bytes(_WASM)
    exports = client.exports(export_only)
    assert exports["total"] == 2
    assert exports["incomplete"] is False
    names = {(row["name"], row["kind"]) for row in exports["exports"]}
    assert names == {("add", "func"), ("mem", "memory")}
    # The export-only module has no Import section at all -> empty, complete.
    assert client.imports(export_only)["total"] == 0

    with_imports = tmp_path / "imports.wasm"
    with_imports.write_bytes(_WASM_WITH_IMPORTS)
    imports = client.imports(with_imports)
    assert imports["total"] == 3
    assert imports["declared"] == 3
    assert imports["incomplete"] is False
    by_name = {row["name"]: row for row in imports["imports"]}
    # The func import's signature is resolved from the module's Type section.
    assert by_name["log"]["kind"] == "func"
    assert by_name["log"]["params"] == ["i32", "i32"]
    assert by_name["log"]["results"] == ["i32"]
    assert by_name["memory"]["kind"] == "memory"
    assert by_name["memory"]["limits"] == {"min": 1}
    assert by_name["g"]["kind"] == "global"
    assert by_name["g"]["value_type"] == "i32"
    assert by_name["g"]["mutable"] is True
    # This module's export is run (func); prove the export path too.
    assert {row["name"] for row in client.exports(with_imports)["exports"]} == {"run"}

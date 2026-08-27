"""M11 WASM live gate: wasm2wat / wasm-objdump against a real module.

The jsre WASM path (wabt) had no live coverage: the unit tests mock the CLI, so
a wabt whose wasm2wat / wasm-objdump output drifted would pass them while the
real tool returned something the client mishandled. This drives both tools
against a tiny embedded module -- an exported ``add`` function plus a memory --
and asserts the WAT round-trips with that export and the objdump lists the
sections. Portable: it resolves wabt from settings/PATH exactly as the service
does and skips (skip != pass) when wabt is absent. The dependency-free readers
(imports/exports/names/sections/strings) run in further tests that never skip,
since they read the module bytes in-process with no wabt.
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

# A module carrying a custom "name" section: module name "gate" and function
# names {0: add, 1: run}. Used to prove wasm.names decodes the debug-name symbol
# map that symbolises an otherwise index-only module.
_WASM_WITH_NAMES = bytes.fromhex(
    "0061736d0100000001070160027f7f017f"
    "0019046e616d6500050467617465010b020003616464010372756e"
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

    # wasm.sections: the structural map reads the same real module with no wabt,
    # in file order, naming each section and carrying its declared entry count.
    smap = client.sections(export_only)
    assert smap["incomplete"] is False
    by_id = {row["id"]: row for row in smap["sections"]}
    assert by_id[1]["name"] == "type" and by_id[1]["count"] == 1
    assert by_id[7]["name"] == "export" and by_id[7]["count"] == 2  # add + mem
    assert by_id[10]["name"] == "code"
    offsets = [row["offset"] for row in smap["sections"]]
    assert offsets == sorted(offsets)  # sections map in ascending file order
    assert all(r["offset"] + r["size"] <= len(_WASM) for r in smap["sections"])

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

    # wasm.names: a module with a custom "name" section symbolises to the debug
    # names it carries; a stripped module (no name section) reports present False
    # rather than fabricating names.
    named = tmp_path / "named.wasm"
    named.write_bytes(_WASM_WITH_NAMES)
    names = client.names(named)
    assert names["present"] is True
    assert names["module_name"] == "gate"
    assert names["total"] == 2
    assert {(row["index"], row["name"]) for row in names["function_names"]} == {
        (0, "add"),
        (1, "run"),
    }
    stripped = client.names(export_only)  # the wat2wasm module carries no names
    assert stripped["present"] is False
    assert stripped["function_names"] == []

    # The named module's section map surfaces the custom "name" section by its
    # own name (all custom sections share id 0), which is how wasm.sections tells
    # apart "name"/"producers"/".debug_*" for triage.
    named_sections = client.sections(named)["sections"]
    custom = next(row for row in named_sections if row["id"] == 0)
    assert custom["name"] == "custom"
    assert custom["custom_name"] == "name"


@pytest.mark.integration
def test_m11_wasm_strings_read_from_bytes(tmp_path: Path) -> None:
    """wasm.strings pulls the Data-section literal pool from real bytes, no wabt.

    Builds a spec-valid module with a memory and one active data segment holding
    two distinct strings, then asserts the parser recovers both, honours a raised
    min_length, and filters by a case-insensitive substring -- all in-process, so
    this never skips on a wabt-less host.
    """
    payload = b"MARKER_STRING\x00https://example.test/v1"
    magic = bytes.fromhex("0061736d01000000")
    memory = bytes([5, 3, 1, 0, 1])  # memory section: one memory, min 1
    # one active segment into memory 0 at i32.const 0, then the byte vector.
    segment = b"\x00\x41\x00\x0b" + bytes([len(payload)]) + payload
    data_body = bytes([1]) + segment
    module = magic + memory + bytes([11, len(data_body)]) + data_body

    fixture = tmp_path / "data.wasm"
    fixture.write_bytes(module)
    client = WasmClient(None)  # deliberately no wabt: strings never needs it

    result = client.strings(fixture)
    assert result["incomplete"] is False
    assert result["data_segments"] == 1
    assert result["min_length"] == 4
    assert set(result["strings"]) == {"MARKER_STRING", "https://example.test/v1"}
    assert "filtered" not in result

    # A raised floor drops the shorter run (13 chars) but keeps the 23-char URL.
    long_only = client.strings(fixture, min_length=20)
    assert long_only["strings"] == ["https://example.test/v1"]

    filtered = client.strings(fixture, contains="marker")  # case-insensitive
    assert filtered["filtered"] is True
    assert filtered["strings"] == ["MARKER_STRING"]

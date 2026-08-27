"""Suite-wide integration test for the pure-Python WebAssembly tools.

Every per-tool test elsewhere feeds each parser an isolated byte fragment. This
test instead assembles ONE coherent module that populates every standard
section (type, import, function, table, memory, global, export, start, element,
code, data) plus the name, producers and target_features custom sections, then
runs all sixteen wasm.* parsers over it and checks both that each reads the
expected values and that the tools agree with one another on the shared facts --
the function index space, the import/local boundary, and the forward/reverse
call edges. It is the one place a change that makes two tools disagree about the
same module is caught.

The module is hand-assembled (no external toolchain), but it is a coherent,
spec-shaped program:

    type 0 : [] -> []
    type 1 : [i32] -> [i32]
    import func  env.log       : type 1        -> function index 0 (imported)
    import global env.g        : i32 immutable  -> global index 0 (imported)
    func 1 (local, type 0)     : i32.const 5; call 0 (env.log); drop
    func 2 (local, type 1)     : local.get 0; i32.const 0; call_indirect type 1
    table 0                    : funcref, min 2 max 4
    memory 0                   : min 1 max 2
    global 1 (local)           : i32 mutable = 42
    exports                    : main=func 2, mem=memory 0, tab=table 0, g=global 1
    start                      : func 1
    element                    : active, table 0, offset 0, funcs [1, 2]
    data                       : active, memory 0, offset 16, "hello\\0world"
    names                      : module "mymod"; funcs 0=log 1=init 2=main
    producers                  : language Rust 1.75.0; processed-by rustc 1.75.0
    target_features            : +simd128, +bulk-memory
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import (
    parse_wasm_callers,
    parse_wasm_calls,
    parse_wasm_data,
    parse_wasm_elements,
    parse_wasm_exports,
    parse_wasm_features,
    parse_wasm_functions,
    parse_wasm_globals,
    parse_wasm_imports,
    parse_wasm_memory,
    parse_wasm_names,
    parse_wasm_producers,
    parse_wasm_sections,
    parse_wasm_start,
    parse_wasm_strings,
    parse_wasm_tables,
)

_PREAMBLE = b"\x00asm\x01\x00\x00\x00"
_DATA_PAYLOAD = b"hello\x00world"
_DATA_OFFSET = 16


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _custom_section(name: str, payload: bytes) -> bytes:
    return _section(0, _name(name) + payload)


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _type_section() -> bytes:
    type0 = b"\x60" + _uleb(0) + _uleb(0)  # [] -> []
    type1 = b"\x60" + _uleb(1) + b"\x7f" + _uleb(1) + b"\x7f"  # [i32] -> [i32]
    return _section(1, _vec([type0, type1]))


def _import_section() -> bytes:
    func_import = _name("env") + _name("log") + b"\x00" + _uleb(1)  # type 1
    global_import = _name("env") + _name("g") + b"\x03" + b"\x7f" + b"\x00"
    return _section(2, _vec([func_import, global_import]))


def _function_section() -> bytes:
    return _section(3, _vec([_uleb(0), _uleb(1)]))  # func1->type0, func2->type1


def _table_section() -> bytes:
    tabletype = b"\x70" + b"\x01" + _uleb(2) + _uleb(4)  # funcref, min 2 max 4
    return _section(4, _vec([tabletype]))


def _memory_section() -> bytes:
    memtype = b"\x01" + _uleb(1) + _uleb(2)  # min 1 max 2
    return _section(5, _vec([memtype]))


def _global_section() -> bytes:
    glob = b"\x7f" + b"\x01" + b"\x41" + _uleb(42) + b"\x0b"  # i32 mut = 42
    return _section(6, _vec([glob]))


def _export_section() -> bytes:
    exports = [
        _name("main") + b"\x00" + _uleb(2),
        _name("mem") + b"\x02" + _uleb(0),
        _name("tab") + b"\x01" + _uleb(0),
        _name("g") + b"\x03" + _uleb(1),
    ]
    return _section(7, _vec(exports))


def _start_section() -> bytes:
    return _section(8, _uleb(1))  # start = func 1


def _element_section() -> bytes:
    seg = b"\x00" + (b"\x41" + _uleb(0) + b"\x0b") + _vec([_uleb(1), _uleb(2)])
    return _section(9, _vec([seg]))


def _code_section() -> bytes:
    body1 = _uleb(0) + b"\x41" + _uleb(5) + b"\x10" + _uleb(0) + b"\x1a" + b"\x0b"
    body2 = (
        _uleb(0)
        + b"\x20" + _uleb(0)
        + b"\x41" + _uleb(0)
        + b"\x11" + _uleb(1) + _uleb(0)
        + b"\x0b"
    )
    return _section(10, _vec([_uleb(len(body1)) + body1, _uleb(len(body2)) + body2]))


def _data_section() -> bytes:
    seg = (
        b"\x00"
        + (b"\x41" + _uleb(_DATA_OFFSET) + b"\x0b")
        + _uleb(len(_DATA_PAYLOAD))
        + _DATA_PAYLOAD
    )
    return _section(11, _vec([seg]))


def _name_section() -> bytes:
    module_sub = b"\x00" + _uleb(len(_name("mymod"))) + _name("mymod")
    namemap = _vec(
        [
            _uleb(0) + _name("log"),
            _uleb(1) + _name("init"),
            _uleb(2) + _name("main"),
        ]
    )
    func_sub = b"\x01" + _uleb(len(namemap)) + namemap
    return _custom_section("name", module_sub + func_sub)


def _producers_section() -> bytes:
    language = _name("language") + _vec([_name("Rust") + _name("1.75.0")])
    processed = _name("processed-by") + _vec([_name("rustc") + _name("1.75.0")])
    return _custom_section("producers", _vec([language, processed]))


def _target_features_section() -> bytes:
    feats = [b"\x2b" + _name("simd128"), b"\x2b" + _name("bulk-memory")]
    return _custom_section("target_features", _vec(feats))


def _build_module() -> bytes:
    return _PREAMBLE + b"".join(
        [
            _type_section(),
            _import_section(),
            _function_section(),
            _table_section(),
            _memory_section(),
            _global_section(),
            _export_section(),
            _start_section(),
            _element_section(),
            _code_section(),
            _data_section(),
            _name_section(),
            _producers_section(),
            _target_features_section(),
        ]
    )


@pytest.fixture()
def module(tmp_path: Path) -> Path:
    target = tmp_path / "everything.wasm"
    target.write_bytes(_build_module())
    return target


def test_sections_lists_every_section(module: Path) -> None:
    payload = parse_wasm_sections(module)
    assert payload["truncated"] is False
    names = [row["name"] for row in payload["sections"]]
    assert names == [
        "type",
        "import",
        "function",
        "table",
        "memory",
        "global",
        "export",
        "start",
        "element",
        "code",
        "data",
        "custom",
        "custom",
        "custom",
    ]
    customs = {
        row["custom_name"]
        for row in payload["sections"]
        if row["name"] == "custom"
    }
    assert customs == {"name", "producers", "target_features"}


def test_imports_and_exports(module: Path) -> None:
    imports = parse_wasm_imports(module)
    assert imports["total"] == 2
    assert imports["imports"] == [
        {"module": "env", "name": "log", "kind": "func"},
        {"module": "env", "name": "g", "kind": "global"},
    ]

    exports = parse_wasm_exports(module)
    assert exports["total"] == 4
    by_name = {row["name"]: row for row in exports["exports"]}
    assert by_name["main"] == {"name": "main", "kind": "func", "index": 2}
    assert by_name["mem"]["kind"] == "memory"
    assert by_name["tab"]["kind"] == "table"
    assert by_name["g"] == {"name": "g", "kind": "global", "index": 1}


def test_functions_join_names_and_signatures(module: Path) -> None:
    payload = parse_wasm_functions(module)
    assert payload["total"] == 3
    assert payload["imported_count"] == 1
    rows = {row["index"]: row for row in payload["functions"]}
    assert rows[0]["kind"] == "import"
    assert rows[0]["name"] == "log"
    assert rows[0]["params"] == ["i32"] and rows[0]["results"] == ["i32"]
    assert rows[1]["kind"] == "local"
    assert rows[1]["name"] == "init"
    assert rows[1]["params"] == [] and rows[1]["results"] == []
    assert rows[2]["name"] == "main"
    assert rows[2]["params"] == ["i32"] and rows[2]["results"] == ["i32"]


def test_globals_memory_tables(module: Path) -> None:
    globals_ = parse_wasm_globals(module)
    assert globals_["total"] == 2 and globals_["imported_count"] == 1
    assert globals_["globals"][0] == {
        "index": 0,
        "kind": "import",
        "module": "env",
        "name": "g",
        "type": "i32",
        "mutable": False,
    }
    assert globals_["globals"][1] == {
        "index": 1,
        "kind": "local",
        "type": "i32",
        "mutable": True,
    }

    memory = parse_wasm_memory(module)
    assert memory["total"] == 1
    assert memory["memories"][0] == {
        "index": 0,
        "kind": "local",
        "min": 1,
        "max": 2,
        "shared": False,
        "index_type": "i32",
    }

    tables = parse_wasm_tables(module)
    assert tables["total"] == 1
    assert tables["tables"][0] == {
        "index": 0,
        "kind": "local",
        "element_type": "funcref",
        "min": 2,
        "max": 4,
    }


def test_elements_data_strings(module: Path) -> None:
    elements = parse_wasm_elements(module)
    assert elements["total"] == 2
    assert [row["func_index"] for row in elements["entries"]] == [1, 2]
    assert [row["slot"] for row in elements["entries"]] == [0, 1]
    assert {row["mode"] for row in elements["entries"]} == {"active"}
    assert {row["table_index"] for row in elements["entries"]} == {0}

    data = parse_wasm_data(module)
    assert data["total"] == 1
    assert data["segments"][0] == {
        "index": 0,
        "mode": "active",
        "memory_index": 0,
        "memory_offset": _DATA_OFFSET,
        "size": len(_DATA_PAYLOAD),
    }

    strings = parse_wasm_strings(module)
    assert strings["has_data_section"] is True
    assert "hello" in strings["strings"]
    assert "world" in strings["strings"]


def test_calls_and_callers_agree(module: Path) -> None:
    calls = parse_wasm_calls(module)
    assert calls["total"] == 2  # two local function bodies
    assert calls["imported_count"] == 1
    by_index = {row["index"]: row for row in calls["functions"]}
    # func 1 makes one direct call, to the imported env.log (index 0).
    assert by_index[1]["callees"] == [0]
    assert by_index[1]["call_sites"] == 1
    assert by_index[1]["call_indirect_sites"] == 0
    assert by_index[1]["decoded"] is True
    # func 2 dispatches through the table, so it is an indirect call site.
    assert by_index[2]["callees"] == []
    assert by_index[2]["call_indirect_sites"] == 1
    assert by_index[2]["decoded"] is True

    # The reverse view must name func 1 as the sole caller of the import.
    callers = parse_wasm_callers(module, function=0)
    assert callers["target"] == 0
    assert callers["undecoded_bodies"] == 0
    assert callers["callers"] == [{"index": 1, "call_sites": 1, "decoded": True}]


def test_names_producers_features_start(module: Path) -> None:
    names = parse_wasm_names(module)
    assert names["module"] == "mymod"
    assert names["has_name_section"] is True
    assert {row["index"]: row["name"] for row in names["functions"]} == {
        0: "log",
        1: "init",
        2: "main",
    }

    producers = parse_wasm_producers(module)
    assert producers["has_producers_section"] is True
    assert {(r["field"], r["name"], r["version"]) for r in producers["producers"]} == {
        ("language", "Rust", "1.75.0"),
        ("processed-by", "rustc", "1.75.0"),
    }

    features = parse_wasm_features(module)
    assert features["has_target_features_section"] is True
    assert {(r["name"], r["prefix"]) for r in features["features"]} == {
        ("simd128", "+"),
        ("bulk-memory", "+"),
    }

    start = parse_wasm_start(module)
    assert start == {
        "has_start_section": True,
        "start_function": 1,
        "kind": "local",
        "imported_count": 1,
        "truncated": False,
    }


def test_cross_tool_index_space_is_consistent(module: Path) -> None:
    """The tools must agree on the function index space and call edges."""
    functions = parse_wasm_functions(module)
    calls = parse_wasm_calls(module)
    elements = parse_wasm_elements(module)
    start = parse_wasm_start(module)

    imported = functions["imported_count"]
    total_functions = functions["total"]

    # The code section holds exactly the local (non-imported) functions.
    assert calls["total"] == total_functions - imported
    assert calls["imported_count"] == imported == start["imported_count"]

    # Every element-table target is a valid function index in the module.
    for row in elements["entries"]:
        assert 0 <= row["func_index"] < total_functions

    # The start function is a real function index, and here a local one.
    assert 0 <= start["start_function"] < total_functions
    assert start["start_function"] >= imported  # local => at or past the boundary

    # Forward and reverse call graphs describe the same edge (func 1 -> import 0).
    forward = {row["index"]: row["callees"] for row in calls["functions"]}
    assert 0 in forward[1]
    callers_of_0 = parse_wasm_callers(module, function=0)
    assert [row["index"] for row in callers_of_0["callers"]] == [1]

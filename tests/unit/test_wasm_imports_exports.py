"""The dependency-free WASM readers must recover a module's static surface.

wasm.imports / wasm.exports / wasm.sections / wasm.names / wasm.strings read the
WebAssembly binary directly (no wabt), so the tests build minimal but real
modules from bytes and assert the parsers resolve the import/export/section/name
surface and the Data-section literal pool, stay bounded on hostile/truncated
input, and never require a wabt install. Each parser is exercised directly and
through the WasmClient method that adds the file guard and pagination.
"""

from __future__ import annotations

import ast
import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import wasm_format as wf
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

_MAGIC = bytes.fromhex("0061736d01000000")


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _vec(items: list[bytes]) -> bytes:
    return bytes([len(items)]) + b"".join(items)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return bytes([len(raw)]) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id, len(body)]) + body


def _module(*sections: bytes) -> bytes:
    return _MAGIC + b"".join(sections)


# A func type (i32, i32) -> i32, the fixture's add() signature.
_FUNCTYPE = b"\x60" + _vec([b"\x7f", b"\x7f"]) + _vec([b"\x7f"])
_TYPE_SECTION = _section(1, _vec([_FUNCTYPE]))


def _import_section(*entries: bytes) -> bytes:
    return _section(2, _vec(list(entries)))


def _export_section(*entries: bytes) -> bytes:
    return _section(7, _vec(list(entries)))


def _custom_section(section_name: str, payload: bytes) -> bytes:
    return _section(0, _name(section_name) + payload)


def _subsection(sub_id: int, payload: bytes) -> bytes:
    return bytes([sub_id, len(payload)]) + payload


def _name_section(module_name: str | None, func_names: list[tuple[int, str]]) -> bytes:
    payload = b""
    if module_name is not None:
        payload += _subsection(0, _name(module_name))
    if func_names:
        name_map = bytes([len(func_names)]) + b"".join(
            bytes([index]) + _name(text) for index, text in func_names
        )
        payload += _subsection(1, name_map)
    return _custom_section("name", payload)


def test_parse_imports_resolves_func_signature_and_each_kind() -> None:
    """Every import kind decodes, and a func import gets its resolved signature.

    Measured: env.log func#0 -> params [i32,i32] results [i32]; env.memory
    memory -> limits min 1; js.g global -> value_type i32, mutable True. declared
    3, not incomplete.
    """
    imp_func = _name("env") + _name("log") + b"\x00" + b"\x00"
    imp_mem = _name("env") + _name("memory") + b"\x02" + b"\x00\x01"  # flag 0, min 1
    imp_glob = _name("js") + _name("g") + b"\x03" + b"\x7f\x01"  # i32, mutable
    module = _module(_TYPE_SECTION, _import_section(imp_func, imp_mem, imp_glob))

    entries, declared, incomplete = wf.parse_imports(module)
    assert declared == 3
    assert incomplete is False
    func, mem, glob = entries
    assert func == {
        "module": "env",
        "name": "log",
        "kind": "func",
        "type_index": 0,
        "params": ["i32", "i32"],
        "results": ["i32"],
    }
    assert mem == {"module": "env", "name": "memory", "kind": "memory", "limits": {"min": 1}}
    assert glob == {
        "module": "js",
        "name": "g",
        "kind": "global",
        "value_type": "i32",
        "mutable": True,
    }


def test_parse_imports_table_limits_carry_max_when_bounded() -> None:
    """A table import with a max bound reports both min and max."""
    imp_table = _name("env") + _name("tbl") + b"\x01" + b"\x70" + b"\x01\x02\x0a"
    entries, _declared, _incomplete = wf.parse_imports(_module(_import_section(imp_table)))
    assert entries[0] == {
        "module": "env",
        "name": "tbl",
        "kind": "table",
        "element_type": "funcref",
        "limits": {"min": 2, "max": 10},
    }


def test_parse_exports_reports_name_kind_and_index() -> None:
    """Exports decode to name/kind/index across the index spaces.

    Measured: add func#0 and mem memory#0 -> two rows, declared 2, not
    incomplete. This is the existing live-gate fixture's export shape.
    """
    exp = _export_section(
        _name("add") + b"\x00" + b"\x00",
        _name("mem") + b"\x02" + b"\x00",
    )
    entries, declared, incomplete = wf.parse_exports(_module(_TYPE_SECTION, exp))
    assert declared == 2
    assert incomplete is False
    assert entries == [
        {"name": "add", "kind": "func", "index": 0},
        {"name": "mem", "kind": "memory", "index": 0},
    ]


def test_parse_handles_a_module_with_no_import_or_export_section() -> None:
    """A module lacking the section yields an empty, complete answer, not an error."""
    bare = _module(_TYPE_SECTION)
    assert wf.parse_imports(bare) == ([], 0, False)
    assert wf.parse_exports(bare) == ([], 0, False)


def test_parse_rejects_a_non_module() -> None:
    """Bytes without the wasm magic are not a module at all (hard error)."""
    for bad in (b"", b"not wasm here", b"\x00asm"):  # too short / wrong magic
        with pytest.raises(wf.WasmParseError):
            wf.parse_imports(bad)
        with pytest.raises(wf.WasmParseError):
            wf.parse_exports(bad)


def test_parse_imports_flags_a_truncated_section_incomplete() -> None:
    """A section that claims more entries than its bytes hold stops and flags it.

    The header says 3 imports but the body ends mid-first-entry; the parser must
    return what it could (nothing here) with incomplete True and the declared 3,
    never reading past the buffer.
    """
    truncated_body = b"\x03\x03" + b"env"  # declared 3, then a dangling name len
    module = _module(_TYPE_SECTION, _section(2, truncated_body))
    entries, declared, incomplete = wf.parse_imports(module)
    assert declared == 3
    assert incomplete is True
    assert entries == []


def test_parse_imports_bounds_a_runaway_leb128_length() -> None:
    """A name length encoded as endless continuation bytes cannot spin the reader.

    declared 1, then a module-name length of five 0x80 continuation bytes; the
    width-capped LEB128 stops rather than looping, and the result is flagged
    incomplete instead of hanging or over-reading.
    """
    body = b"\x01" + b"\x80\x80\x80\x80\x80"
    module = _module(_section(2, body))
    entries, _declared, incomplete = wf.parse_imports(module)
    assert entries == []
    assert incomplete is True


def test_wasm_client_imports_pages_and_needs_no_wabt(tmp_path: Path) -> None:
    """WasmClient.imports reads a file, pages the list, and works with no wabt.

    Measured: a 3-import module through WasmClient(None) (no wabt configured) ->
    total 3, declared 3, incomplete False; limit 2 -> count 2, has_more True;
    offset 2 -> the last row, has_more False.
    """
    imp1 = _name("env") + _name("a") + b"\x00" + b"\x00"
    imp2 = _name("env") + _name("b") + b"\x00" + b"\x00"
    imp3 = _name("env") + _name("c") + b"\x00" + b"\x00"
    module = _module(_TYPE_SECTION, _import_section(imp1, imp2, imp3))
    path = tmp_path / "m.wasm"
    path.write_bytes(module)

    client = WasmClient(None)  # no wabt path; imports must still work
    first = client.imports(path, limit=2)
    assert first["total"] == 3
    assert first["declared"] == 3
    assert first["incomplete"] is False
    assert first["count"] == 2
    assert len(first["imports"]) == 2
    assert first["has_more"] is True
    assert "items" not in first
    second = client.imports(path, offset=2, limit=2)
    assert second["count"] == 1
    assert second["offset"] == 2
    assert second["has_more"] is False
    assert second["imports"][0]["name"] == "c"


def test_wasm_client_exports_reads_a_real_file(tmp_path: Path) -> None:
    """WasmClient.exports reads the Export section off disk with no wabt."""
    exp = _export_section(_name("run") + b"\x00" + b"\x00")
    path = tmp_path / "m.wasm"
    path.write_bytes(_module(_TYPE_SECTION, exp))
    payload = WasmClient(None).exports(path)
    assert payload["total"] == 1
    assert payload["exports"] == [{"name": "run", "kind": "func", "index": 0}]
    assert payload["incomplete"] is False


def test_wasm_client_imports_missing_file_is_not_found(tmp_path: Path) -> None:
    """A missing module is not_found, not a crash or a fabricated empty list."""
    with pytest.raises(JsReError) as info:
        WasmClient(None).imports(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_parse_names_reads_module_and_function_names() -> None:
    """The name section decodes the module name and the funcidx->name map.

    Measured: module name "mymod" plus func names {0: add, 3: main} ->
    present True, module_name mymod, two rows sorted by index, not incomplete.
    """
    module = _module(_name_section("mymod", [(3, "main"), (0, "add")]))
    present, module_name, functions, incomplete = wf.parse_names(module)
    assert present is True
    assert module_name == "mymod"
    assert incomplete is False
    assert functions == [
        {"index": 0, "name": "add"},
        {"index": 3, "name": "main"},
    ]


def test_parse_names_absent_section_reports_not_present() -> None:
    """A module with other custom sections but no "name" reports present False.

    A "producers" custom section must not be mistaken for the name section: the
    finder matches on the section's own name, so this returns present False --
    the stripped-module signal -- rather than misreading producers' bytes.
    """
    module = _module(_TYPE_SECTION, _custom_section("producers", b"\x00\x01"))
    present, module_name, functions, incomplete = wf.parse_names(module)
    assert present is False
    assert module_name is None
    assert functions == []
    assert incomplete is False


def test_parse_names_truncated_map_is_incomplete() -> None:
    """A func-name map claiming more rows than its bytes hold is flagged incomplete."""
    # name-map subsection says 5 entries but carries only one.
    bad_map = bytes([5]) + bytes([0]) + _name("add")
    module = _module(_custom_section("name", _subsection(1, bad_map)))
    present, _module_name, functions, incomplete = wf.parse_names(module)
    assert present is True
    assert functions == [{"index": 0, "name": "add"}]
    assert incomplete is True


def test_wasm_client_names_pages_and_flags_present(tmp_path: Path) -> None:
    """WasmClient.names reads a file, pages the map, and needs no wabt.

    Measured: a name section with 3 function names through WasmClient(None) ->
    present True, total 3; limit 2 -> count 2, has_more True; offset 2 -> the
    last row, has_more False.
    """
    module = _module(
        _TYPE_SECTION,
        _name_section("m", [(0, "a"), (1, "b"), (2, "c")]),
    )
    path = tmp_path / "m.wasm"
    path.write_bytes(module)
    client = WasmClient(None)
    first = client.names(path, limit=2)
    assert first["present"] is True
    assert first["module_name"] == "m"
    assert first["total"] == 3
    assert first["count"] == 2
    assert first["has_more"] is True
    assert "names" not in first  # the list field is function_names
    second = client.names(path, offset=2, limit=2)
    assert second["count"] == 1
    assert second["function_names"][0] == {"index": 2, "name": "c"}
    assert second["has_more"] is False


def test_wasm_client_names_stripped_module_is_present_false(tmp_path: Path) -> None:
    """A module with no name section answers present False, not an error."""
    path = tmp_path / "stripped.wasm"
    path.write_bytes(_module(_TYPE_SECTION))
    payload = WasmClient(None).names(path)
    assert payload["present"] is False
    assert payload["function_names"] == []
    assert payload["total"] == 0


def test_wasm_names_docstring_names_its_fields() -> None:
    doc = _tool_docstring("wasm.names")
    for token in ("present", "module_name", "function_names", "incomplete", "index"):
        assert token in doc


def test_wasm_import_export_docstrings_name_their_fields() -> None:
    """The catalog must name the list fields and the declared/incomplete contract."""
    imports_doc = _tool_docstring("wasm.imports")
    for token in ("imports", "declared", "incomplete", "params", "results", "kind"):
        assert token in imports_doc
    exports_doc = _tool_docstring("wasm.exports")
    for token in ("exports", "declared", "incomplete", "index", "kind"):
        assert token in exports_doc


def test_parse_sections_maps_layout_with_names_and_vector_counts() -> None:
    """The section map lists each section in file order with id/name/size/count.

    Measured on a type+import+export module: three rows named type/import/export,
    each vector-prefixed section carrying its entry count (type 1, import 2,
    export 1), the type section's body starting just past the 8-byte header and
    its own 2-byte section header (offset 10), and incomplete False.
    """
    imp1 = _name("env") + _name("a") + b"\x00" + b"\x00"
    imp2 = _name("env") + _name("b") + b"\x00" + b"\x00"
    exp = _name("run") + b"\x00" + b"\x00"
    module = _module(
        _TYPE_SECTION,
        _import_section(imp1, imp2),
        _export_section(exp),
    )
    sections, incomplete = wf.parse_sections(module)
    assert incomplete is False
    assert [(s["id"], s["name"], s.get("count")) for s in sections] == [
        (1, "type", 1),
        (2, "import", 2),
        (7, "export", 1),
    ]
    type_row = sections[0]
    assert type_row["offset"] == 10  # 8-byte module header + 2-byte section header
    assert type_row["size"] == len(_TYPE_SECTION) - 2  # body only, not the header
    # Every declared body sits within the file, in order, with no overlap.
    for row in sections:
        assert row["offset"] >= 0
        assert row["offset"] + row["size"] <= len(module)


def test_parse_sections_reads_a_custom_section_name() -> None:
    """A custom section is id 0 named "custom", tagged by its own custom_name.

    The two custom sections share id 0 and are told apart only by custom_name;
    neither carries a vector count, so count is absent on those rows.
    """
    module = _module(
        _TYPE_SECTION,
        _custom_section("name", b"\x00"),
        _custom_section("producers", b"\x00"),
    )
    sections, incomplete = wf.parse_sections(module)
    assert incomplete is False
    customs = [s for s in sections if s["id"] == 0]
    assert [s["name"] for s in customs] == ["custom", "custom"]
    assert [s["custom_name"] for s in customs] == ["name", "producers"]
    assert all("count" not in s for s in customs)


def test_parse_sections_reads_the_data_count_section_value() -> None:
    """The data_count section (id 12) is a single count, surfaced as count."""
    module = _module(_TYPE_SECTION, _section(12, b"\x05"))
    sections, _incomplete = wf.parse_sections(module)
    data_count = next(s for s in sections if s["id"] == 12)
    assert data_count["name"] == "data_count"
    assert data_count["count"] == 5


def test_parse_sections_renders_an_unknown_id_as_hex() -> None:
    """A nonstandard section id is visible as its hex byte, not dropped."""
    module = _module(_TYPE_SECTION, _section(200, b"\x00"))
    sections, incomplete = wf.parse_sections(module)
    assert incomplete is False
    unknown = next(s for s in sections if s["id"] == 200)
    assert unknown["name"] == "0xc8"
    assert "count" not in unknown  # only known vector/data_count rows carry count


def test_parse_sections_flags_a_section_overrunning_the_buffer() -> None:
    """A section whose declared size runs past the file stops and flags incomplete.

    The type section parses whole, then a function section (id 3) claims 50 bytes
    it does not have; the walk returns the rows it gathered with incomplete True
    rather than reading past the buffer.
    """
    module = _module(_TYPE_SECTION) + bytes([3, 50])  # id 3, size 50, no body
    sections, incomplete = wf.parse_sections(module)
    assert incomplete is True
    assert [s["id"] for s in sections] == [1]  # only the type section survived


def test_parse_sections_rejects_a_non_module() -> None:
    """Bytes without the wasm magic are not a module at all (hard error)."""
    for bad in (b"", b"not wasm here", b"\x00asm"):
        with pytest.raises(wf.WasmParseError):
            wf.parse_sections(bad)


def test_wasm_client_sections_pages_and_needs_no_wabt(tmp_path: Path) -> None:
    """WasmClient.sections reads a file, pages the map, and works with no wabt.

    Measured: a three-section module through WasmClient(None) -> total 3; limit 2
    -> count 2, has_more True, list field sections (not items); offset 2 -> the
    export row, has_more False.
    """
    imp = _name("env") + _name("a") + b"\x00" + b"\x00"
    exp = _name("run") + b"\x00" + b"\x00"
    module = _module(_TYPE_SECTION, _import_section(imp), _export_section(exp))
    path = tmp_path / "m.wasm"
    path.write_bytes(module)

    client = WasmClient(None)  # no wabt path; sections must still work
    first = client.sections(path, limit=2)
    assert first["total"] == 3
    assert first["incomplete"] is False
    assert first["count"] == 2
    assert len(first["sections"]) == 2
    assert first["has_more"] is True
    assert "items" not in first
    second = client.sections(path, offset=2, limit=2)
    assert second["count"] == 1
    assert second["offset"] == 2
    assert second["has_more"] is False
    assert second["sections"][0]["id"] == 7  # the export section


def test_wasm_client_sections_missing_file_is_not_found(tmp_path: Path) -> None:
    """A missing module is not_found, not a crash or a fabricated empty map."""
    with pytest.raises(JsReError) as info:
        WasmClient(None).sections(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_sections_docstring_names_its_fields() -> None:
    doc = _tool_docstring("wasm.sections")
    for token in ("sections", "custom_name", "count", "offset", "size", "incomplete"):
        assert token in doc


def _function_section(*type_indices: int) -> bytes:
    # Function section (id 3): a vector of one type index per defined function.
    return _section(3, _vec([bytes([index]) for index in type_indices]))


def test_parse_functions_lists_defined_functions_with_signatures() -> None:
    """Each defined function resolves to its absolute index and signature.

    Measured on a module with one func type (i32,i32)->i32 and a Function
    section of two functions both of type 0, no imports: two rows at absolute
    index 0 and 1, each with params [i32,i32] results [i32], declared 2, not
    incomplete.
    """
    module = _module(_TYPE_SECTION, _function_section(0, 0))
    entries, declared, incomplete = wf.parse_functions(module)
    assert declared == 2
    assert incomplete is False
    assert entries == [
        {"index": 0, "type_index": 0, "params": ["i32", "i32"], "results": ["i32"]},
        {"index": 1, "type_index": 0, "params": ["i32", "i32"], "results": ["i32"]},
    ]


def test_parse_functions_offsets_indices_past_imported_functions() -> None:
    """A defined function's index counts imported functions first.

    One func import (env.log) plus one memory import, then a single defined
    function: only the func import shifts the index space, so the defined
    function is absolute index 1, not 0 or 2.
    """
    imp_func = _name("env") + _name("log") + b"\x00" + b"\x00"
    imp_mem = _name("env") + _name("memory") + b"\x02" + b"\x00\x01"
    module = _module(
        _TYPE_SECTION,
        _import_section(imp_func, imp_mem),
        _function_section(0),
    )
    entries, _declared, incomplete = wf.parse_functions(module)
    assert incomplete is False
    assert entries == [
        {"index": 1, "type_index": 0, "params": ["i32", "i32"], "results": ["i32"]},
    ]


def test_parse_functions_resolves_names_from_the_name_section() -> None:
    """A named module carries each defined function's debug name on its row."""
    module = _module(
        _TYPE_SECTION,
        _function_section(0, 0),
        _name_section("m", [(0, "init"), (1, "run")]),
    )
    entries, _declared, _incomplete = wf.parse_functions(module)
    assert entries[0]["name"] == "init"
    assert entries[1]["name"] == "run"


def test_parse_functions_unknown_type_index_omits_signature() -> None:
    """A type index the Type section does not hold leaves the row without a sig.

    The row still reports its index and type_index -- an unresolved/future type
    is visible rather than dropped -- but carries no params/results to invent.
    """
    module = _module(_TYPE_SECTION, _function_section(9))
    entries, _declared, _incomplete = wf.parse_functions(module)
    assert entries == [{"index": 0, "type_index": 9}]


def test_parse_functions_no_function_section_is_empty_not_incomplete() -> None:
    """A module lacking a Function section yields an empty, complete answer."""
    assert wf.parse_functions(_module(_TYPE_SECTION)) == ([], 0, False)


def test_parse_functions_truncated_section_is_incomplete() -> None:
    """A section claiming more functions than its bytes hold stops and flags it."""
    # declares 3 type indices but carries only two.
    module = _module(_TYPE_SECTION, _section(3, b"\x03\x00\x00"))
    entries, declared, incomplete = wf.parse_functions(module)
    assert declared == 3
    assert incomplete is True
    assert [row["index"] for row in entries] == [0, 1]


def test_parse_functions_rejects_a_non_module() -> None:
    """Bytes without the wasm magic are not a module at all (hard error)."""
    for bad in (b"", b"not wasm here", b"\x00asm"):
        with pytest.raises(wf.WasmParseError):
            wf.parse_functions(bad)


def test_wasm_client_functions_pages_and_needs_no_wabt(tmp_path: Path) -> None:
    """WasmClient.functions reads a file, pages the table, and works with no wabt.

    Measured: a three-function module through WasmClient(None) -> total 3,
    declared 3, incomplete False; limit 2 -> count 2, has_more True, list field
    functions (not items); offset 2 -> the last row, has_more False.
    """
    module = _module(_TYPE_SECTION, _function_section(0, 0, 0))
    path = tmp_path / "m.wasm"
    path.write_bytes(module)

    client = WasmClient(None)  # no wabt path; functions must still work
    first = client.functions(path, limit=2)
    assert first["total"] == 3
    assert first["declared"] == 3
    assert first["incomplete"] is False
    assert first["count"] == 2
    assert len(first["functions"]) == 2
    assert first["has_more"] is True
    assert "items" not in first
    second = client.functions(path, offset=2, limit=2)
    assert second["count"] == 1
    assert second["offset"] == 2
    assert second["has_more"] is False
    assert second["functions"][0]["index"] == 2


def test_wasm_client_functions_missing_file_is_not_found(tmp_path: Path) -> None:
    """A missing module is not_found, not a crash or a fabricated empty table."""
    with pytest.raises(JsReError) as info:
        WasmClient(None).functions(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_functions_docstring_names_its_fields() -> None:
    doc = _tool_docstring("wasm.functions")
    for token in ("functions", "index", "type_index", "declared", "incomplete", "params", "name"):
        assert token in doc


def _sleb128(value: int) -> bytes:
    """Signed LEB128 encoder, so tests can craft real i32/i64.const immediates."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _global(value_type: int, mutable: int, init_expr: bytes) -> bytes:
    return bytes([value_type, mutable]) + init_expr


def _global_section(*globals_: bytes) -> bytes:
    return _section(6, _vec(list(globals_)))


def _i32_const(value: int) -> bytes:
    return b"\x41" + _sleb128(value) + b"\x0b"


def test_parse_globals_reads_type_mutability_and_int_init() -> None:
    """Each defined global resolves to its index, type, mutability and init value.

    Measured on two i32 globals: a const one initialised to 1048576 (a typical
    stack-pointer literal) at index 0, and a var one initialised to 0 at index 1;
    declared 2, not incomplete.
    """
    module = _module(
        _global_section(
            _global(0x7F, 0, _i32_const(1048576)),
            _global(0x7F, 1, _i32_const(0)),
        )
    )
    entries, declared, incomplete = wf.parse_globals(module)
    assert declared == 2
    assert incomplete is False
    assert entries == [
        {
            "index": 0,
            "value_type": "i32",
            "mutable": False,
            "init": {"op": "i32.const", "value": 1048576},
        },
        {
            "index": 1,
            "value_type": "i32",
            "mutable": True,
            "init": {"op": "i32.const", "value": 0},
        },
    ]


def test_parse_globals_decodes_a_negative_i32_const() -> None:
    """A negative init reads back signed (proves the sleb sign extension)."""
    module = _module(_global_section(_global(0x7F, 0, _i32_const(-7))))
    entries, _declared, _incomplete = wf.parse_globals(module)
    assert entries[0]["init"] == {"op": "i32.const", "value": -7}


def test_parse_globals_decodes_i64_and_float_consts() -> None:
    """i64.const past 2^32 and an f64.const literal both decode to their value."""
    i64_init = b"\x42" + _sleb128(5_000_000_000) + b"\x0b"
    f64_init = b"\x44" + struct.pack("<d", 3.5) + b"\x0b"
    module = _module(
        _global_section(
            _global(0x7E, 0, i64_init),  # i64
            _global(0x7C, 1, f64_init),  # f64
        )
    )
    entries, _declared, incomplete = wf.parse_globals(module)
    assert incomplete is False
    assert entries[0]["init"] == {"op": "i64.const", "value": 5_000_000_000}
    assert entries[1]["init"] == {"op": "f64.const", "value": 3.5}


def test_parse_globals_non_finite_float_keeps_op_drops_value() -> None:
    """A NaN/inf float const keeps op but omits value (not JSON-representable)."""
    f32_inf = b"\x43" + struct.pack("<f", float("inf")) + b"\x0b"
    module = _module(_global_section(_global(0x7D, 0, f32_inf)))
    entries, _declared, _incomplete = wf.parse_globals(module)
    assert entries[0]["init"] == {"op": "f32.const"}


def test_parse_globals_offsets_index_past_imported_globals() -> None:
    """A defined global's index counts imported globals first."""
    imp_glob = _name("js") + _name("g") + b"\x03" + b"\x7f\x01"  # global i32 mutable
    module = _module(
        _import_section(imp_glob),
        _global_section(_global(0x7F, 0, _i32_const(0))),
    )
    entries, _declared, _incomplete = wf.parse_globals(module)
    assert entries[0]["index"] == 1


def test_parse_globals_global_get_init_is_a_reference() -> None:
    """An init that is global.get reports the referenced index, not a literal."""
    module = _module(_global_section(_global(0x7F, 0, b"\x23\x00\x0b")))
    entries, _declared, _incomplete = wf.parse_globals(module)
    assert entries[0]["init"] == {"op": "global.get", "value": 0}


def test_parse_globals_no_global_section_is_empty_not_incomplete() -> None:
    """A module lacking a Global section yields an empty, complete answer."""
    assert wf.parse_globals(_module(_TYPE_SECTION)) == ([], 0, False)


def test_parse_globals_truncated_section_is_incomplete() -> None:
    """A section claiming more globals than its bytes hold stops and flags it."""
    # declares 2, carries one whole global then a dangling value-type byte.
    body = b"\x02" + _global(0x7F, 0, _i32_const(0)) + b"\x7f"
    module = _module(_section(6, body))
    entries, declared, incomplete = wf.parse_globals(module)
    assert declared == 2
    assert incomplete is True
    assert [row["index"] for row in entries] == [0]


def test_parse_globals_undecodable_init_is_incomplete() -> None:
    """An init opcode we cannot decode stops the walk and flags incomplete.

    0x00 (unreachable) is not a constant op, so its operand layout is unknown;
    the parser must not guess where the next global starts.
    """
    module = _module(_global_section(_global(0x7F, 0, b"\x00\x0b")))
    entries, _declared, incomplete = wf.parse_globals(module)
    assert entries == []
    assert incomplete is True


def test_parse_globals_rejects_a_non_module() -> None:
    """Bytes without the wasm magic are not a module at all (hard error)."""
    for bad in (b"", b"not wasm here", b"\x00asm"):
        with pytest.raises(wf.WasmParseError):
            wf.parse_globals(bad)


def test_wasm_client_globals_pages_and_needs_no_wabt(tmp_path: Path) -> None:
    """WasmClient.globals reads a file, pages the table, and works with no wabt.

    Measured: a three-global module through WasmClient(None) -> total 3,
    declared 3, incomplete False; limit 2 -> count 2, has_more True, list field
    globals (not items); offset 2 -> the last row, has_more False.
    """
    module = _module(
        _global_section(
            _global(0x7F, 0, _i32_const(1)),
            _global(0x7F, 0, _i32_const(2)),
            _global(0x7F, 0, _i32_const(3)),
        )
    )
    path = tmp_path / "m.wasm"
    path.write_bytes(module)

    client = WasmClient(None)  # no wabt path; globals must still work
    first = client.globals(path, limit=2)
    assert first["total"] == 3
    assert first["declared"] == 3
    assert first["incomplete"] is False
    assert first["count"] == 2
    assert len(first["globals"]) == 2
    assert first["has_more"] is True
    assert "items" not in first
    second = client.globals(path, offset=2, limit=2)
    assert second["count"] == 1
    assert second["offset"] == 2
    assert second["has_more"] is False
    assert second["globals"][0]["init"] == {"op": "i32.const", "value": 3}


def test_wasm_client_globals_missing_file_is_not_found(tmp_path: Path) -> None:
    """A missing module is not_found, not a crash or a fabricated empty table."""
    with pytest.raises(JsReError) as info:
        WasmClient(None).globals(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_globals_docstring_names_its_fields() -> None:
    doc = _tool_docstring("wasm.globals")
    for token in ("globals", "value_type", "mutable", "init", "index", "declared", "incomplete"):
        assert token in doc


_OFFSET0 = b"\x41\x00\x0b"  # (i32.const 0) end -- an offset expr at table position 0


def _elem_section(*segments: bytes) -> bytes:
    return _section(9, _vec(list(segments)))


def _funcvec(indices: list[int]) -> bytes:
    return _vec([bytes([index]) for index in indices])


def _reffunc_expr(index: int) -> bytes:
    return b"\xd2" + bytes([index]) + b"\x0b"  # (ref.func index) end


_REFNULL_EXPR = b"\xd0\x70\x0b"  # (ref.null func) end


def test_parse_elements_active_flag0_reads_offset_and_funcidx_vec() -> None:
    """The classic active segment: table 0, an offset, then a raw funcidx list.

    Measured: flags 0 with offset 0 and funcs [1,2,3] -> mode active, table 0,
    offset 0, func_count 3; declared 1, not incomplete.
    """
    module = _module(_elem_section(b"\x00" + _OFFSET0 + _funcvec([1, 2, 3])))
    entries, declared, incomplete = wf.parse_elements(module)
    assert declared == 1
    assert incomplete is False
    assert entries == [
        {
            "index": 0,
            "flags": 0,
            "mode": "active",
            "table": 0,
            "offset": 0,
            "func_count": 3,
            "funcs": [1, 2, 3],
        }
    ]


def test_parse_elements_active_flag2_has_table_index_and_offset() -> None:
    """flags 2 carries an explicit table index and its own offset expression."""
    segment = b"\x02" + bytes([1]) + b"\x41\x05\x0b" + b"\x00" + _funcvec([7])
    entries, _declared, incomplete = wf.parse_elements(_module(_elem_section(segment)))
    assert incomplete is False
    assert entries[0]["mode"] == "active"
    assert entries[0]["table"] == 1
    assert entries[0]["offset"] == 5
    assert entries[0]["funcs"] == [7]


def test_parse_elements_passive_flag1_has_no_table_or_offset() -> None:
    """A passive segment names no table and no offset -- just its funcidx list."""
    segment = b"\x01" + b"\x00" + _funcvec([4, 5])
    entries, _declared, _incomplete = wf.parse_elements(_module(_elem_section(segment)))
    assert entries[0]["mode"] == "passive"
    assert entries[0]["funcs"] == [4, 5]
    assert "table" not in entries[0]
    assert "offset" not in entries[0]


def test_parse_elements_declarative_flag3_reads_as_declarative() -> None:
    """flags 3 is a declarative segment (forward-declares funcs, fills no table)."""
    segment = b"\x03" + b"\x00" + _funcvec([9])
    entries, _declared, _incomplete = wf.parse_elements(_module(_elem_section(segment)))
    assert entries[0]["mode"] == "declarative"
    assert entries[0]["funcs"] == [9]
    assert "table" not in entries[0]


def test_parse_elements_expr_vec_flag4_reads_ref_func_and_null_slots() -> None:
    """flags 4 gives each slot as an expression: ref.func -> index, ref.null -> None."""
    segment = b"\x04" + _OFFSET0 + _vec([_reffunc_expr(2), _REFNULL_EXPR, _reffunc_expr(8)])
    entries, _declared, incomplete = wf.parse_elements(_module(_elem_section(segment)))
    assert incomplete is False
    assert entries[0]["mode"] == "active"
    assert entries[0]["offset"] == 0
    assert entries[0]["func_count"] == 3
    assert entries[0]["funcs"] == [2, None, 8]


def test_parse_elements_passive_expr_vec_flag5() -> None:
    """flags 5 is a passive expression vector prefixed by a reftype byte."""
    segment = b"\x05" + b"\x70" + _vec([_reffunc_expr(3)])
    entries, _declared, _incomplete = wf.parse_elements(_module(_elem_section(segment)))
    assert entries[0]["mode"] == "passive"
    assert entries[0]["funcs"] == [3]
    assert "offset" not in entries[0]


def test_parse_elements_no_element_section_is_empty_not_incomplete() -> None:
    """A module lacking an Element section yields an empty, complete answer."""
    assert wf.parse_elements(_module(_TYPE_SECTION)) == ([], 0, False)


def test_parse_elements_unknown_flags_is_incomplete() -> None:
    """A flags value above 7 is an encoding we do not know: stop and flag it."""
    entries, declared, incomplete = wf.parse_elements(_module(_elem_section(b"\x08\x00")))
    assert entries == []
    assert declared == 1
    assert incomplete is True


def test_parse_elements_truncated_segment_is_incomplete() -> None:
    """A section claiming more segments than its bytes hold stops and flags it."""
    # declares 2, carries one whole flag-0 segment then a dangling flags byte.
    body = bytes([2]) + (b"\x00" + _OFFSET0 + _funcvec([1])) + b"\x00"
    entries, declared, incomplete = wf.parse_elements(_module(_section(9, body)))
    assert declared == 2
    assert incomplete is True
    assert [row["index"] for row in entries] == [0]


def test_parse_elements_caps_a_segment_and_flags_funcs_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One over-cap segment yields a partial funcs list flagged funcs_truncated."""
    monkeypatch.setattr(wf, "_MAX_ELEM_FUNCS", 2)
    segment = b"\x00" + _OFFSET0 + _funcvec([1, 2, 3, 4])
    entries, _declared, _incomplete = wf.parse_elements(_module(_elem_section(segment)))
    assert entries[0]["func_count"] == 4
    assert entries[0]["funcs"] == [1, 2]
    assert entries[0]["funcs_truncated"] is True


def test_parse_elements_rejects_a_non_module() -> None:
    """Bytes without the wasm magic are not a module at all (hard error)."""
    for bad in (b"", b"not wasm here", b"\x00asm"):
        with pytest.raises(wf.WasmParseError):
            wf.parse_elements(bad)


def test_wasm_client_elements_pages_and_needs_no_wabt(tmp_path: Path) -> None:
    """WasmClient.elements reads a file, pages segments, and works with no wabt.

    Measured: a three-segment module through WasmClient(None) -> total 3,
    declared 3, incomplete False; limit 2 -> count 2, has_more True, list field
    elements (not items); offset 2 -> the last segment, has_more False.
    """
    module = _module(
        _elem_section(
            b"\x00" + _OFFSET0 + _funcvec([1]),
            b"\x00" + _OFFSET0 + _funcvec([2]),
            b"\x00" + _OFFSET0 + _funcvec([3]),
        )
    )
    path = tmp_path / "m.wasm"
    path.write_bytes(module)

    client = WasmClient(None)  # no wabt path; elements must still work
    first = client.elements(path, limit=2)
    assert first["total"] == 3
    assert first["declared"] == 3
    assert first["incomplete"] is False
    assert first["count"] == 2
    assert len(first["elements"]) == 2
    assert first["has_more"] is True
    assert "items" not in first
    second = client.elements(path, offset=2, limit=2)
    assert second["count"] == 1
    assert second["offset"] == 2
    assert second["has_more"] is False
    assert second["elements"][0]["funcs"] == [3]


def test_wasm_client_elements_missing_file_is_not_found(tmp_path: Path) -> None:
    """A missing module is not_found, not a crash or a fabricated empty table."""
    with pytest.raises(JsReError) as info:
        WasmClient(None).elements(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_elements_docstring_names_its_fields() -> None:
    doc = _tool_docstring("wasm.elements")
    for token in ("elements", "flags", "mode", "funcs", "func_count", "table", "incomplete"):
        assert token in doc


def _bytevec(payload: bytes) -> bytes:
    # A WASM byte vector: a LEB length prefix (single byte for len < 128) then
    # the raw bytes. All data-segment payloads here stay under that.
    return bytes([len(payload)]) + payload


def _data_active(payload: bytes, *, offset: int = 0) -> bytes:
    # flag 0: active segment into memory 0, offset = i32.const <offset>; end.
    return b"\x00" + b"\x41" + bytes([offset]) + b"\x0b" + _bytevec(payload)


def _data_passive(payload: bytes) -> bytes:
    # flag 1: passive segment, bytes only (no memory index, no offset expr).
    return b"\x01" + _bytevec(payload)


def _data_active_memidx(payload: bytes, *, memidx: int = 0, offset: int = 0) -> bytes:
    # flag 2: active into an explicit memory index, then offset expr, then bytes.
    return b"\x02" + bytes([memidx]) + b"\x41" + bytes([offset]) + b"\x0b" + _bytevec(payload)


def _data_section(*segments: bytes) -> bytes:
    return _section(11, _vec(list(segments)))


def test_parse_data_strings_extracts_printable_ascii_runs() -> None:
    """Printable runs in a data segment surface as distinct, sorted strings.

    Non-printable bytes split runs; a run shorter than min_len (default 4) is
    dropped. Measured on one active segment: "GET /path", "first_string" and
    "second-one" survive, the 2-char "hi" is dropped, one segment, not
    incomplete.
    """
    payload = b"first_string\x00\x00second-one\x01hi\x00GET /path"
    module = _module(_data_section(_data_active(payload)))
    strings, segments, incomplete = wf.parse_data_strings(module)
    assert segments == 1
    assert incomplete is False
    assert strings == ["GET /path", "first_string", "second-one"]


def test_parse_data_strings_respects_min_length() -> None:
    """min_len is the floor on run length: raising it drops the shorter runs."""
    module = _module(_data_section(_data_active(b"abc\x00abcd\x00abcde")))
    assert wf.parse_data_strings(module, min_len=3) == (["abc", "abcd", "abcde"], 1, False)
    assert wf.parse_data_strings(module, min_len=4) == (["abcd", "abcde"], 1, False)
    assert wf.parse_data_strings(module, min_len=5) == (["abcde"], 1, False)


def test_parse_data_strings_caps_individual_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run past the per-string clip is split, never returned as one giant string.

    With the clip lowered to 8, a 20-'A' run yields clipped 8-char pieces (and a
    4-char tail), so every returned string respects the cap.
    """
    monkeypatch.setattr(wf, "_MAX_STRING_CHARS", 8)
    module = _module(_data_section(_data_active(b"A" * 20)))
    strings, _segments, _incomplete = wf.parse_data_strings(module, min_len=4)
    assert strings  # something came back
    assert all(len(text) <= 8 for text in strings)
    assert "AAAAAAAA" in strings


def test_parse_data_strings_caps_distinct_strings_and_flags_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hitting the distinct-string cap stops collection and flags incomplete."""
    monkeypatch.setattr(wf, "_MAX_DATA_STRINGS", 2)
    payload = b"alpha\x00bravo\x00charlie\x00delta"
    module = _module(_data_section(_data_active(payload)))
    strings, _segments, incomplete = wf.parse_data_strings(module, min_len=4)
    assert len(strings) == 2
    assert incomplete is True


def test_parse_data_strings_handles_different_segment_flags() -> None:
    """Active (mem 0), passive, and active-with-memidx segments all decode.

    Each of the three segment encodings carries one string; all three are found,
    the segment count is 3, and nothing is incomplete.
    """
    module = _module(
        _data_section(
            _data_active(b"active_default"),
            _data_passive(b"passive_only"),
            _data_active_memidx(b"active_memidx"),
        )
    )
    strings, segments, incomplete = wf.parse_data_strings(module)
    assert segments == 3
    assert incomplete is False
    assert strings == ["active_default", "active_memidx", "passive_only"]


def test_parse_data_strings_skips_a_global_get_offset_expr() -> None:
    """An active segment whose offset is global.get (not a const) is still walked.

    Dynamically linked modules place data at a global-relative offset; the parser
    only needs to step past the init-expr to reach the bytes, so the string is
    still extracted with nothing flagged incomplete.
    """
    # flag 0, offset = global.get 0 (0x23 0x00) then end (0x0b), then the bytes.
    segment = b"\x00" + b"\x23\x00" + b"\x0b" + _bytevec(b"relocatable_string")
    module = _module(_data_section(segment))
    strings, segments, incomplete = wf.parse_data_strings(module)
    assert segments == 1
    assert incomplete is False
    assert strings == ["relocatable_string"]


def test_parse_data_strings_stops_on_an_unknown_offset_op() -> None:
    """An offset expr with an opcode we cannot skip stops the walk and flags it.

    Not knowing an opcode's immediate width means the byte after it is unknown,
    so the parser must not guess where the segment bytes begin: it returns what
    it had (nothing) with incomplete True rather than misreading the buffer.
    """
    # flag 0, offset expr = 0xd1 (ref.is_null, not a const op) -> unresolvable.
    segment = b"\x00" + b"\xd1" + b"\x0b" + _bytevec(b"unreachable_string")
    module = _module(_data_section(segment))
    strings, _segments, incomplete = wf.parse_data_strings(module)
    assert strings == []
    assert incomplete is True


def test_parse_data_strings_flags_a_truncated_segment_incomplete() -> None:
    """A segment claiming more bytes than the section holds stops and flags it."""
    # count 1, flag 0, i32.const 0, end, then a byte-vec of declared length 50
    # with no bytes following.
    body = b"\x01" + b"\x00" + b"\x41\x00\x0b" + b"\x32"
    module = _module(_section(11, body))
    strings, _segments, incomplete = wf.parse_data_strings(module)
    assert strings == []
    assert incomplete is True


def test_parse_data_strings_no_data_section_is_empty_not_incomplete() -> None:
    """A module without a Data section yields an empty, complete answer."""
    assert wf.parse_data_strings(_module(_TYPE_SECTION)) == ([], 0, False)


def test_parse_data_strings_rejects_a_non_module() -> None:
    """Bytes without the wasm magic are not a module at all (hard error)."""
    for bad in (b"", b"not wasm here", b"\x00asm"):
        with pytest.raises(wf.WasmParseError):
            wf.parse_data_strings(bad)


def test_wasm_client_strings_pages_and_filters(tmp_path: Path) -> None:
    """WasmClient.strings reads a file, filters by substring, pages, and needs no wabt.

    Measured on a segment holding four strings through WasmClient(None):
    total 4, min_length 4, data_segments 1, list field strings (not items);
    contains "API" (case-insensitive) -> two rows and filtered True; a blank
    filter is ignored; limit/offset page the filtered list with has_more.
    """
    payload = b"/api/login\x00/API/logout\x00static-token\x00banner text"
    module = _module(_data_section(_data_active(payload)))
    path = tmp_path / "m.wasm"
    path.write_bytes(module)

    client = WasmClient(None)  # no wabt path; strings must still work
    full = client.strings(path)
    assert full["total"] == 4
    assert full["min_length"] == 4
    assert full["data_segments"] == 1
    assert full["incomplete"] is False
    assert "filtered" not in full
    assert "items" not in full
    assert full["strings"] == sorted(full["strings"])

    filtered = client.strings(path, contains="API")
    assert filtered["filtered"] is True
    assert filtered["strings"] == ["/API/logout", "/api/login"]
    assert filtered["total"] == 2

    blank = client.strings(path, contains="   ")
    assert "filtered" not in blank
    assert blank["total"] == 4

    first = client.strings(path, contains="api", limit=1)
    assert first["count"] == 1
    assert first["has_more"] is True
    second = client.strings(path, contains="api", offset=1, limit=1)
    assert second["count"] == 1
    assert second["has_more"] is False
    assert first["strings"][0] != second["strings"][0]


def test_wasm_client_strings_min_length_is_bounded(tmp_path: Path) -> None:
    """min_length raises the floor and is clamped to at least 1."""
    module = _module(_data_section(_data_active(b"ab\x00abcd\x00abcdef")))
    path = tmp_path / "m.wasm"
    path.write_bytes(module)
    client = WasmClient(None)
    assert client.strings(path, min_length=6)["strings"] == ["abcdef"]
    low = client.strings(path, min_length=0)
    assert low["min_length"] == 1  # clamped up from 0
    assert "ab" in low["strings"]


def test_wasm_client_strings_missing_file_is_not_found(tmp_path: Path) -> None:
    """A missing module is not_found, not a crash or a fabricated empty list."""
    with pytest.raises(JsReError) as info:
        WasmClient(None).strings(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_strings_docstring_names_its_fields() -> None:
    doc = _tool_docstring("wasm.strings")
    for token in ("strings", "min_length", "data_segments", "incomplete", "filtered"):
        assert token in doc

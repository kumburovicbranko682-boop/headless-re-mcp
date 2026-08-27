"""wasm.imports / wasm.exports must read the module's host boundary from bytes.

These read the WebAssembly binary directly (no wabt), so the tests build minimal
but real modules from bytes and assert the parser resolves the import/export
surface, stays bounded on hostile/truncated input, and never requires a wabt
install. The parser is exercised directly and through the WasmClient methods
that add the file guard and pagination.
"""

from __future__ import annotations

import ast
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

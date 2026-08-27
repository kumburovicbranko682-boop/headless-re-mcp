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


def test_wasm_import_export_docstrings_name_their_fields() -> None:
    """The catalog must name the list fields and the declared/incomplete contract."""
    imports_doc = _tool_docstring("wasm.imports")
    for token in ("imports", "declared", "incomplete", "params", "results", "kind"):
        assert token in imports_doc
    exports_doc = _tool_docstring("wasm.exports")
    for token in ("exports", "declared", "incomplete", "index", "kind"):
        assert token in exports_doc

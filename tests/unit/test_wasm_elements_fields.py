"""Tests for WasmClient.elements, the table-fill (element-segment) reader.

Like the summary/globals tests these build tiny modules by hand so the parser
runs with no wabt: wasm.elements walks the module binary's table and element
sections directly, flattening every element segment into a resolved
slot->function map (the concrete set a call_indirect can reach) and folding in
the function names the name section gives each target. It handles all eight
element-segment flag encodings the reference-types/bulk-memory proposals define.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    JsReError,
    WasmClient,
    _parse_wasm_elements,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

FUNCREF, EXTERNREF = 0x70, 0x6F


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


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*sections: bytes) -> bytes:
    return b"\x00asm" + (1).to_bytes(4, "little") + b"".join(sections)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _i32_offset(value: int) -> bytes:
    return b"\x41" + _sleb(value) + b"\x0b"


def _global_get_offset(gidx: int) -> bytes:
    return b"\x23" + _uleb(gidx) + b"\x0b"


def _funcidx_vec(indices: tuple[int, ...]) -> bytes:
    return _uleb(len(indices)) + b"".join(_uleb(i) for i in indices)


def _ref_func(idx: int) -> bytes:
    return b"\xd2" + _uleb(idx) + b"\x0b"


def _ref_null(reftype: int = FUNCREF) -> bytes:
    return b"\xd0" + bytes([reftype]) + b"\x0b"


def _expr_vec(exprs: tuple[bytes, ...]) -> bytes:
    return _uleb(len(exprs)) + b"".join(exprs)


def _elem_active0(offset: int, *funcs: int) -> bytes:
    return _uleb(0) + _i32_offset(offset) + _funcidx_vec(funcs)


def _elem_active0_globaloffset(gidx: int, *funcs: int) -> bytes:
    return _uleb(0) + _global_get_offset(gidx) + _funcidx_vec(funcs)


def _elem_passive_funcidx(*funcs: int) -> bytes:
    return _uleb(1) + b"\x00" + _funcidx_vec(funcs)


def _elem_active_tableidx(table_index: int, offset: int, *funcs: int) -> bytes:
    return _uleb(2) + _uleb(table_index) + _i32_offset(offset) + b"\x00" + _funcidx_vec(funcs)


def _elem_declarative_funcidx(*funcs: int) -> bytes:
    return _uleb(3) + b"\x00" + _funcidx_vec(funcs)


def _elem_active0_expr(offset: int, *exprs: bytes) -> bytes:
    return _uleb(4) + _i32_offset(offset) + _expr_vec(exprs)


def _elem_passive_expr(reftype: int, *exprs: bytes) -> bytes:
    return _uleb(5) + bytes([reftype]) + _expr_vec(exprs)


def _elem_active_tableidx_expr(table_index: int, offset: int, reftype: int, *exprs: bytes) -> bytes:
    return _uleb(6) + _uleb(table_index) + _i32_offset(offset) + bytes([reftype]) + _expr_vec(exprs)


def _elem_declarative_expr(reftype: int, *exprs: bytes) -> bytes:
    return _uleb(7) + bytes([reftype]) + _expr_vec(exprs)


def _elem_section(*segments: bytes) -> bytes:
    return _section(9, _uleb(len(segments)) + b"".join(segments))


def _limits(minimum: int, maximum: int | None) -> bytes:
    if maximum is None:
        return b"\x00" + _uleb(minimum)
    return b"\x01" + _uleb(minimum) + _uleb(maximum)


def _table(reftype: int = FUNCREF, minimum: int = 1, maximum: int | None = None) -> bytes:
    return bytes([reftype]) + _limits(minimum, maximum)


def _table_section(*tables: bytes) -> bytes:
    return _section(4, _uleb(len(tables)) + b"".join(tables))


def _import_table(
    module: str, field: str, reftype: int = FUNCREF, minimum: int = 1, maximum: int | None = None
) -> bytes:
    return _name(module) + _name(field) + b"\x01" + bytes([reftype]) + _limits(minimum, maximum)


def _import_func(module: str, field: str, type_index: int) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(type_index)


def _import_section(*imports: bytes) -> bytes:
    return _section(2, _uleb(len(imports)) + b"".join(imports))


def _namemap_sub(sub_id: int, pairs: tuple[tuple[int, str], ...]) -> bytes:
    namemap = _uleb(len(pairs)) + b"".join(_uleb(i) + _name(nm) for i, nm in pairs)
    return bytes([sub_id]) + _uleb(len(namemap)) + namemap


def _name_section(
    func_names: tuple[tuple[int, str], ...] = (),
    elem_names: tuple[tuple[int, str], ...] = (),
) -> bytes:
    subs = b""
    if func_names:
        subs += _namemap_sub(1, func_names)
    if elem_names:
        subs += _namemap_sub(8, elem_names)
    return _section(0, _name("name") + subs)


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _elements(tmp_path: Path, data: bytes, **kw: object) -> dict:
    return WasmClient().elements(_write(tmp_path, data), **kw)  # type: ignore[arg-type]


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


def test_active_segment_resolves_slots_to_functions() -> None:
    """The headline case: an active funcidx segment maps table slots to funcs."""
    out = _parse_wasm_elements(
        _module(_table_section(_table(minimum=8)), _elem_section(_elem_active0(1, 0, 1))),
        module="m.wasm",
    )
    assert out["segment_count"] == 1
    (seg,) = out["segments"]
    assert seg["mode"] == "active"
    assert seg["table_index"] == 0
    assert seg["offset"] == 1
    assert seg["count"] == 2
    entries = seg["entries"]
    assert [(e["slot"], e["func"]) for e in entries] == [(1, 0), (2, 1)]


def test_table_declaration_is_listed() -> None:
    out = _parse_wasm_elements(
        _module(_table_section(_table(minimum=4, maximum=16))), module="m.wasm"
    )
    assert out["table_count"] == 1
    (tbl,) = out["tables"]
    assert tbl["index"] == 0
    assert tbl["element_type"] == "funcref"
    assert tbl["min"] == 4
    assert tbl["max"] == 16
    assert tbl["imported"] is False
    assert out["segment_count"] == 0


def test_imported_table_takes_the_low_index_space() -> None:
    out = _parse_wasm_elements(
        _module(
            _import_section(_import_table("env", "__indirect_function_table", minimum=2)),
            _table_section(_table(minimum=1)),
        ),
        module="m.wasm",
    )
    imported, defined = out["tables"]
    assert imported["index"] == 0
    assert imported["imported"] is True
    assert imported["module"] == "env"
    assert imported["import_name"] == "__indirect_function_table"
    assert defined["index"] == 1
    assert defined["imported"] is False


def test_a_func_import_does_not_consume_a_table_index() -> None:
    out = _parse_wasm_elements(
        _module(
            _import_section(
                _import_func("env", "log", 0),
                _import_table("env", "tbl", minimum=1),
            )
        ),
        module="m.wasm",
    )
    (tbl,) = out["tables"]
    assert tbl["index"] == 0
    assert tbl["import_name"] == "tbl"


def test_passive_segment_has_no_slot_or_table() -> None:
    out = _parse_wasm_elements(
        _module(_elem_section(_elem_passive_funcidx(3, 4))), module="m.wasm"
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "passive"
    assert "table_index" not in seg  # a passive segment fills no table
    assert "offset" not in seg
    for entry in seg["entries"]:
        assert entry["slot"] is None
        assert entry["table_index"] is None
    assert [e["func"] for e in seg["entries"]] == [3, 4]


def test_active_segment_with_explicit_table_index() -> None:
    out = _parse_wasm_elements(
        _module(
            _table_section(_table(minimum=1), _table(minimum=8)),
            _elem_section(_elem_active_tableidx(1, 2, 5)),
        ),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "active"
    assert seg["table_index"] == 1
    assert seg["offset"] == 2
    (entry,) = seg["entries"]
    assert entry["table_index"] == 1
    assert entry["slot"] == 2
    assert entry["func"] == 5


def test_declarative_segment_mode() -> None:
    out = _parse_wasm_elements(
        _module(_elem_section(_elem_declarative_funcidx(7))), module="m.wasm"
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "declarative"
    assert seg["entries"][0]["func"] == 7
    assert seg["entries"][0]["slot"] is None


def test_active_element_expression_segment() -> None:
    """Flag 4: an active segment whose entries are ref.func expressions."""
    out = _parse_wasm_elements(
        _module(_elem_section(_elem_active0_expr(0, _ref_func(2), _ref_func(9)))),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "active"
    assert seg["element_type"] == "funcref"
    assert [(e["slot"], e["func"]) for e in seg["entries"]] == [(0, 2), (1, 9)]


def test_passive_element_expression_with_reftype() -> None:
    """Flag 5: passive elemexpr carrying an explicit externref reftype."""
    out = _parse_wasm_elements(
        _module(_elem_section(_elem_passive_expr(EXTERNREF, _ref_null(EXTERNREF)))),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "passive"
    assert seg["element_type"] == "externref"
    assert seg["entries"][0]["func"] is None  # ref.null has no target


def test_active_tableidx_element_expression() -> None:
    """Flag 6: active elemexpr with an explicit table index and reftype."""
    out = _parse_wasm_elements(
        _module(
            _table_section(_table(minimum=1), _table(minimum=4)),
            _elem_section(_elem_active_tableidx_expr(1, 3, FUNCREF, _ref_func(1))),
        ),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["table_index"] == 1
    assert seg["offset"] == 3
    assert seg["entries"][0]["slot"] == 3
    assert seg["entries"][0]["func"] == 1


def test_declarative_element_expression() -> None:
    """Flag 7: declarative elemexpr with a reftype."""
    out = _parse_wasm_elements(
        _module(_elem_section(_elem_declarative_expr(FUNCREF, _ref_func(4)))),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "declarative"
    assert seg["entries"][0]["func"] == 4


def test_ref_null_entry_has_no_target() -> None:
    out = _parse_wasm_elements(
        _module(_elem_section(_elem_active0_expr(0, _ref_func(1), _ref_null()))),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    funcs = [e["func"] for e in seg["entries"]]
    assert funcs == [1, None]


def test_global_get_offset_leaves_slot_unknown() -> None:
    out = _parse_wasm_elements(
        _module(_elem_section(_elem_active0_globaloffset(0, 5, 6))), module="m.wasm"
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "active"
    assert seg["offset"] is None  # base is an imported global.get
    for entry in seg["entries"]:
        assert entry["slot"] is None  # slot cannot be computed without a base
        assert entry["func"] in (5, 6)


def test_name_section_resolves_targets_and_segment_names() -> None:
    out = _parse_wasm_elements(
        _module(
            _elem_section(_elem_active0(0, 0, 1)),
            _name_section(func_names=((0, "draw"), (1, "clear")), elem_names=((0, "vtable"),)),
        ),
        module="m.wasm",
    )
    assert out["has_name_section"] is True
    (seg,) = out["segments"]
    assert seg["name"] == "vtable"
    labels = [(e["func"], e.get("func_name")) for e in seg["entries"]]
    assert labels == [(0, "draw"), (1, "clear")]


def test_no_element_section_is_a_clean_empty_result() -> None:
    out = _parse_wasm_elements(_module(_table_section(_table(minimum=1))), module="m.wasm")
    assert out["segments"] == []
    assert out["segment_count"] == 0
    assert out["table_count"] == 1
    assert out["has_name_section"] is False


def test_bad_magic_is_a_clean_backend_error() -> None:
    with pytest.raises(JsReError) as excinfo:
        _parse_wasm_elements(b"not a wasm module", module="junk.bin")
    assert excinfo.value.code == "backend_error"


def test_a_truncated_segment_stops_and_keeps_what_parsed() -> None:
    payload = _uleb(2) + _elem_active0(0, 1)  # claims 2 segments, supplies one
    out = _parse_wasm_elements(_module(_section(9, payload)), module="m.wasm")
    assert out["parse_stopped"] is True
    assert out["segment_count"] == 1
    assert out["segments"][0]["entries"][0]["func"] == 1


def test_collection_cap_flattens_and_discloses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_ELEMENTS_COLLECT", 2)
    out = _elements(
        tmp_path,
        _module(_elem_section(_elem_active0(0, 0, 1, 2, 3, 4))),
    )
    assert out["scan_capped"] is True
    assert out["total"] == 2  # only two materialised despite five declared
    assert out["segments"][0]["count"] == 5  # the declared count stays honest


def test_flatten_orders_by_segment_then_index() -> None:
    out = _parse_wasm_elements(
        _module(
            _elem_section(
                _elem_active0(0, 10, 11),
                _elem_active0(5, 12),
            )
        ),
        module="m.wasm",
    )
    assert out["segment_count"] == 2


def test_pagination_windows_the_flattened_list(tmp_path: Path) -> None:
    module = _module(_elem_section(_elem_active0(0, 0, 1, 2, 3, 4)))
    page = _elements(tmp_path, module, offset=1, limit=2)
    assert page["offset"] == 1
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True
    assert [e["func"] for e in page["elements"]] == [1, 2]
    # The paginated segment summary drops the heavy per-entry list.
    assert "entries" not in page["segments"][0]


def test_missing_file_is_not_found() -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().elements(Path("/no/such/module.wasm"))
    assert excinfo.value.code == "not_found"


def test_service_wires_through(tmp_path: Path) -> None:
    """The service method returns the resolved table under the wabt backend tag."""
    service = AnalysisService(Settings.load())
    path = _write(
        tmp_path,
        _module(
            _table_section(_table(minimum=8)),
            _elem_section(_elem_active0(1, 0, 1)),
            _name_section(func_names=((0, "inc"), (1, "dec"))),
        ),
    )
    result = service.wasm_elements(str(path))
    assert result.ok, result.error
    assert result.data is not None
    assert result.meta.get("backend") == "wabt"
    assert result.data["total"] == 2
    labels = {e["slot"]: e.get("func_name") for e in result.data["elements"]}
    assert labels == {1: "inc", 2: "dec"}


def test_service_reports_a_bad_module_cleanly(tmp_path: Path) -> None:
    service = AnalysisService(Settings.load())
    path = _write(tmp_path, b"\x00asm\x01\x00\x00", name="bad.wasm")
    result = service.wasm_elements(str(path))
    assert not result.ok
    assert result.error is not None


def test_docstring_frames_it_as_indirect_call_resolution() -> None:
    doc = _tool_docstring("wasm.elements")
    for token in ("call_indirect", "slot", "func", "segments", "tables", "has_more"):
        assert token in doc, token

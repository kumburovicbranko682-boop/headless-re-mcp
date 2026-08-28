"""Tests for WasmClient.globals, the module global-variable table reader.

Like the summary/names/data tests these build tiny modules by hand so the
parser runs with no wabt: wasm.globals walks the module binary's import and
global sections directly, resolving each global's type, mutability and init
expression, and folds in the names an export or the name section gives it. The
memory-layout anchors it surfaces (__stack_pointer, __heap_base, __data_end)
are the wasm analogue of a data/.bss symbol table.
"""

from __future__ import annotations

import ast
import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    JsReError,
    WasmClient,
    _parse_wasm_globals,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

I32, I64, F32, F64 = 0x7F, 0x7E, 0x7D, 0x7C
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


def _mut(mutable: bool) -> int:
    return 1 if mutable else 0


def _global_i32(value: int, *, mutable: bool = False) -> bytes:
    return bytes([I32, _mut(mutable)]) + b"\x41" + _sleb(value) + b"\x0b"


def _global_i64(value: int, *, mutable: bool = False) -> bytes:
    return bytes([I64, _mut(mutable)]) + b"\x42" + _sleb(value) + b"\x0b"


def _global_f32(value: float, *, mutable: bool = False) -> bytes:
    return bytes([F32, _mut(mutable)]) + b"\x43" + struct.pack("<f", value) + b"\x0b"


def _global_f64(value: float, *, mutable: bool = False) -> bytes:
    return bytes([F64, _mut(mutable)]) + b"\x44" + struct.pack("<d", value) + b"\x0b"


def _global_get(valtype: int, gidx: int, *, mutable: bool = False) -> bytes:
    return bytes([valtype, _mut(mutable)]) + b"\x23" + _uleb(gidx) + b"\x0b"


def _global_ref_null(valtype: int, reftype: int, *, mutable: bool = False) -> bytes:
    return bytes([valtype, _mut(mutable)]) + b"\xd0" + bytes([reftype]) + b"\x0b"


def _global_add(a: int, b: int, *, mutable: bool = False) -> bytes:
    body = b"\x41" + _sleb(a) + b"\x41" + _sleb(b) + b"\x6a" + b"\x0b"
    return bytes([I32, _mut(mutable)]) + body


def _global_section(*globs: bytes) -> bytes:
    return _section(6, _uleb(len(globs)) + b"".join(globs))


def _import_global(module: str, field: str, valtype: int, *, mutable: bool = False) -> bytes:
    return _name(module) + _name(field) + b"\x03" + bytes([valtype, _mut(mutable)])


def _import_func(module: str, field: str, type_index: int) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(type_index)


def _import_section(*imports: bytes) -> bytes:
    return _section(2, _uleb(len(imports)) + b"".join(imports))


def _export_global(name: str, index: int) -> bytes:
    return _name(name) + b"\x03" + _uleb(index)


def _export_section(*exports: bytes) -> bytes:
    return _section(7, _uleb(len(exports)) + b"".join(exports))


def _global_name_section(*pairs: tuple[int, str]) -> bytes:
    namemap = _uleb(len(pairs)) + b"".join(_uleb(i) + _name(nm) for i, nm in pairs)
    sub = bytes([7]) + _uleb(len(namemap)) + namemap
    return _section(0, _name("name") + sub)


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _globals(tmp_path: Path, data: bytes, **kw: object) -> dict:
    return WasmClient().globals(_write(tmp_path, data), **kw)  # type: ignore[arg-type]


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


def test_defined_i32_global_carries_type_mut_and_init_value() -> None:
    """The headline case: a defined i32 global with an i32.const initializer."""
    out = _parse_wasm_globals(
        _module(_global_section(_global_i32(66560, mutable=True))), module="m.wasm"
    )
    assert out["global_count"] == 1
    assert out["imported_count"] == 0
    assert out["defined_count"] == 1
    (g,) = out["globals"]
    assert g["index"] == 0
    assert g["type"] == "i32"
    assert g["mutable"] is True
    assert g["imported"] is False
    assert g["init"] == "i32.const 66560"
    assert g["init_value"] == 66560


def test_imported_global_takes_the_low_index_space() -> None:
    """An imported global gets index 0; a defined one continues after it."""
    out = _parse_wasm_globals(
        _module(
            _import_section(_import_global("env", "memBase", I32)),
            _global_section(_global_i32(0, mutable=True)),
        ),
        module="m.wasm",
    )
    assert out["imported_count"] == 1
    assert out["defined_count"] == 1
    assert out["global_count"] == 2
    imported, defined = out["globals"]
    assert imported["index"] == 0
    assert imported["imported"] is True
    assert imported["module"] == "env"
    assert imported["import_name"] == "memBase"
    assert "init" not in imported  # an imported global has no init expression
    assert defined["index"] == 1
    assert defined["imported"] is False


def test_a_func_import_does_not_consume_a_global_index() -> None:
    """Only global imports advance the global index space."""
    out = _parse_wasm_globals(
        _module(
            _import_section(
                _import_func("env", "log", 0),
                _import_global("env", "sp", I32, mutable=True),
            ),
            _global_section(_global_i32(1)),
        ),
        module="m.wasm",
    )
    imported, defined = out["globals"]
    assert imported["index"] == 0  # the func import did not take index 0
    assert imported["import_name"] == "sp"
    assert defined["index"] == 1


def test_mutability_flag_distinguishes_const_from_var() -> None:
    out = _parse_wasm_globals(
        _module(_global_section(_global_i32(1), _global_i32(2, mutable=True))),
        module="m.wasm",
    )
    const_g, var_g = out["globals"]
    assert const_g["mutable"] is False
    assert var_g["mutable"] is True


def test_all_numeric_value_types_render() -> None:
    out = _parse_wasm_globals(
        _module(
            _global_section(
                _global_i32(1),
                _global_i64(2),
                _global_f32(1.5),
                _global_f64(2.5),
            )
        ),
        module="m.wasm",
    )
    types = [g["type"] for g in out["globals"]]
    assert types == ["i32", "i64", "f32", "f64"]
    values = [g["init_value"] for g in out["globals"]]
    assert values == [1, 2, 1.5, 2.5]


def test_i64_const_keeps_a_large_value() -> None:
    out = _parse_wasm_globals(
        _module(_global_section(_global_i64(0x1_0000_0001))), module="m.wasm"
    )
    (g,) = out["globals"]
    assert g["init"] == "i64.const 4294967297"
    assert g["init_value"] == 0x1_0000_0001


def test_global_get_init_has_no_plain_value() -> None:
    """A global.get initializer (an imported base) renders but carries no value."""
    out = _parse_wasm_globals(
        _module(
            _import_section(_import_global("env", "base", I32)),
            _global_section(_global_get(I32, 0)),
        ),
        module="m.wasm",
    )
    defined = out["globals"][1]
    assert defined["init"] == "global.get 0"
    assert "init_value" not in defined


def test_ref_null_initializer_renders_reftype() -> None:
    out = _parse_wasm_globals(
        _module(_global_section(_global_ref_null(FUNCREF, FUNCREF))), module="m.wasm"
    )
    (g,) = out["globals"]
    assert g["type"] == "funcref"
    assert g["init"] == "ref.null funcref"
    assert "init_value" not in g


def test_extended_const_arithmetic_renders_but_has_no_single_value() -> None:
    out = _parse_wasm_globals(
        _module(_global_section(_global_add(4, 4))), module="m.wasm"
    )
    (g,) = out["globals"]
    assert g["init"] == "i32.const 4 i32.const 4 i32.add"
    assert "init_value" not in g


def test_name_section_resolves_a_global_name() -> None:
    out = _parse_wasm_globals(
        _module(
            _global_section(_global_i32(66560, mutable=True)),
            _global_name_section((0, "__stack_pointer")),
        ),
        module="m.wasm",
    )
    (g,) = out["globals"]
    assert g["name"] == "__stack_pointer"
    assert out["has_name_section"] is True


def test_export_names_attach_to_the_global() -> None:
    out = _parse_wasm_globals(
        _module(
            _global_section(_global_i32(0, mutable=True)),
            _export_section(_export_global("g0", 0)),
        ),
        module="m.wasm",
    )
    (g,) = out["globals"]
    assert g["exported_as"] == ["g0"]
    assert out["has_name_section"] is False


def test_imported_externref_global_type() -> None:
    out = _parse_wasm_globals(
        _module(_import_section(_import_global("env", "tbl", EXTERNREF))),
        module="m.wasm",
    )
    (g,) = out["globals"]
    assert g["type"] == "externref"
    assert g["imported"] is True


def test_no_global_or_import_section_is_a_clean_empty_table() -> None:
    out = _parse_wasm_globals(_module(), module="m.wasm")
    assert out["globals"] == []
    assert out["global_count"] == 0
    assert out["imported_count"] == 0
    assert out["defined_count"] == 0
    assert out["has_name_section"] is False


def test_bad_magic_is_a_clean_backend_error() -> None:
    with pytest.raises(JsReError) as excinfo:
        _parse_wasm_globals(b"not a wasm module", module="junk.bin")
    assert excinfo.value.code == "backend_error"


def test_a_truncated_global_section_stops_and_keeps_what_parsed() -> None:
    """A declared-but-missing second global desyncs the vec: parse_stopped, one kept."""
    payload = _uleb(2) + _global_i32(7)  # claims 2 globals, supplies one
    out = _parse_wasm_globals(_module(_section(6, payload)), module="m.wasm")
    assert out["parse_stopped"] is True
    assert len(out["globals"]) == 1
    assert out["globals"][0]["init_value"] == 7
    assert out["defined_count"] == 2  # the declared count is still disclosed


def test_collection_cap_truncates_and_discloses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_GLOBALS_COLLECT", 2)
    out = _parse_wasm_globals(
        _module(_global_section(*[_global_i32(i) for i in range(5)])),
        module="m.wasm",
    )
    assert out["globals_truncated"] is True
    assert len(out["globals"]) == 2
    assert out["defined_count"] == 5


def test_contains_filters_over_names_and_types(tmp_path: Path) -> None:
    out = _globals(
        tmp_path,
        _module(
            _global_section(
                _global_i32(66560, mutable=True),
                _global_i32(0, mutable=True),
            ),
            _global_name_section((0, "__stack_pointer"), (1, "counter")),
        ),
        contains="stack",
    )
    assert out["contains"] == "stack"
    assert out["total"] == 1
    assert [g["name"] for g in out["globals"]] == ["__stack_pointer"]
    # global_count still reflects the whole module, not the filtered view.
    assert out["global_count"] == 2


def test_pagination_windows_the_table(tmp_path: Path) -> None:
    module = _module(_global_section(*[_global_i32(i) for i in range(5)]))
    page = _globals(tmp_path, module, offset=1, limit=2)
    assert page["offset"] == 1
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True
    assert [g["index"] for g in page["globals"]] == [1, 2]


def test_missing_file_is_not_found() -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().globals(Path("/no/such/module.wasm"))
    assert excinfo.value.code == "not_found"


def test_service_wires_through(tmp_path: Path) -> None:
    """The service method returns the table under the wabt backend tag."""
    service = AnalysisService(Settings.load())
    path = _write(
        tmp_path,
        _module(
            _import_section(_import_global("env", "base", I32)),
            _global_section(_global_i32(66560, mutable=True)),
            _global_name_section((1, "__stack_pointer")),
        ),
    )
    result = service.wasm_globals(str(path))
    assert result.ok, result.error
    assert result.data is not None
    assert result.meta.get("backend") == "wabt"
    assert result.data["global_count"] == 2
    names = {g["index"]: g.get("name") for g in result.data["globals"]}
    assert names[1] == "__stack_pointer"


def test_service_reports_a_bad_module_cleanly(tmp_path: Path) -> None:
    service = AnalysisService(Settings.load())
    path = _write(tmp_path, b"\x00asm\x01\x00\x00", name="bad.wasm")
    result = service.wasm_globals(str(path))
    assert not result.ok
    assert result.error is not None


def test_docstring_frames_it_as_the_global_symbol_table() -> None:
    doc = _tool_docstring("wasm.globals")
    for token in ("index", "mutable", "init", "imported", "wasm.summary", "has_more"):
        assert token in doc, token

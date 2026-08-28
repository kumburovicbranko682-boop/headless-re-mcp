"""wasm.tables lists table definitions (reftype + limits), imported first."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_tables
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


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


def _name_bytes(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


# limits: flag 0 => min only; flag 1 => min, max.
def _limits_min(minimum: int) -> bytes:
    return b"\x00" + _uleb(minimum)


def _limits_min_max(minimum: int, maximum: int) -> bytes:
    return b"\x01" + _uleb(minimum) + _uleb(maximum)


_FUNCREF = 0x70
_EXTERNREF = 0x6F


def _defined_table(reftype: int, limits: bytes) -> bytes:
    return bytes([reftype]) + limits


def _table_section(tables: list[bytes]) -> bytes:
    return _section(4, _uleb(len(tables)) + b"".join(tables))


def _import_table(module: str, name: str, reftype: int, limits: bytes) -> bytes:
    # import entry: module, name, kind=1 (table), reftype, limits.
    return _name_bytes(module) + _name_bytes(name) + b"\x01" + bytes([reftype]) + limits


def _import_section(entries: list[bytes]) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _module(*sections: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


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


def test_tables_decode_defined_reftype_and_limits() -> None:
    module = _module(_table_section([_defined_table(_FUNCREF, _limits_min_max(1, 10))]))
    result = list_wasm_tables(module)
    assert result["total"] == 1
    assert result["defined_count"] == 1
    assert result["imported_count"] == 0
    table = result["tables"][0]
    assert table["index"] == 0
    assert table["origin"] == "defined"
    assert table["element_type"] == "funcref"
    assert table["limits"]["initial"] == 1
    assert table["limits"]["maximum"] == 10
    assert table["module"] is None


def test_tables_place_imported_tables_first() -> None:
    module = _module(
        _import_section([_import_table("env", "__indirect", _FUNCREF, _limits_min(5))]),
        _table_section([_defined_table(_EXTERNREF, _limits_min(0))]),
    )
    result = list_wasm_tables(module)
    assert result["imported_count"] == 1
    assert result["defined_count"] == 1
    assert result["total"] == 2
    imported = result["tables"][0]
    assert imported["index"] == 0
    assert imported["origin"] == "imported"
    assert imported["module"] == "env"
    assert imported["name"] == "__indirect"
    assert imported["element_type"] == "funcref"
    defined = result["tables"][1]
    assert defined["index"] == 1
    assert defined["origin"] == "defined"
    assert defined["element_type"] == "externref"


def test_tables_on_a_module_without_a_table_section() -> None:
    result = list_wasm_tables(_module())
    assert result["total"] == 0
    assert result["tables"] == []
    assert result["resolved"] is True


def test_tables_page_the_listing() -> None:
    module = _module(
        _table_section(
            [
                _defined_table(_FUNCREF, _limits_min(1)),
                _defined_table(_FUNCREF, _limits_min(2)),
            ]
        )
    )
    result = list_wasm_tables(module, offset=0, limit=1)
    assert result["count"] == 1
    assert result["total"] == 2
    assert result["has_more"] is True


def test_tables_degrade_on_a_malformed_table_section() -> None:
    # Claims one table then truncates before the limits flag byte.
    module = _module(_section(4, _uleb(1) + bytes([_FUNCREF])))
    result = list_wasm_tables(module)
    assert result["resolved"] is False
    assert result["tables"] == []


def test_wasm_client_tables_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_table_section([_defined_table(_FUNCREF, _limits_min(3))])))
    result = WasmClient(None).tables(module)
    assert result["tables"][0]["limits"]["initial"] == 3


def test_wasm_client_tables_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"not wasm")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).tables(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_tables_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.tables")
    assert "element_type" in doc
    assert "imported_count" in doc
    assert "resolved" in doc

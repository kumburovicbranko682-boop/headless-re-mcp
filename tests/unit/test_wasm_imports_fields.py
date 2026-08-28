"""wasm.imports lists imports and resolves function-import signatures."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_imports
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


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*, with_types: bool = True) -> bytes:
    # Two types: (i32,i32)->i32 and ()->()
    type0 = b"\x60" + _vec([b"\x7f", b"\x7f"]) + _vec([b"\x7f"])
    type1 = b"\x60" + _vec([]) + _vec([])
    type_sec = _section(1, _vec([type0, type1]))

    imports = [
        # func import wasi_snapshot_preview1.fd_write, type 0 -> func_index 0
        _name("wasi_snapshot_preview1") + _name("fd_write") + b"\x00" + _uleb(0),
        # func import env.abort, type 1 -> func_index 1
        _name("env") + _name("abort") + b"\x00" + _uleb(1),
        # memory import env.memory, limits {min:1}
        _name("env") + _name("memory") + b"\x02" + b"\x00" + _uleb(1),
        # global import env.tableBase, i32 immutable
        _name("env") + _name("tableBase") + b"\x03" + b"\x7f" + b"\x00",
        # table import env.table, funcref limits {min:0}
        _name("env") + _name("table") + b"\x01" + b"\x70" + b"\x00" + _uleb(0),
    ]
    import_sec = _section(2, _vec(imports))

    module = b"\x00asm\x01\x00\x00\x00"
    if with_types:
        module += type_sec
    module += import_sec
    return module


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


def test_imports_resolve_function_signatures_and_index() -> None:
    result = list_wasm_imports(_module())
    assert result["total"] == 5
    assert result["types_resolved"] is True
    assert result["imported_func_count"] == 2

    by_name = {row["name"]: row for row in result["imports"]}

    fd_write = by_name["fd_write"]
    assert fd_write["module"] == "wasi_snapshot_preview1"
    assert fd_write["kind"] == "func"
    assert fd_write["func_index"] == 0
    assert fd_write["type_index"] == 0
    assert fd_write["params"] == ["i32", "i32"]
    assert fd_write["results"] == ["i32"]

    abort = by_name["abort"]
    assert abort["func_index"] == 1
    assert abort["params"] == []
    assert abort["results"] == []


def test_imports_carry_non_function_descriptors() -> None:
    result = list_wasm_imports(_module())
    by_name = {row["name"]: row for row in result["imports"]}

    memory = by_name["memory"]
    assert memory["kind"] == "memory"
    assert memory["limits"]["initial"] == 1
    assert "params" not in memory

    table_base = by_name["tableBase"]
    assert table_base["kind"] == "global"
    assert table_base["value_type"] == "i32"
    assert table_base["mutable"] is False

    table = by_name["table"]
    assert table["kind"] == "table"
    assert table["element_type"] == "funcref"


def test_imports_survive_a_module_with_no_import_section() -> None:
    module = b"\x00asm\x01\x00\x00\x00"
    result = list_wasm_imports(module)
    assert result["total"] == 0
    assert result["imports"] == []
    assert result["imported_func_count"] == 0


def test_imports_page_the_listing() -> None:
    result = list_wasm_imports(_module(), offset=1, limit=2)
    assert result["count"] == 2
    assert result["total"] == 5
    assert result["offset"] == 1
    assert result["has_more"] is True


def test_imports_degrade_without_a_type_section() -> None:
    result = list_wasm_imports(_module(with_types=False))
    # No type section: func imports keep func_index but not params/results.
    fd_write = next(r for r in result["imports"] if r["name"] == "fd_write")
    assert fd_write["func_index"] == 0
    assert "params" not in fd_write
    assert result["imported_func_count"] == 2


def test_wasm_client_imports_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module())
    result = WasmClient(None).imports(module)
    assert result["total"] == 5


def test_wasm_client_imports_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"PK not a module")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).imports(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_imports_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.imports")
    assert "func_index" in doc
    assert "imported_func_count" in doc
    assert "types_resolved" in doc
    assert "has_more" in doc

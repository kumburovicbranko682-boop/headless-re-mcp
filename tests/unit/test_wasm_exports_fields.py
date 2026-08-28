"""wasm.exports lists exports and resolves function-export signatures."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_exports
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


def _module(*, with_names: bool = True) -> bytes:
    # Two types: (i32,i32)->i32 and ()->()
    type0 = b"\x60" + _vec([b"\x7f", b"\x7f"]) + _vec([b"\x7f"])
    type1 = b"\x60" + _vec([]) + _vec([])
    type_sec = _section(1, _vec([type0, type1]))

    # One imported function (env.log, type 1) -> function index 0.
    func_import = _name("env") + _name("log") + b"\x00" + _uleb(1)
    import_sec = _section(2, _vec([func_import]))

    # Two defined functions -> function indices 1 (type 0) and 2 (type 1).
    func_sec = _section(3, _vec([_uleb(0), _uleb(1)]))

    # A memory so we can export it too.
    mem_sec = _section(5, _vec([b"\x00" + _uleb(1)]))

    exports = [
        _name("add") + b"\x00" + _uleb(1),  # func export -> defined function 1
        _name("reexport_log") + b"\x00" + _uleb(0),  # func export -> imported 0
        _name("memory") + b"\x02" + _uleb(0),  # memory export
    ]
    export_sec = _section(7, _vec(exports))

    module = (
        b"\x00asm\x01\x00\x00\x00"
        + type_sec
        + import_sec
        + func_sec
        + mem_sec
        + export_sec
    )
    if with_names:
        namemap = _uleb(1) + (_uleb(1) + _name("internal_add"))
        name_sub = b"\x01" + _uleb(len(namemap)) + namemap
        module += _section(0, _name("name") + name_sub)
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


def test_exports_resolve_function_signatures_and_origin() -> None:
    result = list_wasm_exports(_module())
    assert result["total"] == 3
    assert result["types_resolved"] is True
    assert result["imported_func_count"] == 1

    by_name = {row["name"]: row for row in result["exports"]}

    add = by_name["add"]
    assert add["kind"] == "func"
    assert add["index"] == 1
    assert add["origin"] == "defined"
    assert add["params"] == ["i32", "i32"]
    assert add["results"] == ["i32"]
    assert add["internal_name"] == "internal_add"

    reexport = by_name["reexport_log"]
    assert reexport["origin"] == "imported"
    assert reexport["params"] == []


def test_exports_include_non_function_kinds() -> None:
    result = list_wasm_exports(_module())
    memory = next(r for r in result["exports"] if r["name"] == "memory")
    assert memory["kind"] == "memory"
    assert "params" not in memory
    assert "origin" not in memory


def test_exports_survive_a_module_with_no_export_section() -> None:
    module = b"\x00asm\x01\x00\x00\x00"
    result = list_wasm_exports(module)
    assert result["total"] == 0
    assert result["exports"] == []


def test_exports_page_the_listing() -> None:
    result = list_wasm_exports(_module(), offset=1, limit=1)
    assert result["count"] == 1
    assert result["total"] == 3
    assert result["offset"] == 1
    assert result["has_more"] is True


def test_exports_degrade_without_a_name_section() -> None:
    result = list_wasm_exports(_module(with_names=False))
    add = next(r for r in result["exports"] if r["name"] == "add")
    assert "internal_name" not in add
    # Signature still resolves from the type section.
    assert add["params"] == ["i32", "i32"]


def test_wasm_client_exports_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module())
    result = WasmClient(None).exports(module)
    assert result["total"] == 3


def test_wasm_client_exports_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"PK not a module")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).exports(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_exports_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.exports")
    assert "origin" in doc
    assert "internal_name" in doc
    assert "imported_func_count" in doc
    assert "types_resolved" in doc
    assert "has_more" in doc

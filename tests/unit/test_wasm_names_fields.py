"""wasm.names recovers the module/function/local symbol table from a module."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_names
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


def _subsection(sub_id: int, body: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(body)) + body


def _name_map(entries: list[tuple[int, str]]) -> bytes:
    body = _uleb(len(entries))
    for index, text in entries:
        body += _uleb(index) + _name_bytes(text)
    return body


def _indirect_name_map(funcs: list[tuple[int, list[tuple[int, str]]]]) -> bytes:
    body = _uleb(len(funcs))
    for func_index, locals_list in funcs:
        body += _uleb(func_index) + _name_map(locals_list)
    return body


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _custom_section(name: str, body: bytes) -> bytes:
    return _section(0, _name_bytes(name) + body)


def _module(name_body: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + _custom_section("name", name_body)


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


def _full_name_section() -> bytes:
    module_sub = _subsection(0, _name_bytes("my_module"))
    func_sub = _subsection(1, _name_map([(0, "add"), (2, "main")]))
    local_sub = _subsection(2, _indirect_name_map([(0, [(0, "lhs"), (1, "rhs")])]))
    return module_sub + func_sub + local_sub


def test_names_decode_module_functions_and_locals() -> None:
    result = list_wasm_names(_module(_full_name_section()))
    assert result["has_name_section"] is True
    assert result["module"] == "my_module"
    assert result["functions"] == [
        {"index": 0, "name": "add"},
        {"index": 2, "name": "main"},
    ]
    assert result["function_total"] == 2
    assert result["local_function_count"] == 1
    locals_row = result["locals"][0]
    assert locals_row["function"] == 0
    assert locals_row["names"] == [
        {"index": 0, "name": "lhs"},
        {"index": 1, "name": "rhs"},
    ]
    assert locals_row["name_count"] == 2
    assert locals_row["names_truncated"] is False


def test_names_report_absent_name_section() -> None:
    result = list_wasm_names(b"\x00asm\x01\x00\x00\x00")
    assert result["has_name_section"] is False
    assert result["module"] is None
    assert result["functions"] == []
    assert result["locals"] == []


def test_names_module_may_be_absent_with_functions_present() -> None:
    body = _subsection(1, _name_map([(0, "only_fn")]))
    result = list_wasm_names(_module(body))
    assert result["has_name_section"] is True
    assert result["module"] is None
    assert result["function_total"] == 1


def test_names_page_the_function_list() -> None:
    body = _subsection(1, _name_map([(0, "a"), (1, "b"), (2, "c")]))
    result = list_wasm_names(_module(body), offset=0, limit=2)
    assert result["function_count"] == 2
    assert result["function_total"] == 3
    assert result["has_more"] is True
    assert result["offset"] == 0


def test_names_survive_a_malformed_subsection() -> None:
    # A function subsection that claims one entry then truncates the name.
    broken = _subsection(1, _uleb(1) + _uleb(0) + _uleb(20) + b"short")
    result = list_wasm_names(_module(broken))
    # has_name_section stays true; the unreadable function map yields nothing.
    assert result["has_name_section"] is True
    assert result["functions"] == []


def test_wasm_client_names_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_full_name_section()))
    result = WasmClient(None).names(module)
    assert result["module"] == "my_module"
    assert result["locals"][0]["names"][0]["name"] == "lhs"


def test_wasm_client_names_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"not a module at all")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).names(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_names_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.names")
    assert "has_name_section" in doc
    assert "locals" in doc
    assert "function_total" in doc

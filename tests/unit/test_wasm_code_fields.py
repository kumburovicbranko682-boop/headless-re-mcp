"""wasm.code lists per-function code bodies (body size + local layout)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_code
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

_I32 = 0x7F
_I64 = 0x7E


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


def _code_entry(local_groups: list[tuple[int, int]], instrs: bytes = b"\x0b") -> bytes:
    body = _uleb(len(local_groups))
    for count, valtype in local_groups:
        body += _uleb(count) + bytes([valtype])
    body += instrs
    return _uleb(len(body)) + body


def _code_section(entries: list[bytes]) -> bytes:
    return _section(10, _uleb(len(entries)) + b"".join(entries))


def _import_func(module: str, name: str, type_index: int) -> bytes:
    # import entry: module, name, kind=0 (func), type index.
    return _name_bytes(module) + _name_bytes(name) + b"\x00" + _uleb(type_index)


def _import_section(entries: list[bytes]) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _name_section(func_names: dict[int, str]) -> bytes:
    body = _uleb(len(func_names))
    for index, text in func_names.items():
        body += _uleb(index) + _name_bytes(text)
    subsection = bytes([1]) + _uleb(len(body)) + body
    payload = _name_bytes("name") + subsection
    return _section(0, payload)


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


def test_code_reports_body_size_and_locals() -> None:
    module = _module(
        _code_section(
            [
                _code_entry([]),  # no locals: body is 0x00 0x0b
                _code_entry([(2, _I32), (1, _I64)]),
            ]
        )
    )
    result = list_wasm_code(module)
    assert result["total"] == 2
    assert result["imported_count"] == 0
    assert result["resolved"] is True

    first = result["functions"][0]
    assert first["index"] == 0
    assert first["body_size"] == 2
    assert first["local_count"] == 0
    assert first["local_groups"] == []

    second = result["functions"][1]
    assert second["index"] == 1
    assert second["local_count"] == 3
    assert second["local_groups"] == [
        {"count": 2, "type": "i32"},
        {"count": 1, "type": "i64"},
    ]


def test_code_indices_start_after_imported_functions() -> None:
    module = _module(
        _import_section([_import_func("env", "log", 0), _import_func("env", "now", 0)]),
        _code_section([_code_entry([])]),
    )
    result = list_wasm_code(module)
    assert result["imported_count"] == 2
    assert result["total"] == 1
    # The single defined body is function index 2 (after the two imports).
    assert result["functions"][0]["index"] == 2


def test_code_attaches_debug_name_from_name_section() -> None:
    module = _module(
        _code_section([_code_entry([])]),
        _name_section({0: "main"}),
    )
    result = list_wasm_code(module)
    assert result["functions"][0]["name"] == "main"


def test_code_on_a_module_without_a_code_section() -> None:
    result = list_wasm_code(_module())
    assert result["total"] == 0
    assert result["functions"] == []
    assert result["resolved"] is True


def test_code_pages_the_listing() -> None:
    module = _module(_code_section([_code_entry([]), _code_entry([]), _code_entry([])]))
    result = list_wasm_code(module, offset=0, limit=2)
    assert result["count"] == 2
    assert result["total"] == 3
    assert result["has_more"] is True


def test_code_degrades_on_a_truncated_code_section() -> None:
    # Claims one body of size 8 but the payload ends immediately.
    module = _module(_section(10, _uleb(1) + _uleb(8)))
    result = list_wasm_code(module)
    assert result["resolved"] is False
    assert result["functions"] == []


def test_wasm_client_code_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_code_section([_code_entry([(4, _I32)])])))
    result = WasmClient(None).code(module)
    assert result["functions"][0]["local_count"] == 4


def test_wasm_client_code_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"not wasm")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).code(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_code_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.code")
    assert "body_size" in doc
    assert "local_groups" in doc
    assert "imported_count" in doc

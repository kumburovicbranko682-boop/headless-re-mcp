"""wasm.callgraph builds the module's static call graph from the code section."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_callgraph
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


def _code_entry(instrs: bytes) -> bytes:
    body = _uleb(0) + instrs  # no locals
    return _uleb(len(body)) + body


def _code_section(entries: list[bytes]) -> bytes:
    return _section(10, _uleb(len(entries)) + b"".join(entries))


def _import_func(module: str, name: str, type_index: int) -> bytes:
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


def _call(index: int) -> bytes:
    return bytes([0x10]) + _uleb(index)


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


def test_callgraph_collects_direct_call_edges() -> None:
    # One import (index 0), two defined functions (indices 1 and 2).
    # func 1 calls func 2 and the import; func 2 calls nothing.
    body1 = _call(2) + _call(0) + bytes([0x0B])
    body2 = bytes([0x0B])
    module = _module(
        _import_section([_import_func("env", "host", 0)]),
        _code_section([_code_entry(body1), _code_entry(body2)]),
    )
    result = list_wasm_callgraph(module)
    assert result["imported_count"] == 1
    assert result["total"] == 2
    assert result["resolved"] is True

    f1 = result["functions"][0]
    assert f1["index"] == 1
    assert f1["call_count"] == 2
    targets = {c["index"]: c for c in f1["calls"]}
    assert targets[2]["imported"] is False
    assert targets[0]["imported"] is True
    assert targets[0]["name"] == "env.host"

    f2 = result["functions"][1]
    assert f2["index"] == 2
    assert f2["calls"] == []
    assert f2["call_count"] == 0
    assert result["edge_count"] == 2


def test_callgraph_dedupes_repeated_calls_and_counts_indirect() -> None:
    # func 1 calls func 1 twice (dedup to 1) and has one call_indirect.
    # call_indirect encoding: 0x11 typeidx tableidx.
    body = _call(1) + _call(1) + bytes([0x11]) + _uleb(0) + _uleb(0) + bytes([0x0B])
    module = _module(_code_section([_code_entry(body)]))
    result = list_wasm_callgraph(module)
    f0 = result["functions"][0]
    assert f0["index"] == 0
    assert f0["call_count"] == 1
    assert f0["indirect_call_count"] == 1
    assert f0["complete"] is True


def test_callgraph_uses_the_debug_names() -> None:
    body = _call(1) + bytes([0x0B])
    module = _module(
        _code_section([_code_entry(body), _code_entry(bytes([0x0B]))]),
        _name_section({0: "main", 1: "helper"}),
    )
    result = list_wasm_callgraph(module)
    f0 = result["functions"][0]
    assert f0["name"] == "main"
    assert f0["calls"][0]["name"] == "helper"


def test_callgraph_marks_incomplete_body_on_simd() -> None:
    # call 0, then a SIMD prefix that stops the decode before the trailing call.
    body = _call(0) + bytes([0xFD, 0x00]) + _call(0) + bytes([0x0B])
    module = _module(_code_section([_code_entry(body)]))
    result = list_wasm_callgraph(module)
    f0 = result["functions"][0]
    assert f0["complete"] is False
    # The one call decoded before the SIMD op is still recorded.
    assert f0["call_count"] == 1


def test_callgraph_pages_functions() -> None:
    entries = [_code_entry(bytes([0x0B])) for _ in range(5)]
    module = _module(_code_section(entries))
    result = list_wasm_callgraph(module, offset=0, limit=2)
    assert result["count"] == 2
    assert result["total"] == 5
    assert result["has_more"] is True


def test_callgraph_no_code_section() -> None:
    module = _module(_import_section([_import_func("env", "host", 0)]))
    result = list_wasm_callgraph(module)
    assert result["total"] == 0
    assert result["functions"] == []
    assert result["imported_count"] == 1


def test_callgraph_through_the_client(tmp_path: Path) -> None:
    body = _call(0) + bytes([0x0B])
    module = _module(_code_section([_code_entry(body)]))
    wasm = tmp_path / "m.wasm"
    wasm.write_bytes(module)
    result = WasmClient().callgraph(wasm)
    assert result["total"] == 1
    assert result["functions"][0]["call_count"] == 1


def test_wasm_callgraph_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.callgraph")
    assert "call_count" in doc
    assert "indirect_call_count" in doc
    assert "imported" in doc
    assert "edge_count" in doc

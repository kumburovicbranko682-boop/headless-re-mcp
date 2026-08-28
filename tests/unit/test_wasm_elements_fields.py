"""wasm.elements decodes element segments (the indirect-call dispatch table)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_elements
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


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _i32_const(value: int) -> bytes:
    # i32.const <sleb> end -- small non-negative values encode as one byte.
    return b"\x41" + _uleb(value) + b"\x0b"


def _module_active_funcidx() -> bytes:
    # flag 0: active, table 0, offset expr, vec funcidx.
    seg = b"\x00" + _i32_const(1) + _vec([_uleb(7), _uleb(3), _uleb(9)])
    return b"\x00asm\x01\x00\x00\x00" + _section(9, _vec([seg]))


def _module_expr_form() -> bytes:
    # flag 5: passive, reftype funcref, vec of element expressions.
    # Two exprs: ref.func 4 ; ref.null func.
    ref_func = b"\xd2" + _uleb(4) + b"\x0b"
    ref_null = b"\xd0\x70\x0b"
    seg = b"\x05\x70" + _vec([ref_func, ref_null])
    return b"\x00asm\x01\x00\x00\x00" + _section(9, _vec([seg]))


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


def test_elements_decode_active_funcidx_segment() -> None:
    result = list_wasm_elements(_module_active_funcidx())
    assert result["total"] == 1
    seg = result["elements"][0]
    assert seg["mode"] == "active"
    assert seg["table_index"] == 0
    assert seg["element_type"] == "funcref"
    assert seg["offset"] == {"op": "i32.const", "value": 1}
    assert seg["func_indices"] == [7, 3, 9]
    assert seg["count"] == 3
    assert seg["entries_truncated"] is False


def test_elements_decode_expression_form_with_ref_null() -> None:
    result = list_wasm_elements(_module_expr_form())
    seg = result["elements"][0]
    assert seg["mode"] == "passive"
    assert seg["table_index"] is None
    assert seg["offset"] is None
    assert seg["element_type"] == "funcref"
    # ref.func 4 resolves to index 4; ref.null becomes a null slot.
    assert seg["func_indices"] == [4, None]


def test_elements_survive_a_module_with_no_element_section() -> None:
    result = list_wasm_elements(b"\x00asm\x01\x00\x00\x00")
    assert result["total"] == 0
    assert result["elements"] == []


def test_elements_page_the_listing() -> None:
    # Two active segments back to back.
    seg = b"\x00" + _i32_const(0) + _vec([_uleb(1)])
    module = b"\x00asm\x01\x00\x00\x00" + _section(9, _vec([seg, seg]))
    result = list_wasm_elements(module, offset=0, limit=1)
    assert result["count"] == 1
    assert result["total"] == 2
    assert result["offset"] == 0
    assert result["has_more"] is True


def test_elements_degrade_on_a_malformed_section() -> None:
    # Declares one segment then truncates mid-record -> empty listing, no raise.
    module = b"\x00asm\x01\x00\x00\x00" + _section(9, b"\x01\x00\x41")
    result = list_wasm_elements(module)
    assert result["total"] == 0
    assert result["elements"] == []


def test_wasm_client_elements_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module_active_funcidx())
    result = WasmClient(None).elements(module)
    assert result["elements"][0]["func_indices"] == [7, 3, 9]


def test_wasm_client_elements_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"PK not a module")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).elements(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_elements_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.elements")
    assert "func_indices" in doc
    assert "call_indirect" in doc
    assert "table_index" in doc
    assert "has_more" in doc

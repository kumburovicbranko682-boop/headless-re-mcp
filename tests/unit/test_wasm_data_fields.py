"""wasm.data lays out the data section with memory offsets and previews."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_data
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
    return b"\x41" + _uleb(value) + b"\x0b"


def _active_segment(offset: int, blob: bytes) -> bytes:
    # flag 0: active, memory 0, offset expr, then a byte vector.
    return b"\x00" + _i32_const(offset) + _uleb(len(blob)) + blob


def _passive_segment(blob: bytes) -> bytes:
    # flag 1: passive, byte vector only.
    return b"\x01" + _uleb(len(blob)) + blob


def _module(segments: list[bytes]) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + _section(11, _vec(segments))


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


def test_data_decodes_active_segment_offset_and_preview() -> None:
    module = _module([_active_segment(1024, b"/api/login\x00\x01")])
    result = list_wasm_data(module)
    assert result["total"] == 1
    seg = result["segments"][0]
    assert seg["mode"] == "active"
    assert seg["memory_index"] == 0
    assert seg["offset"] == {"op": "i32.const", "value": 1024}
    assert seg["size"] == 12
    assert seg["hex"].startswith(b"/api/login".hex())
    # Non-printable bytes render as '.' in the text preview.
    assert seg["text"] == "/api/login.."
    assert seg["preview_truncated"] is False


def test_data_reports_passive_segment_without_offset() -> None:
    module = _module([_passive_segment(b"payload")])
    result = list_wasm_data(module)
    seg = result["segments"][0]
    assert seg["mode"] == "passive"
    assert seg["memory_index"] is None
    assert seg["offset"] is None
    assert seg["size"] == 7


def test_data_truncates_a_large_blob_preview() -> None:
    big = b"A" * 200
    module = _module([_active_segment(0, big)])
    result = list_wasm_data(module)
    seg = result["segments"][0]
    assert seg["size"] == 200
    assert len(bytes.fromhex(seg["hex"])) == 64
    assert seg["preview_truncated"] is True


def test_data_survives_a_module_with_no_data_section() -> None:
    result = list_wasm_data(b"\x00asm\x01\x00\x00\x00")
    assert result["total"] == 0
    assert result["segments"] == []


def test_data_pages_the_listing() -> None:
    module = _module([_active_segment(0, b"a"), _active_segment(8, b"b")])
    result = list_wasm_data(module, offset=0, limit=1)
    assert result["count"] == 1
    assert result["total"] == 2
    assert result["has_more"] is True


def test_data_degrades_on_a_malformed_section() -> None:
    # Declares one segment then truncates the offset expression -> empty, no raise.
    module = b"\x00asm\x01\x00\x00\x00" + _section(11, b"\x01\x00\x41")
    result = list_wasm_data(module)
    assert result["total"] == 0
    assert result["segments"] == []


def test_wasm_client_data_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module([_active_segment(16, b"hi")]))
    result = WasmClient(None).data(module)
    assert result["segments"][0]["offset"]["value"] == 16


def test_wasm_client_data_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"PK not a module")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).data(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_data_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.data")
    assert "memory_index" in doc
    assert "preview_truncated" in doc
    assert "has_more" in doc

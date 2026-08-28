"""wasm.globals lists the global section with type, mutability, and init."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_globals
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


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40))
        if not done:
            byte |= 0x80
        out.append(byte)
        if done:
            return bytes(out)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _global(valtype: int, mutable: int, init: bytes) -> bytes:
    return bytes([valtype, mutable]) + init


def _module(*, with_import: bool = False, bad: bool = False) -> bytes:
    module = b"\x00asm\x01\x00\x00\x00"
    if with_import:
        # An imported global (env.__stack_pointer, mutable i32) precedes the
        # defined ones in the global index space.
        imp = _name("env") + _name("__stack_pointer") + b"\x03" + b"\x7f\x01"
        module += _section(2, _vec([imp]))
    if bad:
        # A global section whose init opcode (0x00 unreachable) is not a const
        # expression -> unresolved.
        module += _section(6, _uleb(1) + b"\x7f\x00\x00")
        return module
    g_i32 = _global(0x7F, 0x00, b"\x41" + _sleb(42) + b"\x0b")  # const i32 = 42
    g_i32_mut = _global(0x7F, 0x01, b"\x41" + _sleb(-7) + b"\x0b")  # mutable i32 = -7
    g_f64 = _global(0x7C, 0x00, b"\x44" + b"\x00" * 8 + b"\x0b")  # const f64
    g_getter = _global(0x7F, 0x00, b"\x23" + _uleb(0) + b"\x0b")  # global.get 0
    module += _section(6, _vec([g_i32, g_i32_mut, g_f64, g_getter]))
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


def test_globals_decode_type_mutability_and_init() -> None:
    result = list_wasm_globals(_module())
    assert result["total"] == 4
    assert result["resolved"] is True
    assert result["imported_count"] == 0

    rows = result["globals"]
    assert rows[0]["value_type"] == "i32"
    assert rows[0]["mutable"] is False
    assert rows[0]["init"] == {"op": "i32.const", "value": 42}
    assert rows[0]["index"] == 0

    assert rows[1]["mutable"] is True
    assert rows[1]["init"] == {"op": "i32.const", "value": -7}

    assert rows[2]["value_type"] == "f64"
    assert rows[2]["init"] == {"op": "f64.const"}

    assert rows[3]["init"] == {"op": "global.get", "index": 0}


def test_globals_offset_index_by_imported_globals() -> None:
    result = list_wasm_globals(_module(with_import=True))
    assert result["imported_count"] == 1
    # The first defined global sits at index 1 (imported global took index 0).
    assert result["globals"][0]["index"] == 1


def test_globals_degrade_on_a_bad_section() -> None:
    result = list_wasm_globals(_module(bad=True))
    assert result["resolved"] is False
    assert result["globals"] == []


def test_globals_report_a_module_with_no_global_section() -> None:
    result = list_wasm_globals(b"\x00asm\x01\x00\x00\x00")
    assert result["total"] == 0
    assert result["resolved"] is True


def test_globals_page_the_listing() -> None:
    result = list_wasm_globals(_module(), offset=2, limit=1)
    assert result["count"] == 1
    assert result["total"] == 4
    assert result["offset"] == 2
    assert result["has_more"] is True
    assert result["globals"][0]["value_type"] == "f64"


def test_wasm_client_globals_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module())
    result = WasmClient(None).globals(module)
    assert result["total"] == 4


def test_wasm_client_globals_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"not wasm at all")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).globals(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_globals_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.globals")
    assert "value_type" in doc
    assert "mutable" in doc
    assert "init" in doc
    assert "imported_count" in doc
    assert "has_more" in doc

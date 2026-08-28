"""wasm.globals decodes the global section: type, mutability, and init value.

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing) and assert the value-type and mutability decode, the
numeric/global.get initializers, the imported-global index offset, the 4096-item
cut, and that hostile input is refused rather than crashed.
"""

from __future__ import annotations

import ast
import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, list_wasm_globals_bytes
from headless_re_mcp.backends.jsre.wasm_summary import _MAX_ITEMS
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


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, content: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(content)) + content


def _module(*sections: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


# One global: valtype byte + mutability byte + init const-expr (ending 0x0B).
def _global_i32(value: int, *, mutable: bool) -> bytes:
    return bytes([0x7F, 0x01 if mutable else 0x00]) + b"\x41" + _sleb(value) + b"\x0b"


def _global_f64(value: float, *, mutable: bool) -> bytes:
    return (
        bytes([0x7C, 0x01 if mutable else 0x00])
        + b"\x44"
        + struct.pack("<d", value)
        + b"\x0b"
    )


def _global_getref(valtype: int, global_index: int) -> bytes:
    return bytes([valtype, 0x00]) + b"\x23" + _uleb(global_index) + b"\x0b"


def _global_import(module: str, field: str, valtype: int, mutable: int) -> bytes:
    return _name(module) + _name(field) + b"\x03" + bytes([valtype, mutable])


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


def test_wasm_globals_decodes_types_mutability_and_inits() -> None:
    """A mutable i32 stack pointer, an immutable f64 const, and a global.get seed
    must each decode their value type, mutability and initializer."""
    global_sec = _section(
        6,
        _vec(
            [
                _global_i32(1048576, mutable=True),  # shadow stack pointer
                _global_f64(3.5, mutable=False),
                _global_getref(0x7F, 0),  # i32 seeded from imported global 0
            ]
        ),
    )
    result = list_wasm_globals_bytes(_module(global_sec))
    assert result["count"] == result["total"] == 3
    assert result["imported_count"] == 0
    assert result["scan_capped"] is False

    sp = result["globals"][0]
    assert sp["index"] == 0
    assert sp["valtype"] == "i32"
    assert sp["mutable"] is True
    assert sp["init"] == "i32.const 1048576"
    assert sp["init_value"] == 1048576

    konst = result["globals"][1]
    assert konst["valtype"] == "f64"
    assert konst["mutable"] is False
    assert konst["init"] == "f64.const 3.5"
    assert konst["init_value"] == 3.5

    seeded = result["globals"][2]
    assert seeded["init"] == "global.get 0"
    assert seeded["init_global"] == 0
    assert "init_value" not in seeded


def test_wasm_globals_offsets_index_past_imported_globals() -> None:
    """An imported global occupies index 0, so the defined global is index 1."""
    import_sec = _section(2, _vec([_global_import("env", "g", 0x7F, 0x01)]))
    global_sec = _section(6, _vec([_global_i32(7, mutable=False)]))
    result = list_wasm_globals_bytes(_module(import_sec, global_sec))
    assert result["imported_count"] == 1
    assert result["count"] == result["total"] == 1
    only = result["globals"][0]
    assert only["index"] == 1  # after the one imported global
    assert only["init_value"] == 7


def test_wasm_globals_reports_a_module_with_no_globals() -> None:
    # A module with only a (bodiless) type section has no global section.
    result = list_wasm_globals_bytes(_module(_section(1, _vec([]))))
    assert result["globals"] == []
    assert result["count"] == result["total"] == 0
    assert result["imported_count"] == 0
    assert result["scan_capped"] is False


def test_wasm_globals_caps_a_huge_global_section() -> None:
    global_sec = _section(6, _vec([_global_i32(0, mutable=False)] * (_MAX_ITEMS + 5)))
    result = list_wasm_globals_bytes(_module(global_sec))
    assert result["count"] == _MAX_ITEMS
    assert result["total"] == _MAX_ITEMS + 5
    assert result["scan_capped"] is True


def test_wasm_globals_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as caught:
        list_wasm_globals_bytes(b"MZ\x90\x00 not wasm")
    assert caught.value.code == "invalid_params"


def test_wasm_globals_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.globals")
    assert doc, "wasm.globals is missing its docstring"
    assert "valtype" in doc
    assert "mutable" in doc
    assert "init" in doc
    assert "imported_count" in doc
    assert "pure Python" in doc

"""wasm.strings extracts data-segment strings in-process (no wabt)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, WasmClient
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
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _active_data(offset: int, payload: bytes) -> bytes:
    # flags 0: active, memidx 0, i32.const offset, end, then vec(byte).
    seg = _uleb(0) + b"\x41" + _sleb(offset) + b"\x0b" + _uleb(len(payload)) + payload
    return _section(11, _uleb(1) + seg)


def _module(*sections: bytes) -> bytes:
    return b"\x00asm" + b"\x01\x00\x00\x00" + b"".join(sections)


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


def test_wasm_strings_reads_data_segment_with_memory_offsets(tmp_path: Path) -> None:
    payload = b"\x00\x01hello world\x00https://evil.example/api\x00ab"
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_active_data(1024, payload)))
    data = WasmClient().strings(module)
    assert data["items"] == [
        {"string": "hello world", "offset": 1024 + payload.index(b"hello")},
        {"string": "https://evil.example/api", "offset": 1024 + payload.index(b"https")},
    ]
    assert data["count"] == 2
    assert data["min_length"] == 4
    assert "truncated" not in data


def test_wasm_strings_min_length_filters(tmp_path: Path) -> None:
    payload = b"abc\x00abcd\x00abcde"
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_active_data(0, payload)))
    # Default min 4 drops "abc"; min 3 keeps it.
    default = WasmClient().strings(module)
    assert [item["string"] for item in default["items"]] == ["abcd", "abcde"]
    loose = WasmClient().strings(module, min_length=3)
    assert [item["string"] for item in loose["items"]] == ["abc", "abcd", "abcde"]
    assert loose["min_length"] == 3


def test_wasm_strings_passive_segment_has_no_offset(tmp_path: Path) -> None:
    # flags 1: passive segment -- no memory offset to report.
    payload = b"passivestring"
    seg = _uleb(1) + _uleb(len(payload)) + payload
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_section(11, _uleb(1) + seg)))
    data = WasmClient().strings(module)
    assert data["items"] == [{"string": "passivestring"}]


def test_wasm_strings_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_active_data(0, b"needsnowabt")))
    client = WasmClient()
    client._wasm2wat = None  # type: ignore[assignment]
    client._objdump = None  # type: ignore[assignment]
    assert client.strings(module)["count"] == 1


def test_wasm_strings_rejects_non_wasm(tmp_path: Path) -> None:
    junk = tmp_path / "not.wasm"
    junk.write_bytes(b"MZ\x00\x00not a module")
    with pytest.raises(JsReError) as excinfo:
        WasmClient().strings(junk)
    assert excinfo.value.code == "invalid_params"


def test_wasm_strings_flags_a_truncated_data_section(tmp_path: Path) -> None:
    # A data section that claims one segment but whose declared segment size
    # overruns the section body: parse stops and truncated is set.
    broken_body = _uleb(1) + _uleb(0) + b"\x41" + _sleb(0) + b"\x0b" + _uleb(9999) + b"\x01"
    module = tmp_path / "m.wasm"
    module.write_bytes(_module(_section(11, broken_body)))
    data = WasmClient().strings(module)
    assert data["truncated"] is True
    assert data["items"] == []


def test_wasm_strings_docstring_names_offset_and_no_wabt() -> None:
    doc = _tool_docstring("wasm.strings")
    assert "offset" in doc
    assert "items" in doc
    assert "wabt" in doc

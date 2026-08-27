"""wasm.sections lays out a module's section table (id, name, size, offset).

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing) and assert the id/name/size/offset shape, the custom
section name/payload, an unknown id, the 4096 cap, and that hostile input is
refused rather than crashed on.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, extract_wasm_sections_bytes
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


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, content: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(content)) + content


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


def test_wasm_sections_lays_out_the_table() -> None:
    """Each section must come back with id, name, byte size and file offset.

    The offsets are computed by hand from the framing (magic is 8 bytes, then
    each section is id + uleb(len) + body), so this pins that offset is the body
    start in the file -- the value a caller seeks to when carving.
    """
    module = _module(
        _section(1, b"\x00"),  # type section, 1-byte body
        _section(11, b"\xaa\xbb"),  # data section, 2-byte body
        _section(0, _name("name") + b"\x01\x02\x03"),  # custom "name", 3-byte payload
    )
    result = extract_wasm_sections_bytes(module)
    assert result["version"] == 1
    assert result["count"] == 3
    assert result["total"] == 3
    assert result["sections"][0] == {"id": 1, "name": "type", "size": 1, "offset": 10}
    assert result["sections"][1] == {"id": 11, "name": "data", "size": 2, "offset": 13}
    custom = result["sections"][2]
    assert custom["id"] == 0
    assert custom["name"] == "custom"
    assert custom["size"] == 8
    assert custom["offset"] == 17
    assert custom["custom_name"] == "name"
    assert custom["payload_size"] == 3
    assert "sections_truncated" not in result


def test_wasm_sections_reports_a_custom_payload_size() -> None:
    """A custom section's payload_size must exclude its name bytes."""
    payload = b"\x00" * 40
    module = _module(_section(0, _name("producers") + payload))
    section = extract_wasm_sections_bytes(module)["sections"][0]
    assert section["custom_name"] == "producers"
    # name is uleb(9)+9 bytes = 10 bytes; payload is the rest.
    assert section["payload_size"] == len(payload)
    assert section["size"] == 10 + len(payload)


def test_wasm_sections_names_an_unknown_section_id() -> None:
    """A section id outside the known set is reported, not rejected."""
    module = _module(_section(99, b"\x00\x00"))
    section = extract_wasm_sections_bytes(module)["sections"][0]
    assert section["id"] == 99
    assert section["name"] == "section 99"
    assert "custom_name" not in section


def test_wasm_sections_caps_a_flood_of_sections() -> None:
    """More sections than the cap must clip the list and flag the cut."""
    sections = [_section(0, _name(f"c{index}")) for index in range(_MAX_ITEMS + 5)]
    module = _module(*sections)
    result = extract_wasm_sections_bytes(module)
    assert result["count"] == _MAX_ITEMS
    assert result["total"] == _MAX_ITEMS + 5
    assert result["sections_truncated"] is True
    assert result["sections_total"] == _MAX_ITEMS + 5
    assert result["sections_limit"] == _MAX_ITEMS


def test_wasm_sections_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as excinfo:
        extract_wasm_sections_bytes(b"not a wasm module at all")
    assert excinfo.value.code == "invalid_params"


def test_wasm_sections_rejects_a_lying_section_length() -> None:
    """A section length past the end of the module must raise, not read over."""
    # id=1, declared length 200, but only 1 body byte present.
    module = _module(bytes([1]) + _uleb(200) + b"\x00")
    with pytest.raises(JsReError) as excinfo:
        extract_wasm_sections_bytes(module)
    assert excinfo.value.code == "invalid_params"


def test_wasm_sections_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.sections")
    assert doc, "wasm.sections is missing its docstring"
    assert "offset" in doc
    assert "custom_name" in doc
    assert "payload_size" in doc
    assert "sections_truncated" in doc

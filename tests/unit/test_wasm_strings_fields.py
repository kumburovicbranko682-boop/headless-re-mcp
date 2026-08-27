"""wasm.strings pulls printable strings from a module's data segments.

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing + a data section with active segments) and assert the
string/segment/addr shape, the min_length floor, the contains filter, the 4096
cap, and that hostile input is refused rather than crashed on.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, extract_wasm_strings_bytes
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
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _section(section_id: int, content: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(content)) + content


def _active_segment(base: int, payload: bytes) -> bytes:
    """A flags=0 data segment: i32.const base ; end ; vec(byte) payload."""
    offset_expr = b"\x41" + _sleb(base) + b"\x0b"
    return _uleb(0) + offset_expr + _uleb(len(payload)) + payload


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


def test_wasm_strings_extracts_data_segment_strings() -> None:
    """A data segment's printable runs must come back with segment and addr.

    Bury two strings around non-printable padding at a known linear-memory base;
    assert both are recovered, the short/binary noise between them is dropped,
    and each string's addr is base + its position in the segment -- the address
    an analyst pivots on.
    """
    base = 1024
    url = b"https://evil.example/c2"
    key = b"API_KEY=SECRET123"
    payload = url + b"\x00" + b"\x01\x02\x03" + key + b"\x00" + b"ab"
    module = _module(_section(11, _vec([_active_segment(base, payload)])))

    result = extract_wasm_strings_bytes(module)
    found = {item["string"]: item for item in result["strings"]}
    assert url.decode() in found
    assert key.decode() in found
    # The 2-byte "ab" tail is below the default 4-char floor and must be dropped.
    assert "ab" not in found
    assert result["data_segments"] == 1
    assert found[url.decode()]["segment"] == 0
    assert found[url.decode()]["addr"] == base
    assert found[key.decode()]["addr"] == base + payload.index(key)
    # A clean scan carries no filter/cut flags.
    assert result["scan_capped"] is False
    assert "filtered" not in result


def test_wasm_strings_min_length_raises_the_floor() -> None:
    payload = b"hi\x00" + b"hello\x00" + b"xyz\x00"
    module = _module(_section(11, _vec([_active_segment(0, payload)])))
    default = {item["string"] for item in extract_wasm_strings_bytes(module)["strings"]}
    assert default == {"hello"}  # "hi"/"xyz" are under 4
    lowered = {
        item["string"]
        for item in extract_wasm_strings_bytes(module, min_length=2)["strings"]
    }
    assert lowered == {"hi", "hello", "xyz"}


def test_wasm_strings_contains_filters_to_matches() -> None:
    payload = (
        b"https://api.example.com/v1\x00"
        b"https://cdn.other.net/x\x00"
        b"AES/CBC/PKCS5Padding\x00"
    )
    module = _module(_section(11, _vec([_active_segment(0, payload)])))
    hits = extract_wasm_strings_bytes(module, contains="EXAMPLE.com")
    assert [item["string"] for item in hits["strings"]] == ["https://api.example.com/v1"]
    assert hits["filtered"] is True
    assert hits["query"] == "EXAMPLE.com"
    assert hits["total"] == 1
    # An unfiltered call names no filter, so a plain listing is not read as one.
    plain = extract_wasm_strings_bytes(module)
    assert "filtered" not in plain
    assert "query" not in plain


def test_wasm_strings_reports_a_module_with_no_data_section() -> None:
    module = _module(_section(1, _vec([b"\x60\x00\x00"])))  # a type section only
    result = extract_wasm_strings_bytes(module)
    assert result["strings"] == []
    assert result["count"] == 0
    assert result["total"] == 0
    assert result["data_segments"] == 0


def test_wasm_strings_caps_a_flood_of_strings() -> None:
    # Each "WXYZ\x00" is one printable run; more than the cap of them proves the
    # list is trimmed while total counts them all.
    count = _MAX_ITEMS + 25
    payload = b"".join(b"WXYZ\x00" for _ in range(count))
    module = _module(_section(11, _vec([_active_segment(0, payload)])))
    result = extract_wasm_strings_bytes(module)
    assert result["count"] == _MAX_ITEMS
    assert result["total"] == count
    assert result["scan_capped"] is True


def test_wasm_strings_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as caught:
        extract_wasm_strings_bytes(b"MZ\x90\x00 this is a PE, not wasm")
    assert caught.value.code == "invalid_params"


def test_wasm_strings_rejects_a_truncated_data_section() -> None:
    # A data section claiming 40 bytes but the module ends immediately: reading
    # the segment must fail cleanly, not crash.
    truncated = _module(bytes([11]) + _uleb(40) + b"\x01\x00\x41\x00\x0b\x10")
    with pytest.raises(JsReError) as caught:
        extract_wasm_strings_bytes(truncated)
    assert caught.value.code == "invalid_params"


def test_wasm_strings_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.strings")
    assert doc, "wasm.strings is missing its docstring"
    assert "data segment" in doc
    assert "segment" in doc
    assert "addr" in doc
    assert "min_length" in doc
    assert "contains" in doc
    assert "scan_capped" in doc
    assert "pure Python" in doc

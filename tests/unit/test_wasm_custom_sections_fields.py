"""wasm.custom_sections indexes custom sections in pure Python (no wabt).

Modules are hand-built byte for byte: a magic, a version, then custom sections
(section id 0) whose payload opens with a length-prefixed name. The tool lists
them and decodes the analysis-relevant ones -- DWARF (.debug_*), a
sourceMappingURL, target_features -- so nothing here needs wabt installed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import (
    JsReError,
    WasmClient,
    _parse_wasm_custom_sections,
)
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


def _wasm_name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _custom(name: str, content: bytes = b"") -> bytes:
    body = _wasm_name(name) + content
    return bytes([0x00]) + _uleb(len(body)) + body


_HEADER = b"\x00asm\x01\x00\x00\x00"


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


def test_lists_custom_sections_with_sizes(tmp_path: Path) -> None:
    """Every custom section shows up with its name, size and file offset."""
    blob = tmp_path / "m.wasm"
    blob.write_bytes(_HEADER + _custom("producers", b"\x00") + _custom("name", b"\x00"))
    result = WasmClient(None).custom_sections(blob)
    names = [item["name"] for item in result["items"]]
    assert names == ["producers", "name"]
    assert result["count"] == 2
    assert result["items_total"] == 2
    assert result["has_producers_section"] is True
    assert result["has_name_section"] is True
    assert result["truncated"] is False
    first = result["items"][0]
    assert first["size"] > 0 and first["offset"] >= _HEADER.__len__()
    assert first["content_size"] == first["size"] - len(_wasm_name("producers"))


def test_detects_dwarf_debug_sections(tmp_path: Path) -> None:
    """.debug_* custom sections set has_dwarf and are listed by name."""
    blob = tmp_path / "m.wasm"
    blob.write_bytes(
        _HEADER
        + _custom(".debug_info", b"\x01\x02")
        + _custom(".debug_line", b"\x03")
        + _custom("name", b"\x00")
    )
    result = WasmClient(None).custom_sections(blob)
    assert result["has_dwarf"] is True
    assert set(result["debug_sections"]) == {".debug_info", ".debug_line"}


def test_decodes_source_map_url(tmp_path: Path) -> None:
    """A sourceMappingURL section's URL is decoded to source_map_url."""
    blob = tmp_path / "m.wasm"
    url = "https://example.com/app.wasm.map"
    blob.write_bytes(_HEADER + _custom("sourceMappingURL", _wasm_name(url)))
    result = WasmClient(None).custom_sections(blob)
    assert result["source_map_url"] == url


def test_decodes_target_features(tmp_path: Path) -> None:
    """target_features decodes to (feature, flag) pairs with the +/-/= prefix."""
    blob = tmp_path / "m.wasm"
    # count=2; '+' simd128, '-' atomics
    content = _uleb(2) + b"\x2b" + _wasm_name("simd128") + b"\x2d" + _wasm_name("atomics")
    blob.write_bytes(_HEADER + _custom("target_features", content))
    result = WasmClient(None).custom_sections(blob)
    assert result["target_features"] == [
        {"feature": "simd128", "flag": "+"},
        {"feature": "atomics", "flag": "-"},
    ]


def test_no_custom_sections_is_clean(tmp_path: Path) -> None:
    """A module with only standard sections reports an empty, honest result."""
    blob = tmp_path / "m.wasm"
    # A type section (id 1) with an empty body -- not a custom section.
    type_section = bytes([0x01]) + _uleb(1) + b"\x00"
    blob.write_bytes(_HEADER + type_section)
    result = WasmClient(None).custom_sections(blob)
    assert result["items"] == []
    assert result["count"] == 0
    assert result["has_dwarf"] is False
    assert "source_map_url" not in result
    assert result["truncated"] is False


def test_needs_no_wabt(tmp_path: Path) -> None:
    """custom_sections reads bytes directly; wabt being absent is irrelevant."""
    client = WasmClient(None)
    client._wasm2wat = None
    client._objdump = None
    blob = tmp_path / "m.wasm"
    blob.write_bytes(_HEADER + _custom("name", b"\x00"))
    assert client.custom_sections(blob)["has_name_section"] is True


def test_rejects_non_wasm_input(tmp_path: Path) -> None:
    """A file without the \\0asm magic is invalid_params."""
    blob = tmp_path / "not.wasm"
    blob.write_bytes(b"MZ\x90\x00 not wasm")
    with pytest.raises(JsReError) as excinfo:
        WasmClient(None).custom_sections(blob)
    assert excinfo.value.code == "invalid_params"


def test_truncated_section_flagged() -> None:
    """A section whose declared size overruns the module sets truncated."""
    blob = _HEADER + bytes([0x00]) + _uleb(200) + _wasm_name("name")
    result = _parse_wasm_custom_sections(blob, limit=4096)
    assert result["truncated"] is True


def test_tool_docstring_names_the_fields() -> None:
    doc = _tool_docstring("wasm.custom_sections")
    for field in ("items", "has_dwarf", "source_map_url", "target_features"):
        assert field in doc
    assert "no wabt" in doc

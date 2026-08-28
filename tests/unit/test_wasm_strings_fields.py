"""wasm.strings extracts printable strings from a module's data (rodata) section.

wasm.summary gives structure and wasm.names gives symbols; wasm.strings is the
content companion -- the URLs, error messages and format strings a triage pass
greps for live in the data section. It is ``strings`` of that section, parsed
in-process (no wabt). These build a real data section and cover the extraction,
min_length, the case-insensitive filter, the no-data-section case, the huge-run
clip, paging via the client, the error paths, service routing, and read-only.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import parse_data_strings
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

_HEADER = b"\x00asm\x01\x00\x00\x00"


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


def _section(sec_id: int, body: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(body)) + body


def _data_section(payload: bytes) -> bytes:
    # One active segment: flags 0, offset expr `i32.const 0` `end`, then the raw
    # bytes. wasm.strings scans the whole section body, so the framing bytes
    # (flags/expr/length) are included but too short to form printable runs.
    segment = b"\x00" + b"\x41\x00\x0b" + _uleb(len(payload)) + payload
    return _section(11, _uleb(1) + segment)


def _module_with_data(payload: bytes) -> bytes:
    # A dummy type section in front proves the data section is found by walking.
    return _HEADER + _section(1, _uleb(0)) + _data_section(payload)


def _module_without_data() -> bytes:
    return _HEADER + _section(1, _uleb(0))


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


_PAYLOAD = (
    b"https://evil.example.com/c2\x00"
    b"GET /api/v1/login\x00"
    b"ab\x00"  # 2 chars: below the default min_length, dropped
    b"Content-Type\x00"
)


def test_wasm_strings_extracts_printable_runs() -> None:
    rows, has_data, scan_capped = parse_data_strings(_module_with_data(_PAYLOAD))
    assert has_data is True
    assert scan_capped is False
    texts = [row["text"] for row in rows]
    assert "https://evil.example.com/c2" in texts
    assert "GET /api/v1/login" in texts
    assert "Content-Type" in texts
    # The 2-char run is below the default min_length of 4.
    assert "ab" not in texts
    # Offsets are ascending (scan order) and each carries its byte length.
    offsets = [row["offset"] for row in rows]
    assert offsets == sorted(offsets)
    row = next(r for r in rows if r["text"] == "Content-Type")
    assert row["size"] == len("Content-Type")


def test_wasm_strings_min_length_drops_shorter_runs() -> None:
    rows, _has, _capped = parse_data_strings(_module_with_data(_PAYLOAD), min_length=15)
    texts = {row["text"] for row in rows}
    # Only runs of 15+ printable chars survive.
    assert "https://evil.example.com/c2" in texts
    assert "GET /api/v1/login" in texts
    assert "Content-Type" not in texts  # 12 chars


def test_wasm_strings_name_filter_is_case_insensitive() -> None:
    rows, _has, _capped = parse_data_strings(
        _module_with_data(_PAYLOAD), name_filter="HTTPS"
    )
    assert [row["text"] for row in rows] == ["https://evil.example.com/c2"]


def test_wasm_strings_no_data_section_is_empty_not_error() -> None:
    rows, has_data, scan_capped = parse_data_strings(_module_without_data())
    assert rows == []
    assert has_data is False
    assert scan_capped is False


def test_wasm_strings_clips_a_huge_run_and_marks_it() -> None:
    from headless_re_mcp.backends.jsre.wasm_summary import _MAX_STRING_TEXT

    payload = b"A" * (_MAX_STRING_TEXT + 500) + b"\x00"
    rows, _has, _capped = parse_data_strings(_module_with_data(payload))
    assert len(rows) == 1
    row = rows[0]
    assert len(row["text"]) == _MAX_STRING_TEXT
    assert row["text_truncated"] is True
    # size reports the full on-disk run, not the clipped text.
    assert row["size"] == _MAX_STRING_TEXT + 500


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "mod.wasm"
    p.write_bytes(data)
    return p


def test_wasm_client_strings_pages_and_totals(tmp_path: Path) -> None:
    payload = b"".join(f"string_number_{i:03d}\x00".encode() for i in range(10))
    out = WasmClient().strings(_write(tmp_path, _module_with_data(payload)), limit=3)
    assert out["has_data_section"] is True
    assert out["count"] == 3
    assert out["total"] == 10
    assert out["offset"] == 0
    assert out["has_more"] is True
    assert out["scan_capped"] is False
    page2 = WasmClient().strings(
        _write(tmp_path, _module_with_data(payload)), offset=9, limit=3
    )
    assert page2["count"] == 1
    assert page2["has_more"] is False


def test_wasm_client_strings_stripped_module_is_the_answer(tmp_path: Path) -> None:
    out = WasmClient().strings(_write(tmp_path, _module_without_data()))
    assert out["has_data_section"] is False
    assert out["strings"] == []
    assert out["total"] == 0


def test_wasm_client_strings_not_a_module_is_invalid_params(tmp_path: Path) -> None:
    p = tmp_path / "notwasm.bin"
    p.write_bytes(b"MZ\x90\x00 this is not a wasm module at all")
    from headless_re_mcp.backends.jsre.client import JsReError

    with pytest.raises(JsReError) as info:
        WasmClient().strings(p)
    assert info.value.code == "invalid_params"


def test_wasm_client_strings_missing_file_is_not_found(tmp_path: Path) -> None:
    from headless_re_mcp.backends.jsre.client import JsReError

    with pytest.raises(JsReError) as info:
        WasmClient().strings(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_wasm_client_strings_page_limit_is_capped(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_STRINGS_PAGE", 2)
    payload = b"".join(f"str_{i:03d}_xxxx\x00".encode() for i in range(6))
    out = WasmClient().strings(_write(tmp_path, _module_with_data(payload)), limit=1000)
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_service_wasm_strings_routes_to_the_client(tmp_path: Path) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        payload = b"https://api.example.com/token\x00hello world\x00"
        p = _write(tmp_path, _module_with_data(payload))
        result = service.wasm_strings(str(p), name_filter="api.example")
        assert result.ok and result.data is not None
        assert [r["text"] for r in result.data["strings"]] == [
            "https://api.example.com/token"
        ]
        assert result.data["total"] == 1
    finally:
        service.close_all()


def test_wasm_strings_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("wasm.strings").split())
    assert "data section" in doc
    assert "has_data_section" in doc
    assert "min_length" in doc
    assert "name_filter" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "wasm.strings" in _READ_ONLY_NAMES

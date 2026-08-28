"""Unit tests for wasm.custom_sections (pure-Python custom-section lister).

Hand-crafted modules interleave custom (id 0) and non-custom sections so the
filter keeps only customs, the payload offset/size point at the bytes after the
section name, the decoder routing maps the three known names and leaves the rest
null, duplicate names are listed separately in binary order, and a malformed
custom name or an over-long section is reported as truncated with a best-effort
null-name row. The non-wasm and missing-file guards are covered too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import (
    JsReError,
    parse_wasm_custom_sections,
)

_PREAMBLE = b"\x00asm\x01\x00\x00\x00"


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


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _custom(name: str, payload: bytes = b"") -> bytes:
    return _section(0, _name(name) + payload)


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes) -> Path:
    target = tmp_path / "mod.wasm"
    target.write_bytes(data)
    return target


def test_filters_customs_and_reports_payload_range(tmp_path: Path) -> None:
    module = _module(
        _section(1, _uleb(0)),  # a (non-custom) type section, must be skipped
        _custom("producers", b"\x01\x02\x03"),
        _custom(".debug_info", b"\xaa\xbb"),
    )
    payload = parse_wasm_custom_sections(_write(tmp_path, module))
    assert payload["total"] == 2
    rows = payload["custom_sections"]
    assert [r["name"] for r in rows] == ["producers", ".debug_info"]
    # producers payload is the 3 bytes after its name.
    assert rows[0]["size"] == 3
    assert rows[0]["decoder"] == "wasm.producers"
    # .debug_info is opaque: 2 payload bytes, no decoder.
    assert rows[1]["size"] == 2
    assert rows[1]["decoder"] is None
    assert payload["truncated"] is False


def test_payload_offset_points_at_content_after_name(tmp_path: Path) -> None:
    module = _module(_custom("name", b"\xde\xad\xbe\xef"))
    raw = _write(tmp_path, module)
    payload = parse_wasm_custom_sections(raw)
    row = payload["custom_sections"][0]
    assert row["decoder"] == "wasm.names"
    assert row["size"] == 4
    # The reported slice is exactly the payload we supplied.
    data = raw.read_bytes()
    assert data[row["offset"] : row["offset"] + row["size"]] == b"\xde\xad\xbe\xef"


def test_all_three_known_decoders_route(tmp_path: Path) -> None:
    module = _module(
        _custom("name"),
        _custom("producers"),
        _custom("target_features"),
        _custom("vendor.blob"),
    )
    payload = parse_wasm_custom_sections(_write(tmp_path, module))
    routing = {r["name"]: r["decoder"] for r in payload["custom_sections"]}
    assert routing == {
        "name": "wasm.names",
        "producers": "wasm.producers",
        "target_features": "wasm.features",
        "vendor.blob": None,
    }


def test_duplicate_names_listed_separately(tmp_path: Path) -> None:
    module = _module(_custom("dup", b"\x01"), _custom("dup", b"\x02\x03"))
    payload = parse_wasm_custom_sections(_write(tmp_path, module))
    rows = payload["custom_sections"]
    assert [r["name"] for r in rows] == ["dup", "dup"]
    assert [r["size"] for r in rows] == [1, 2]


def test_no_custom_sections(tmp_path: Path) -> None:
    payload = parse_wasm_custom_sections(_write(tmp_path, _module(_section(1, _uleb(0)))))
    assert payload["custom_sections"] == []
    assert payload["total"] == 0
    assert payload["truncated"] is False


def test_malformed_custom_name_is_truncated_with_null_row(tmp_path: Path) -> None:
    # Declare a name length of 20 but give only 2 bytes before the section ends.
    bad_body = _uleb(20) + b"ab"
    module = _module(_section(0, bad_body))
    payload = parse_wasm_custom_sections(_write(tmp_path, module))
    assert payload["truncated"] is True
    assert payload["custom_sections"][0]["name"] is None
    assert payload["custom_sections"][0]["decoder"] is None


def test_section_running_past_module_is_truncated(tmp_path: Path) -> None:
    # A custom section header claiming a body far larger than what follows.
    module = _PREAMBLE + bytes([0]) + _uleb(100) + _name("big")
    payload = parse_wasm_custom_sections(_write(tmp_path, module))
    assert payload["truncated"] is True
    assert payload["custom_sections"][0]["name"] is None


def test_page_window_and_has_more(tmp_path: Path) -> None:
    module = _module(*[_custom(f"c{i:02d}") for i in range(15)])
    raw = _write(tmp_path, module)
    first = parse_wasm_custom_sections(raw, offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 15
    assert first["has_more"] is True
    tail = parse_wasm_custom_sections(raw, offset=10, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def test_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_WASM_CUSTOM_COLLECT", 2)
    module = _module(*[_custom(f"c{i}") for i in range(5)])
    payload = parse_wasm_custom_sections(_write(tmp_path, module))
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


def test_not_a_wasm_module_is_invalid_params(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_custom_sections(_write(tmp_path, b"nope not wasm"))
    assert info.value.code == "invalid_params"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_custom_sections(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"

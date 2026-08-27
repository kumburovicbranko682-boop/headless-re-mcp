"""Unit tests for wasm.sections (pure-Python, wabt-free section-table walker).

The walker is exercised against hand-crafted .wasm binaries so the section
id/name mapping, the leading-vec entry count, the custom-section name read,
binary-order preservation, and the truncated/malformed degradation are really
executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_sections

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
    encoded = text.encode("utf-8")
    return _uleb(len(encoded)) + encoded


def _sec(
    section_id: int,
    *,
    count: int | None = None,
    custom_name: str | None = None,
    extra: bytes = b"",
) -> bytes:
    if custom_name is not None:
        body = _name(custom_name) + extra
    elif count is not None:
        body = _uleb(count) + extra
    else:
        body = extra
    return bytes([section_id]) + _uleb(len(body)) + body


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_sections_mixed_table(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _PREAMBLE
        + b"".join(
            [
                _sec(1, count=2),  # type, 2 entries
                _sec(3, count=1),  # function, 1 entry
                _sec(0, custom_name="name"),  # custom
                _sec(7, count=1),  # export, 1 entry
                _sec(8),  # start, no vec
                _sec(12, count=3),  # data_count, declared 3 segments
            ]
        ),
    )

    payload = parse_wasm_sections(src)
    rows = payload["sections"]

    assert [r["id"] for r in rows] == [1, 3, 0, 7, 8, 12]
    assert [r["name"] for r in rows] == [
        "type",
        "function",
        "custom",
        "export",
        "start",
        "data_count",
    ]
    assert rows[0]["entries"] == 2
    assert rows[1]["entries"] == 1
    assert "entries" not in rows[2]
    assert rows[2]["custom_name"] == "name"
    assert rows[3]["entries"] == 1
    assert "entries" not in rows[4]
    assert "custom_name" not in rows[4]
    assert rows[5]["entries"] == 3
    assert payload["total"] == 6
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_sections_offsets_and_size(tmp_path: Path) -> None:
    src = _write(
        tmp_path, _PREAMBLE + b"".join([_sec(1, count=2), _sec(7, count=1)])
    )

    rows = parse_wasm_sections(src)["sections"]

    # First section's id byte sits right after the 8-byte preamble; offsets
    # then advance strictly and the declared size is the body length.
    assert rows[0]["offset"] == 8
    offs = [r["offset"] for r in rows]
    assert offs == sorted(offs) and len(set(offs)) == len(offs)
    assert rows[0]["size"] == 1  # body is just _uleb(2)


def test_wasm_sections_unknown_id(tmp_path: Path) -> None:
    src = _write(tmp_path, _PREAMBLE + _sec(99, extra=b"\x00"))

    rows = parse_wasm_sections(src)["sections"]

    assert rows == [{"id": 99, "name": "unknown", "offset": 8, "size": 1}]


def test_wasm_sections_empty_module(tmp_path: Path) -> None:
    src = _write(tmp_path, _PREAMBLE)

    payload = parse_wasm_sections(src)

    assert payload["sections"] == []
    assert payload["total"] == 0
    assert payload["truncated"] is False


def test_wasm_sections_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm at all", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_sections(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_sections_truncated_body_is_marked(tmp_path: Path) -> None:
    # A type section claims a 50-byte body but only 3 bytes follow.
    src = _write(tmp_path, _PREAMBLE + bytes([1]) + _uleb(50) + b"\x01\x02\x03")

    payload = parse_wasm_sections(src)

    assert payload["truncated"] is True
    assert len(payload["sections"]) == 1
    row = payload["sections"][0]
    assert row["id"] == 1
    assert row["size"] == 50  # declared size preserved
    assert "entries" not in row  # short body is not parsed


def test_wasm_sections_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path, _PREAMBLE + b"".join(_sec(1, count=i) for i in range(5))
    )

    payload = parse_wasm_sections(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["entries"] for r in payload["sections"]] == [2, 3]


def test_wasm_sections_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_SECTIONS_COLLECT", 3
    )
    src = _write(
        tmp_path, _PREAMBLE + b"".join(_sec(1, count=i) for i in range(10))
    )

    payload = parse_wasm_sections(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_sections_clamps_oversized_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_SECTIONS_PAGE", 2
    )
    src = _write(
        tmp_path, _PREAMBLE + b"".join(_sec(1, count=i) for i in range(5))
    )

    payload = parse_wasm_sections(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_sections_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_sections(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_sections_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _PREAMBLE + _sec(1, count=1))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_sections(src)
    assert excinfo.value.code == "too_large"


def test_wasm_sections_docstring_names_shape() -> None:
    doc = parse_wasm_sections.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc

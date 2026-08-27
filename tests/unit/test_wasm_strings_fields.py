"""Unit tests for wasm.strings (pure-Python data-section printable-run scan).

The scan is exercised against hand-crafted .wasm binaries whose data section
carries known printable runs separated by non-printable bytes, so the run
extraction, min-length filtering, de-duplication, first-appearance ordering,
and the missing-section / truncated degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_strings

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


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _data_section(body: bytes) -> bytes:
    # The scan reads the raw section body, so any bytes serve as a fixture.
    return _section(11, body)


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_strings_extracts_and_drops_short(tmp_path: Path) -> None:
    body = b"\x00hello\x00https://example.io\x00hi\x00"
    src = _write(tmp_path, _module(_data_section(body)))

    payload = parse_wasm_strings(src)

    # "hi" is 2 chars, below the default min of 4, so it is dropped.
    assert payload["strings"] == ["hello", "https://example.io"]
    assert payload["has_data_section"] is True
    assert payload["total"] == 2
    assert payload["min_length"] == 4
    assert payload["data_bytes"] == len(body)
    assert payload["truncated"] is False


def test_wasm_strings_respects_min_length(tmp_path: Path) -> None:
    body = b"\x00hello\x00https://example.io\x00"
    src = _write(tmp_path, _module(_data_section(body)))

    payload = parse_wasm_strings(src, min_length=6)

    assert payload["strings"] == ["https://example.io"]
    assert payload["min_length"] == 6


def test_wasm_strings_deduplicates_first_seen_order(tmp_path: Path) -> None:
    body = b"\x00beta\x00alpha\x00beta\x00alpha\x00"
    src = _write(tmp_path, _module(_data_section(body)))

    payload = parse_wasm_strings(src)

    assert payload["strings"] == ["beta", "alpha"]
    assert payload["total"] == 2


def test_wasm_strings_no_data_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_strings(src)

    assert payload["has_data_section"] is False
    assert payload["strings"] == []
    assert payload["total"] == 0
    assert payload["data_bytes"] == 0


def test_wasm_strings_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_strings(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_strings_paginates(tmp_path: Path) -> None:
    body = b"\x00".join(f"item{i:03d}".encode() for i in range(5))
    src = _write(tmp_path, _module(_data_section(body)))

    payload = parse_wasm_strings(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["strings"] == ["item002", "item003"]


def test_wasm_strings_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_STRINGS_COLLECT", 3
    )
    body = b"\x00".join(f"item{i:03d}".encode() for i in range(10))
    src = _write(tmp_path, _module(_data_section(body)))

    payload = parse_wasm_strings(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_strings_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_STRINGS_PAGE", 2
    )
    body = b"\x00".join(f"item{i:03d}".encode() for i in range(5))
    src = _write(tmp_path, _module(_data_section(body)))

    payload = parse_wasm_strings(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_strings_clips_long_run(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_STRING_LEN", 8
    )
    body = b"\x00" + (b"a" * 40) + b"\x00"
    src = _write(tmp_path, _module(_data_section(body)))

    payload = parse_wasm_strings(src)

    assert payload["strings"] == ["a" * 8]


def test_wasm_strings_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_strings(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_strings_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_data_section(b"\x00hello\x00")))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_strings(src)
    assert excinfo.value.code == "too_large"


def test_wasm_strings_docstring_names_shape() -> None:
    doc = parse_wasm_strings.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc

"""Unit tests for wasm.producers (pure-Python build-toolchain fingerprint).

The parser is exercised against hand-crafted "producers" custom sections
carrying the conventional language/processed-by/sdk fields with (name, version)
pairs, an empty version, other custom sections that must be skipped, and a
truncated field vector, so the flattening, the section lookup and the truncated
degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_producers

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


def _custom_section(name: str, payload: bytes) -> bytes:
    return _section(0, _name(name) + payload)


def _field(field_name: str, *pairs: tuple[str, str]) -> bytes:
    body = _name(field_name) + _uleb(len(pairs))
    for name, version in pairs:
        body += _name(name) + _name(version)
    return body


def _producers(*fields: bytes) -> bytes:
    return _custom_section("producers", _uleb(len(fields)) + b"".join(fields))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_producers_decodes_fields(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _producers(
                _field("language", ("Rust", "1.75.0")),
                _field(
                    "processed-by", ("rustc", "1.75.0"), ("clang", "17.0.0")
                ),
                _field("sdk", ("wasm-bindgen", "0.2.89")),
            )
        ),
    )

    payload = parse_wasm_producers(src)

    assert payload["has_producers_section"] is True
    assert payload["total"] == 4
    assert payload["producers"] == [
        {"field": "language", "name": "Rust", "version": "1.75.0"},
        {"field": "processed-by", "name": "rustc", "version": "1.75.0"},
        {"field": "processed-by", "name": "clang", "version": "17.0.0"},
        {"field": "sdk", "name": "wasm-bindgen", "version": "0.2.89"},
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_producers_empty_version(tmp_path: Path) -> None:
    src = _write(
        tmp_path, _module(_producers(_field("language", ("C", ""))))
    )

    row = parse_wasm_producers(src)["producers"][0]

    assert row == {"field": "language", "name": "C", "version": ""}


def test_wasm_producers_skips_other_custom_sections(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _custom_section("name", b"\x00\x00"),
            _producers(_field("language", ("Rust", "1.75.0"))),
        ),
    )

    payload = parse_wasm_producers(src)

    assert payload["has_producers_section"] is True
    assert payload["producers"][0]["name"] == "Rust"


def test_wasm_producers_no_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_producers(src)

    assert payload["has_producers_section"] is False
    assert payload["producers"] == []
    assert payload["total"] == 0


def test_wasm_producers_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_producers(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_producers_truncated_field_is_marked(tmp_path: Path) -> None:
    # The field vec claims two values but only one (name, version) pair follows.
    field = _name("processed-by") + _uleb(2) + _name("rustc") + _name("1.75.0")
    src = _write(tmp_path, _module(_producers(field)))

    payload = parse_wasm_producers(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1  # the value read before the cut survives
    assert payload["producers"][0]["name"] == "rustc"


def test_wasm_producers_paginates(tmp_path: Path) -> None:
    pairs = tuple((f"tool{i}", f"{i}.0") for i in range(5))
    src = _write(tmp_path, _module(_producers(_field("processed-by", *pairs))))

    payload = parse_wasm_producers(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["name"] for r in payload["producers"]] == ["tool2", "tool3"]


def test_wasm_producers_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_PRODUCERS_COLLECT", 3
    )
    pairs = tuple((f"tool{i}", f"{i}.0") for i in range(10))
    src = _write(tmp_path, _module(_producers(_field("processed-by", *pairs))))

    payload = parse_wasm_producers(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_producers_clamps_oversized_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_PRODUCERS_PAGE", 2
    )
    pairs = tuple((f"tool{i}", f"{i}.0") for i in range(5))
    src = _write(tmp_path, _module(_producers(_field("processed-by", *pairs))))

    payload = parse_wasm_producers(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_producers_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_producers(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_producers_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(
        tmp_path, _module(_producers(_field("language", ("Rust", "1.75.0"))))
    )

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_producers(src)
    assert excinfo.value.code == "too_large"


def test_wasm_producers_docstring_names_shape() -> None:
    doc = parse_wasm_producers.__doc__ or ""
    assert "wabt-free" in doc
    assert "provenance" in doc
    assert "truncated" in doc

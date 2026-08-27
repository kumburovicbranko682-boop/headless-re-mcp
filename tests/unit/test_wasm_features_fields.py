"""Unit tests for wasm.features (pure-Python target_features decoder).

The parser is exercised against hand-crafted "target_features" custom sections
carrying the '+' / '-' / '=' prefixes and an unknown marker byte, other custom
sections that must be skipped, and a truncated feature vector, so the prefix
mapping, the section lookup and the truncated degradation are all really
executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_features

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


def _feature(prefix: bytes, name: str) -> bytes:
    return prefix + _name(name)


def _target_features(*features: bytes) -> bytes:
    return _custom_section(
        "target_features", _uleb(len(features)) + b"".join(features)
    )


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_features_decodes_used_features(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _target_features(
                _feature(b"\x2b", "simd128"),
                _feature(b"\x2b", "atomics"),
                _feature(b"\x2b", "bulk-memory"),
            )
        ),
    )

    payload = parse_wasm_features(src)

    assert payload["has_target_features_section"] is True
    assert payload["total"] == 3
    assert payload["features"] == [
        {"name": "simd128", "prefix": "+"},
        {"name": "atomics", "prefix": "+"},
        {"name": "bulk-memory", "prefix": "+"},
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_features_all_prefix_markers(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _target_features(
                _feature(b"\x2b", "used"),
                _feature(b"\x2d", "disallowed"),
                _feature(b"\x3d", "required"),
                _feature(b"\x7e", "weird"),  # unknown marker -> hex
            )
        ),
    )

    prefixes = {
        row["name"]: row["prefix"]
        for row in parse_wasm_features(src)["features"]
    }

    assert prefixes == {
        "used": "+",
        "disallowed": "-",
        "required": "=",
        "weird": "0x7e",
    }


def test_wasm_features_skips_other_custom_sections(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _custom_section("producers", b"\x00"),
            _target_features(_feature(b"\x2b", "tail-call")),
        ),
    )

    payload = parse_wasm_features(src)

    assert payload["has_target_features_section"] is True
    assert payload["features"][0]["name"] == "tail-call"


def test_wasm_features_no_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_features(src)

    assert payload["has_target_features_section"] is False
    assert payload["features"] == []
    assert payload["total"] == 0


def test_wasm_features_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_features(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_features_truncated_vector_is_marked(tmp_path: Path) -> None:
    # The vector claims three features but only one follows.
    body = _uleb(3) + _feature(b"\x2b", "simd128")
    src = _write(tmp_path, _module(_custom_section("target_features", body)))

    payload = parse_wasm_features(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["features"][0]["name"] == "simd128"


def test_wasm_features_paginates(tmp_path: Path) -> None:
    feats = [_feature(b"\x2b", f"feat{i}") for i in range(5)]
    src = _write(tmp_path, _module(_target_features(*feats)))

    payload = parse_wasm_features(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["name"] for r in payload["features"]] == ["feat2", "feat3"]


def test_wasm_features_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_FEATURES_COLLECT", 3
    )
    feats = [_feature(b"\x2b", f"feat{i}") for i in range(10)]
    src = _write(tmp_path, _module(_target_features(*feats)))

    payload = parse_wasm_features(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_features_clamps_oversized_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_FEATURES_PAGE", 2
    )
    feats = [_feature(b"\x2b", f"feat{i}") for i in range(5)]
    src = _write(tmp_path, _module(_target_features(*feats)))

    payload = parse_wasm_features(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_features_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_features(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_features_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(
        tmp_path, _module(_target_features(_feature(b"\x2b", "simd128")))
    )

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_features(src)
    assert excinfo.value.code == "too_large"


def test_wasm_features_docstring_names_shape() -> None:
    doc = parse_wasm_features.__doc__ or ""
    assert "wabt-free" in doc
    assert "target_features" in doc
    assert "truncated" in doc

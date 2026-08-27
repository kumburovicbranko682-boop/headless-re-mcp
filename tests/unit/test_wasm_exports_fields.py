"""Unit tests for wasm.exports (pure-Python, wabt-free export-section parser).

The parser is exercised against hand-crafted .wasm binaries so the LEB128
decoding, the (name, kind byte, index) export layout, binary-order
preservation, and the malformed/truncated degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_exports

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


def _export(name: str, kind: int, index: int) -> bytes:
    return _name(name) + bytes([kind]) + _uleb(index)


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _module(*exports: bytes) -> bytes:
    body = _uleb(len(exports)) + b"".join(exports)
    return _PREAMBLE + _section(7, body)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_exports_all_kinds_in_order(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _export("_malloc", 0, 12),
            _export("memory", 2, 0),
            _export("__indirect_function_table", 1, 0),
            _export("__stack_pointer", 3, 4),
        ),
    )

    payload = parse_wasm_exports(src)

    assert payload["exports"] == [
        {"name": "_malloc", "kind": "func", "index": 12},
        {"name": "memory", "kind": "memory", "index": 0},
        {"name": "__indirect_function_table", "kind": "table", "index": 0},
        {"name": "__stack_pointer", "kind": "global", "index": 4},
    ]
    assert payload["count"] == 4
    assert payload["total"] == 4
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert payload["truncated"] is False


def test_wasm_exports_empty_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module())

    payload = parse_wasm_exports(src)

    assert payload["exports"] == []
    assert payload["total"] == 0
    assert payload["truncated"] is False


def test_wasm_exports_no_export_section(tmp_path: Path) -> None:
    # A bare preamble plus an unrelated (type) section, id 1.
    src = _write(tmp_path, _PREAMBLE + _section(1, _uleb(0)))

    payload = parse_wasm_exports(src)

    assert payload["exports"] == []
    assert payload["total"] == 0
    assert payload["truncated"] is False


def test_wasm_exports_skips_sections_before_exports(tmp_path: Path) -> None:
    # A custom section (id 0) and an import section (id 2) precede exports.
    custom = _section(0, _name("producers") + b"\x01\x02\x03")
    imports = _section(2, _uleb(0))
    body = _uleb(1) + _export("run", 0, 0)
    src = _write(tmp_path, _PREAMBLE + custom + imports + _section(7, body))

    payload = parse_wasm_exports(src)

    assert payload["exports"] == [{"name": "run", "kind": "func", "index": 0}]


def test_wasm_exports_unknown_kind_byte(tmp_path: Path) -> None:
    # An out-of-range kind byte is surfaced as "unknown", not dropped.
    src = _write(tmp_path, _module(_export("weird", 9, 1)))

    payload = parse_wasm_exports(src)

    assert payload["exports"] == [{"name": "weird", "kind": "unknown", "index": 1}]


def test_wasm_exports_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"GIF89a not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_exports(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_exports_truncated_count_is_marked(tmp_path: Path) -> None:
    # Declare 3 exports but supply only 1; the parse stops and flags truncated.
    body = _uleb(3) + _export("a", 0, 0)
    src = _write(tmp_path, _PREAMBLE + _section(7, body))

    payload = parse_wasm_exports(src)

    assert payload["exports"] == [{"name": "a", "kind": "func", "index": 0}]
    assert payload["truncated"] is True


def test_wasm_exports_paginates(tmp_path: Path) -> None:
    exports = tuple(_export(f"f{i:03d}", 0, i) for i in range(5))
    src = _write(tmp_path, _module(*exports))

    payload = parse_wasm_exports(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [row["name"] for row in payload["exports"]] == ["f002", "f003"]


def test_wasm_exports_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_EXPORTS_COLLECT", 3
    )
    exports = tuple(_export(f"f{i:03d}", 0, i) for i in range(10))
    src = _write(tmp_path, _module(*exports))

    payload = parse_wasm_exports(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_exports_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_EXPORTS_PAGE", 2
    )
    exports = tuple(_export(f"f{i:03d}", 0, i) for i in range(5))
    src = _write(tmp_path, _module(*exports))

    payload = parse_wasm_exports(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_exports_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_exports(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_exports_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_export("run", 0, 0)))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_exports(src)
    assert excinfo.value.code == "too_large"


def test_wasm_exports_docstring_names_shape() -> None:
    doc = parse_wasm_exports.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc

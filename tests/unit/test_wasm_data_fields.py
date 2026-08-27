"""Unit tests for wasm.data (pure-Python data-segment load-map parser).

The parser is exercised against hand-crafted .wasm binaries whose data section
carries active (mode 0 and mode 2), passive, and computed-offset segments, so
the mode dispatch, the i32.const offset evaluation, the const-expr skip for a
non-constant offset, and the truncated/missing degradation are all really
executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_data

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


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        if done:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _i32_const_expr(n: int) -> bytes:
    return b"\x41" + _sleb(n) + b"\x0b"


def _active_seg(offset_n: int, payload: bytes) -> bytes:
    return b"\x00" + _i32_const_expr(offset_n) + _uleb(len(payload)) + payload


def _passive_seg(payload: bytes) -> bytes:
    return b"\x01" + _uleb(len(payload)) + payload


def _active_seg_memidx(memidx: int, offset_n: int, payload: bytes) -> bytes:
    return (
        b"\x02"
        + _uleb(memidx)
        + _i32_const_expr(offset_n)
        + _uleb(len(payload))
        + payload
    )


def _active_seg_globalget(gidx: int, payload: bytes) -> bytes:
    return b"\x00" + b"\x23" + _uleb(gidx) + b"\x0b" + _uleb(len(payload)) + payload


def _data_section(*segs: bytes) -> bytes:
    return _section(11, _uleb(len(segs)) + b"".join(segs))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_data_mixed_segments(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _data_section(
                _active_seg(1024, b"hello"),
                _passive_seg(b"xy"),
                _active_seg_memidx(0, 2048, b"z"),
            )
        ),
    )

    payload = parse_wasm_data(src)

    assert payload["has_data_section"] is True
    assert payload["total"] == 3
    assert payload["segments"] == [
        {
            "index": 0,
            "mode": "active",
            "memory_index": 0,
            "memory_offset": 1024,
            "size": 5,
        },
        {"index": 1, "mode": "passive", "size": 2},
        {
            "index": 2,
            "mode": "active",
            "memory_index": 0,
            "memory_offset": 2048,
            "size": 1,
        },
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_data_computed_offset_is_null(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_data_section(_active_seg_globalget(0, b"abcd"))),
    )

    row = parse_wasm_data(src)["segments"][0]

    assert row["mode"] == "active"
    assert row["memory_index"] == 0
    assert row["memory_offset"] is None
    assert row["size"] == 4


def test_wasm_data_no_data_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_data(src)

    assert payload["has_data_section"] is False
    assert payload["segments"] == []
    assert payload["total"] == 0


def test_wasm_data_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_data(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_data_segment_bytes_past_end_is_marked(tmp_path: Path) -> None:
    # An active segment declares a 50-byte payload but only 2 bytes follow.
    seg = b"\x00" + _i32_const_expr(0) + _uleb(50) + b"\x01\x02"
    src = _write(tmp_path, _module(_data_section(seg)))

    payload = parse_wasm_data(src)

    assert payload["truncated"] is True
    assert payload["total"] == 0  # the malformed segment is not emitted


def test_wasm_data_unknown_flag_is_marked(tmp_path: Path) -> None:
    # First segment valid; the second uses an unknown mode flag (3).
    bad = b"\x03" + _uleb(1) + b"\x00"
    src = _write(
        tmp_path, _module(_data_section(_active_seg(0, b"good"), bad))
    )

    payload = parse_wasm_data(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["segments"][0]["index"] == 0


def test_wasm_data_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _data_section(*[_active_seg(i * 8, b"ab") for i in range(5)])
        ),
    )

    payload = parse_wasm_data(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["index"] for r in payload["segments"]] == [2, 3]


def test_wasm_data_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_DATA_COLLECT", 3
    )
    src = _write(
        tmp_path,
        _module(
            _data_section(*[_active_seg(i * 8, b"ab") for i in range(10)])
        ),
    )

    payload = parse_wasm_data(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_data_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_DATA_PAGE", 2
    )
    src = _write(
        tmp_path,
        _module(
            _data_section(*[_active_seg(i * 8, b"ab") for i in range(5)])
        ),
    )

    payload = parse_wasm_data(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_data_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_data(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_data_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_data_section(_active_seg(0, b"hello"))))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_data(src)
    assert excinfo.value.code == "too_large"


def test_wasm_data_docstring_names_shape() -> None:
    doc = parse_wasm_data.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc

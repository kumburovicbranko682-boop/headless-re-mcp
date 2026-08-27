"""Unit tests for wasm.elements (pure-Python call_indirect target-map parser).

The parser is exercised against hand-crafted .wasm binaries whose element
section carries active (flags 0, 2 and 4), passive (flag 1) and declared
(flag 3) segments in both the funcidx and const-expr encodings, so the flags
dispatch, the slot arithmetic, the ref.func evaluation, the ref.null and
computed-offset degradation to null, and the truncated handling are all really
executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_elements

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


def _funcidx_vec(*indices: int) -> bytes:
    return _uleb(len(indices)) + b"".join(_uleb(i) for i in indices)


def _active0_seg(offset_n: int, *indices: int) -> bytes:
    return b"\x00" + _i32_const_expr(offset_n) + _funcidx_vec(*indices)


def _passive_seg(*indices: int) -> bytes:
    return b"\x01" + b"\x00" + _funcidx_vec(*indices)  # elemkind 0 = funcref


def _active_tableidx_seg(tableidx: int, offset_n: int, *indices: int) -> bytes:
    return (
        b"\x02"
        + _uleb(tableidx)
        + _i32_const_expr(offset_n)
        + b"\x00"
        + _funcidx_vec(*indices)
    )


def _declared_seg(*indices: int) -> bytes:
    return b"\x03" + b"\x00" + _funcidx_vec(*indices)


def _ref_func_expr(idx: int) -> bytes:
    return b"\xd2" + _uleb(idx) + b"\x0b"


_REF_NULL_FUNC_EXPR = b"\xd0\x70\x0b"


def _active0_expr_seg(offset_n: int, *exprs: bytes) -> bytes:
    return (
        b"\x04" + _i32_const_expr(offset_n) + _uleb(len(exprs)) + b"".join(exprs)
    )


def _active0_globalget_seg(gidx: int, *indices: int) -> bytes:
    return b"\x00" + b"\x23" + _uleb(gidx) + b"\x0b" + _funcidx_vec(*indices)


def _elem_section(*segs: bytes) -> bytes:
    return _section(9, _uleb(len(segs)) + b"".join(segs))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_elements_active_funcidx_segment(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_elem_section(_active0_seg(10, 7, 8, 9))))

    payload = parse_wasm_elements(src)

    assert payload["has_element_section"] is True
    assert payload["segment_count"] == 1
    assert payload["total"] == 3
    assert payload["entries"] == [
        {"segment": 0, "mode": "active", "table_index": 0, "slot": 10,
         "func_index": 7},
        {"segment": 0, "mode": "active", "table_index": 0, "slot": 11,
         "func_index": 8},
        {"segment": 0, "mode": "active", "table_index": 0, "slot": 12,
         "func_index": 9},
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_elements_passive_and_declared(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_elem_section(_passive_seg(4, 5), _declared_seg(6))),
    )

    payload = parse_wasm_elements(src)

    assert payload["segment_count"] == 2
    assert payload["entries"][0] == {
        "segment": 0,
        "mode": "passive",
        "table_index": None,
        "slot": None,
        "func_index": 4,
    }
    assert payload["entries"][2] == {
        "segment": 1,
        "mode": "declared",
        "table_index": None,
        "slot": None,
        "func_index": 6,
    }


def test_wasm_elements_explicit_table_index(tmp_path: Path) -> None:
    src = _write(
        tmp_path, _module(_elem_section(_active_tableidx_seg(2, 0, 3)))
    )

    row = parse_wasm_elements(src)["entries"][0]

    assert row["mode"] == "active"
    assert row["table_index"] == 2
    assert row["slot"] == 0
    assert row["func_index"] == 3


def test_wasm_elements_expr_segment_resolves_ref_func(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _elem_section(
                _active0_expr_seg(5, _ref_func_expr(7), _REF_NULL_FUNC_EXPR)
            )
        ),
    )

    payload = parse_wasm_elements(src)

    assert payload["entries"] == [
        {"segment": 0, "mode": "active", "table_index": 0, "slot": 5,
         "func_index": 7},
        {"segment": 0, "mode": "active", "table_index": 0, "slot": 6,
         "func_index": None},
    ]
    assert payload["truncated"] is False


def test_wasm_elements_computed_offset_leaves_slot_null(tmp_path: Path) -> None:
    src = _write(
        tmp_path, _module(_elem_section(_active0_globalget_seg(0, 1, 2)))
    )

    payload = parse_wasm_elements(src)

    assert [r["slot"] for r in payload["entries"]] == [None, None]
    assert [r["func_index"] for r in payload["entries"]] == [1, 2]


def test_wasm_elements_no_element_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_elements(src)

    assert payload["has_element_section"] is False
    assert payload["entries"] == []
    assert payload["total"] == 0
    assert payload["segment_count"] == 0


def test_wasm_elements_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_elements(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_elements_truncated_segment_is_marked(tmp_path: Path) -> None:
    # The segment claims five function indices but only two follow.
    seg = b"\x00" + _i32_const_expr(0) + _uleb(5) + _uleb(1) + _uleb(2)
    src = _write(tmp_path, _module(_elem_section(seg)))

    payload = parse_wasm_elements(src)

    assert payload["truncated"] is True
    assert payload["total"] == 2  # the entries read before the cut survive
    assert [r["func_index"] for r in payload["entries"]] == [1, 2]


def test_wasm_elements_unknown_flags_is_marked(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_elem_section(_active0_seg(0, 1), b"\x08" + _funcidx_vec(2))),
    )

    payload = parse_wasm_elements(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["entries"][0]["func_index"] == 1


def test_wasm_elements_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path, _module(_elem_section(_active0_seg(0, *range(10, 15))))
    )

    payload = parse_wasm_elements(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["func_index"] for r in payload["entries"]] == [12, 13]
    assert [r["slot"] for r in payload["entries"]] == [2, 3]


def test_wasm_elements_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_ELEMENTS_COLLECT", 3
    )
    src = _write(
        tmp_path, _module(_elem_section(_active0_seg(0, *range(10))))
    )

    payload = parse_wasm_elements(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_elements_clamps_oversized_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_ELEMENTS_PAGE", 2
    )
    src = _write(
        tmp_path, _module(_elem_section(_active0_seg(0, *range(5))))
    )

    payload = parse_wasm_elements(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_elements_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_elements(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_elements_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_elem_section(_active0_seg(0, 1))))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_elements(src)
    assert excinfo.value.code == "too_large"


def test_wasm_elements_docstring_names_shape() -> None:
    doc = parse_wasm_elements.__doc__ or ""
    assert "wabt-free" in doc
    assert "call_indirect" in doc
    assert "truncated" in doc

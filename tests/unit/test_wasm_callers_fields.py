"""Unit tests for wasm.callers (pure-Python reverse call-graph / xref view).

The reverse-xref walk is exercised against hand-crafted code sections where
some functions call a target (via call and return_call) and some do not, an
import shifts the function index space, and one caller body uses an unknown
opcode, so the caller attribution, the call-site counting, and the
undecoded-body accounting are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_callers

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


def _func_body(instrs: bytes) -> bytes:
    return b"\x00" + instrs + b"\x0b"  # no locals, closing end opcode


def _code_section(*bodies: bytes) -> bytes:
    joined = b"".join(_uleb(len(body)) + body for body in bodies)
    return _section(10, _uleb(len(bodies)) + joined)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _func_import(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _import_section(*entries: bytes) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _call(idx: int) -> bytes:
    return b"\x10" + _uleb(idx)


def _return_call(idx: int) -> bytes:
    return b"\x12" + _uleb(idx)


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_callers_lists_direct_callers(tmp_path: Path) -> None:
    # func 0 calls 2, func 1 does not, func 2 calls 2 via return_call.
    src = _write(
        tmp_path,
        _module(
            _code_section(
                _func_body(_call(2)),
                _func_body(_call(0)),
                _func_body(_return_call(2)),
            )
        ),
    )

    payload = parse_wasm_callers(src, function=2)

    assert payload["target"] == 2
    assert payload["has_code_section"] is True
    assert payload["total"] == 2
    assert payload["callers"] == [
        {"index": 0, "call_sites": 1, "decoded": True},
        {"index": 2, "call_sites": 1, "decoded": True},
    ]
    assert payload["undecoded_bodies"] == 0
    assert payload["truncated"] is False


def test_wasm_callers_counts_multiple_sites(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_code_section(_func_body(_call(1) + _call(1) + _call(1)))),
    )

    row = parse_wasm_callers(src, function=1)["callers"][0]

    assert row["index"] == 0
    assert row["call_sites"] == 3


def test_wasm_callers_index_space_includes_imports(tmp_path: Path) -> None:
    # Two imported funcs (indices 0,1); the one local func (index 2) calls
    # imported function 0.
    src = _write(
        tmp_path,
        _module(
            _import_section(
                _func_import("env", "enc"), _func_import("env", "log")
            ),
            _code_section(_func_body(_call(0))),
        ),
    )

    payload = parse_wasm_callers(src, function=0)

    assert payload["imported_count"] == 2
    assert payload["callers"] == [{"index": 2, "call_sites": 1, "decoded": True}]


def test_wasm_callers_no_callers(tmp_path: Path) -> None:
    src = _write(
        tmp_path, _module(_code_section(_func_body(_call(1)), _func_body(b"")))
    )

    payload = parse_wasm_callers(src, function=9)

    assert payload["has_code_section"] is True
    assert payload["callers"] == []
    assert payload["total"] == 0


def test_wasm_callers_undecoded_body_is_accounted(tmp_path: Path) -> None:
    # func 0 calls target then hits the GC prefix (0xFB), so it is listed but
    # flagged decoded False and counted in undecoded_bodies. func 1 is clean.
    bad = _func_body(_call(3) + b"\xfb\x00\x00")
    good = _func_body(_call(3))
    src = _write(tmp_path, _module(_code_section(bad, good)))

    payload = parse_wasm_callers(src, function=3)

    assert payload["undecoded_bodies"] == 1
    assert payload["callers"] == [
        {"index": 0, "call_sites": 1, "decoded": False},
        {"index": 1, "call_sites": 1, "decoded": True},
    ]
    assert payload["truncated"] is False


def test_wasm_callers_no_code_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_callers(src, function=0)

    assert payload["has_code_section"] is False
    assert payload["callers"] == []
    assert payload["total"] == 0


def test_wasm_callers_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_callers(src, function=0)
    assert excinfo.value.code == "invalid_params"


def test_wasm_callers_truncated_section_is_marked(tmp_path: Path) -> None:
    body = _func_body(_call(1))
    section = _section(10, _uleb(2) + _uleb(len(body)) + body)  # claims two
    src = _write(tmp_path, _module(section))

    payload = parse_wasm_callers(src, function=1)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["callers"][0]["index"] == 0


def test_wasm_callers_paginates(tmp_path: Path) -> None:
    bodies = [_func_body(_call(99)) for _ in range(5)]
    src = _write(tmp_path, _module(_code_section(*bodies)))

    payload = parse_wasm_callers(src, function=99, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["index"] for r in payload["callers"]] == [2, 3]


def test_wasm_callers_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_CALLERS_COLLECT", 3
    )
    bodies = [_func_body(_call(7)) for _ in range(10)]
    src = _write(tmp_path, _module(_code_section(*bodies)))

    payload = parse_wasm_callers(src, function=7)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_callers_clamps_oversized_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_CALLERS_PAGE", 2
    )
    bodies = [_func_body(_call(7)) for _ in range(5)]
    src = _write(tmp_path, _module(_code_section(*bodies)))

    payload = parse_wasm_callers(src, function=7, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_callers_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_callers(tmp_path / "nope.wasm", function=0)
    assert excinfo.value.code == "not_found"


def test_wasm_callers_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_code_section(_func_body(_call(0)))))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_callers(src, function=0)
    assert excinfo.value.code == "too_large"


def test_wasm_callers_docstring_names_shape() -> None:
    doc = parse_wasm_callers.__doc__ or ""
    assert "wabt-free" in doc
    assert "xrefs" in doc
    assert "undecoded_bodies" in doc

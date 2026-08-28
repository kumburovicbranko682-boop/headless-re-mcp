"""Unit tests for wasm.locals (pure-Python local-declaration decoder).

Hand-crafted code sections carry local vectors of known (count, valtype) groups
so the by_type map and totals are pinned, the module-wide index accounts for
imported functions, a declaration that runs past the body is reported as
undecoded (with the groups read so far kept), and the no-code-section, non-wasm
and missing-file guards behave. The valtype byte is read one byte each, matching
the wasm.calls walker, so an unknown byte falls into an 0x.. bucket.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_locals

_PREAMBLE = b"\x00asm\x01\x00\x00\x00"

_I32, _I64, _F32, _F64, _V128 = 0x7F, 0x7E, 0x7D, 0x7C, 0x7B


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


def _locals(*groups: tuple[int, int]) -> bytes:
    """Encode a locals vector: count then valtype byte per (count, valtype)."""
    return _uleb(len(groups)) + b"".join(_uleb(c) + bytes([vt]) for c, vt in groups)


def _body(decls: bytes, instrs: bytes = b"") -> bytes:
    return decls + instrs + b"\x0b"  # closing end opcode


def _code_section(*bodies: bytes) -> bytes:
    joined = b"".join(_uleb(len(b)) + b for b in bodies)
    return _section(10, _uleb(len(bodies)) + joined)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _func_import(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _import_section(*entries: bytes) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes) -> Path:
    target = tmp_path / "mod.wasm"
    target.write_bytes(data)
    return target


def test_by_type_and_totals(tmp_path: Path) -> None:
    body0 = _body(_locals((3, _I32), (1, _I64)))
    body1 = _body(_locals((2, _V128), (4, _F32)))
    payload = parse_wasm_locals(_write(tmp_path, _module(_code_section(body0, body1))))
    assert payload["has_code_section"] is True
    assert payload["total"] == 2
    rows = {row["index"]: row for row in payload["functions"]}
    assert rows[0]["locals"] == 4
    assert rows[0]["by_type"] == {"i32": 3, "i64": 1}
    assert rows[0]["decoded"] is True
    assert rows[1]["locals"] == 6
    assert rows[1]["by_type"] == {"v128": 2, "f32": 4}


def test_no_locals_declared(tmp_path: Path) -> None:
    payload = parse_wasm_locals(_write(tmp_path, _module(_code_section(_body(_locals())))))
    row = payload["functions"][0]
    assert row["locals"] == 0
    assert row["by_type"] == {}
    assert row["decoded"] is True


def test_same_type_groups_accumulate(tmp_path: Path) -> None:
    body = _body(_locals((2, _I32), (3, _I32), (1, _F64)))
    payload = parse_wasm_locals(_write(tmp_path, _module(_code_section(body))))
    assert payload["functions"][0]["by_type"] == {"i32": 5, "f64": 1}
    assert payload["functions"][0]["locals"] == 6


def test_index_accounts_for_imported_functions(tmp_path: Path) -> None:
    module = _module(
        _import_section(_func_import("env", "a"), _func_import("env", "b")),
        _code_section(_body(_locals((1, _I32)))),
    )
    payload = parse_wasm_locals(_write(tmp_path, module))
    assert payload["imported_count"] == 2
    # Two imports occupy indices 0 and 1, so the first defined body is index 2.
    assert payload["functions"][0]["index"] == 2


def test_unknown_valtype_falls_into_hex_bucket(tmp_path: Path) -> None:
    # 0x63 is a GC ref-type prefix the single-byte read cannot name.
    body = _body(_locals((1, 0x63)))
    payload = parse_wasm_locals(_write(tmp_path, _module(_code_section(body))))
    assert payload["functions"][0]["by_type"] == {"0x63": 1}


def test_declaration_past_body_is_undecoded(tmp_path: Path) -> None:
    # Claim two groups but supply only one, so the second read runs off the end.
    truncated_decls = _uleb(2) + _uleb(1) + bytes([_I32])
    body = truncated_decls + b"\x0b"
    payload = parse_wasm_locals(_write(tmp_path, _module(_code_section(body))))
    row = payload["functions"][0]
    assert row["decoded"] is False
    # The first group read before the overrun is kept.
    assert row["by_type"] == {"i32": 1}


def test_no_code_section(tmp_path: Path) -> None:
    payload = parse_wasm_locals(_write(tmp_path, _module(_section(1, _uleb(0)))))
    assert payload["has_code_section"] is False
    assert payload["functions"] == []
    assert payload["total"] == 0


def test_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_WASM_LOCALS_COLLECT", 2)
    bodies = [_body(_locals((1, _I32))) for _ in range(5)]
    payload = parse_wasm_locals(_write(tmp_path, _module(_code_section(*bodies))))
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


def test_page_window_and_has_more(tmp_path: Path) -> None:
    bodies = [_body(_locals((1, _I32))) for _ in range(15)]
    module = _write(tmp_path, _module(_code_section(*bodies)))
    first = parse_wasm_locals(module, offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 15
    assert first["has_more"] is True
    tail = parse_wasm_locals(module, offset=10, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def test_not_a_wasm_module_is_invalid_params(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_locals(_write(tmp_path, b"definitely not wasm"))
    assert info.value.code == "invalid_params"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_locals(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"

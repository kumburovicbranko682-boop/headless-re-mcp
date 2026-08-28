"""Unit tests for wasm.opcodes (pure-Python instruction-mix histogram).

Hand-crafted code sections exercise the categoriser across every family --
numeric/variable/parametric/call/memory/simd on one pair of bodies, and
atomic/table plus the 0xFC bulk-memory and table prefixes on another -- so each
opcode lands in the right bucket, the trailing end counts as control, a body
that hits an opcode outside the walker's table still contributes its earlier
opcodes (decoded_functions < total_functions), and the aggregate does not page.
The immediate layout is shared with wasm.calls, so alignment is assumed and the
focus here is classification and the aggregate envelope.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_opcodes

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
    return _uleb(0) + instrs + b"\x0b"  # no locals; body-closing end opcode


def _code_section(*bodies: bytes) -> bytes:
    joined = b"".join(_uleb(len(body)) + body for body in bodies)
    return _section(10, _uleb(len(bodies)) + joined)


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def _cats(payload: dict) -> dict[str, int]:
    return {row["category"]: row["count"] for row in payload["categories"]}


# i32.const 1, i32.const 2, i32.add, local.get 0, drop, call 0
_BODY_A = _func_body(b"\x41\x01\x41\x02\x6a\x20\x00\x1a\x10\x00")
# i32.const 0, i32.load a=2 o=0, drop, an immediate-free SIMD op (sub 78)
_BODY_B = _func_body(b"\x41\x00\x28\x02\x00\x1a\xfd\x4e")


def test_categories_totals_and_sort(tmp_path: Path) -> None:
    payload = parse_wasm_opcodes(_write(tmp_path, _module(_code_section(_BODY_A, _BODY_B))))
    assert payload["has_code_section"] is True
    assert payload["total_functions"] == 2
    assert payload["decoded_functions"] == 2
    assert payload["instruction_count"] == 12
    assert payload["scan_capped"] is False
    assert payload["truncated"] is False
    assert _cats(payload) == {
        "numeric": 4,
        "control": 2,
        "parametric": 2,
        "call": 1,
        "memory": 1,
        "simd": 1,
        "variable": 1,
    }
    # Sorted by count desc, ties broken by name asc.
    assert [(r["category"], r["count"]) for r in payload["categories"]] == [
        ("numeric", 4),
        ("control", 2),
        ("parametric", 2),
        ("call", 1),
        ("memory", 1),
        ("simd", 1),
        ("variable", 1),
    ]


def test_atomic_table_and_misc_prefixes(tmp_path: Path) -> None:
    # i32.atomic.load (0xFE 16, memarg), memory.fill (0xFC 11), table.size (0xFC 16)
    body = _func_body(b"\xfe\x10\x02\x00\xfc\x0b\x00\xfc\x10\x00")
    payload = parse_wasm_opcodes(_write(tmp_path, _module(_code_section(body))))
    assert _cats(payload) == {"atomic": 1, "memory": 1, "table": 1, "control": 1}
    assert payload["decoded_functions"] == 1
    assert payload["instruction_count"] == 4


def test_call_indirect_table_and_reference(tmp_path: Path) -> None:
    # call_indirect t0 tbl0, table.get 0, ref.func 0, ref.is_null, drop
    body = _func_body(b"\x11\x00\x00\x25\x00\xd2\x00\xd1\x1a")
    payload = parse_wasm_opcodes(_write(tmp_path, _module(_code_section(body))))
    assert _cats(payload) == {
        "call_indirect": 1,
        "table": 1,
        "reference": 2,
        "parametric": 1,
        "control": 1,
    }


def test_undecoded_body_keeps_partial_tally(tmp_path: Path) -> None:
    # i32.const 1 then 0xFB (GC prefix, outside the walker's table) abandons here.
    body = _func_body(b"\x41\x01\xfb\x00")
    payload = parse_wasm_opcodes(_write(tmp_path, _module(_code_section(body))))
    assert payload["total_functions"] == 1
    assert payload["decoded_functions"] == 0
    # The numeric const before the unknown opcode is kept; the trailing end,
    # never reached, is not.
    assert _cats(payload) == {"numeric": 1}
    assert payload["instruction_count"] == 1
    # A body-level abandon is not a malformed section.
    assert payload["truncated"] is False


def test_no_code_section(tmp_path: Path) -> None:
    payload = parse_wasm_opcodes(_write(tmp_path, _module(_section(1, _uleb(0)))))
    assert payload["has_code_section"] is False
    assert payload["categories"] == []
    assert payload["total_functions"] == 0
    assert payload["decoded_functions"] == 0
    assert payload["instruction_count"] == 0


def test_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_WASM_OPCODES_FUNCS", 2)
    bodies = [_func_body(b"") for _ in range(5)]
    payload = parse_wasm_opcodes(_write(tmp_path, _module(_code_section(*bodies))))
    assert payload["total_functions"] == 2
    assert payload["scan_capped"] is True


def test_not_a_wasm_module_is_invalid_params(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_opcodes(_write(tmp_path, b"not wasm at all"))
    assert info.value.code == "invalid_params"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_opcodes(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"

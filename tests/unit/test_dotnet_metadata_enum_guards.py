"""Pure parsers of the ECMA-335 metadata enumerator, fed synthetic contexts.

``test_dotnet_metadata_enum.py`` and ``test_dotnet_il_truncation_honesty.py``
drive the enumerator through whole assemblies; the helpers underneath -- page
clamping, the ``#Strings`` walk, the per-table row readers, the small IL opcode
disassembler, and the index/row-size arithmetic -- are exercised here directly on
a hand-built ``_MetaCtx`` and crafted byte strings. That keeps the table geometry
under test (a TypeDef/MethodDef/Field/ManifestResource/MemberRef row read at the
right offset) and the IL honesty branches (a signed branch target, an unknown
opcode, a truncated operand, a two-byte prefix, the instruction cap) without
needing a real .NET binary for each case.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.metadata_enum import (
    DotnetInspectError,
    _clamp_page,
    _disassemble_il,
    _iter_fields,
    _iter_memberrefs,
    _iter_methoddefs,
    _iter_resources,
    _iter_strings_heap,
    _iter_typedefs,
    _MetaCtx,
    _read_index,
    _rows_the_stream_can_hold,
    _string_at,
    _table_row_size,
    enumerate_metadata,
)


def _ctx(
    *,
    tables: bytes = b"",
    strings: bytes = b"",
    row_counts: dict[int, int] | None = None,
) -> _MetaCtx:
    return _MetaCtx(
        path=Path("synthetic"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=tables,
        strings=strings,
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts=row_counts or {},
        table_data_offset=0,
    )


# ---------------------------------------------------------------------------
# page clamping and kind validation
# ---------------------------------------------------------------------------
def test_clamp_page_rejects_negatives_and_caps_the_limit() -> None:
    with pytest.raises(DotnetInspectError):
        _clamp_page(-1, 5)
    with pytest.raises(DotnetInspectError):
        _clamp_page(0, 0)
    assert _clamp_page(3, 10) == (3, 10)
    assert _clamp_page(0, 100000)[1] == 256  # MAX_LIMIT


def test_enumerate_metadata_rejects_an_unknown_kind_before_touching_the_file() -> None:
    # The kind check runs before inspect_dotnet, so a bogus kind is refused
    # without the path ever being opened.
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata("/no/such/assembly.dll", "widgets")
    assert caught.value.code == "invalid_argument"


# ---------------------------------------------------------------------------
# string heap and small index helpers
# ---------------------------------------------------------------------------
def test_string_at_reads_names_and_reports_out_of_range_as_null() -> None:
    ctx = _ctx(strings=b"\x00Hello\x00")
    assert _string_at(ctx, 1) == "Hello"
    assert _string_at(ctx, 0) is None
    assert _string_at(ctx, 999) is None
    # A heap with no trailing null still yields the tail rather than raising.
    assert _string_at(_ctx(strings=b"\x00Hi"), 1) == "Hi"


def test_read_index_handles_two_and_four_byte_widths() -> None:
    assert _read_index(b"\x01\x02\x03\x04", 0, 2) == (0x0201, 2)
    assert _read_index(b"\x01\x02\x03\x04", 0, 4) == (0x04030201, 4)


def test_iter_strings_heap_skips_empty_entries_and_tolerates_no_terminator() -> None:
    entries = list(_iter_strings_heap(_ctx(strings=b"\x00abc\x00\x00de\x00")))
    assert [(e["index"], e["value"]) for e in entries] == [(1, "abc"), (6, "de")]
    # An empty heap yields nothing.
    assert list(_iter_strings_heap(_ctx(strings=b""))) == []
    # A final run with no terminator is still surfaced.
    tail = list(_iter_strings_heap(_ctx(strings=b"\x00xyz")))
    assert tail == [{"index": 1, "value": "xyz"}]


# ---------------------------------------------------------------------------
# per-table row readers
# ---------------------------------------------------------------------------
def test_iter_typedefs_reads_name_and_namespace() -> None:
    row = bytearray(14)
    struct.pack_into("<H", row, 4, 1)  # Name -> #Strings index 1
    struct.pack_into("<H", row, 6, 8)  # Namespace -> #Strings index 8
    ctx = _ctx(tables=bytes(row), strings=b"\x00MyType\x00NS\x00", row_counts={0x02: 1})
    items = list(_iter_typedefs(ctx))
    assert items == [
        {"token": 0x02000001, "rid": 1, "name": "MyType", "namespace": "NS"}
    ]


def test_iter_methoddefs_reads_rva_and_name() -> None:
    row = bytearray(14)
    struct.pack_into("<I", row, 0, 0x2050)  # RVA
    struct.pack_into("<H", row, 8, 1)  # Name -> #Strings index 1
    ctx = _ctx(tables=bytes(row), strings=b"\x00Main\x00", row_counts={0x06: 1})
    items = list(_iter_methoddefs(ctx))
    assert items == [{"token": 0x06000001, "rid": 1, "name": "Main", "rva": 0x2050}]


def test_iter_fields_reads_name() -> None:
    row = bytearray(6)
    struct.pack_into("<H", row, 2, 1)  # Name index
    ctx = _ctx(tables=bytes(row), strings=b"\x00value\x00", row_counts={0x04: 1})
    assert list(_iter_fields(ctx)) == [{"token": 0x04000001, "rid": 1, "name": "value"}]


def test_iter_resources_reads_offset_flags_and_name() -> None:
    row = bytearray(12)
    struct.pack_into("<I", row, 0, 0x40)  # Offset
    struct.pack_into("<I", row, 4, 0x1)  # Flags (public)
    struct.pack_into("<H", row, 8, 1)  # Name index
    ctx = _ctx(tables=bytes(row), strings=b"\x00res\x00", row_counts={0x28: 1})
    assert list(_iter_resources(ctx)) == [
        {"token": 0x28000001, "rid": 1, "name": "res", "offset": 0x40, "flags": 0x1}
    ]


def test_iter_memberrefs_reads_class_index_and_name() -> None:
    row = bytearray(6)
    struct.pack_into("<H", row, 0, 5)  # class coded index
    struct.pack_into("<H", row, 2, 1)  # Name index
    ctx = _ctx(tables=bytes(row), strings=b"\x00ToString\x00", row_counts={0x0A: 1})
    items = list(_iter_memberrefs(ctx))
    assert items[0]["name"] == "ToString"
    assert items[0]["class_coded_index"] == 5
    assert items[0]["token"] == 0x0A000001


# ---------------------------------------------------------------------------
# row-size arithmetic
# ---------------------------------------------------------------------------
def test_table_row_size_refuses_an_unknown_table() -> None:
    with pytest.raises(DotnetInspectError) as caught:
        _table_row_size(_ctx(), 0x30)
    assert caught.value.code == "unsupported_metadata"


def test_rows_the_stream_can_hold_is_bounded_by_the_stream() -> None:
    ctx = _ctx(tables=b"0123456789")
    assert _rows_the_stream_can_hold(ctx, 0, 4) == 2  # 10 // 4
    assert _rows_the_stream_can_hold(ctx, 100, 4) == 0  # offset past the stream
    assert _rows_the_stream_can_hold(ctx, 0, 0) == 0  # a zero-width row


# ---------------------------------------------------------------------------
# IL opcode disassembler
# ---------------------------------------------------------------------------
def test_disassemble_il_reads_operandless_opcodes() -> None:
    insns, partial = _disassemble_il(bytes([0x00, 0x2A]), max_insns=16)
    assert partial is False
    assert [i["mnemonic"] for i in insns] == ["nop", "ret"]
    assert all(i["operand"] is None for i in insns)


def test_disassemble_il_marks_an_unknown_opcode() -> None:
    insns, partial = _disassemble_il(bytes([0xEE]), max_insns=16)
    assert insns == [{"ip": 0, "mnemonic": "op_ee", "operand": None}]
    assert partial is False


def test_disassemble_il_reads_signed_branch_and_constant_operands() -> None:
    short_branch, _ = _disassemble_il(bytes([0x2B, 0xF6]), max_insns=16)  # br.s -10
    assert short_branch[0]["mnemonic"] == "br.s"
    assert short_branch[0]["operand"] == -10

    ldc = _disassemble_il(bytes([0x20]) + (-10).to_bytes(4, "little", signed=True), max_insns=16)
    assert ldc[0][0]["mnemonic"] == "ldc.i4"
    assert ldc[0][0]["operand"] == -10


def test_disassemble_il_reads_an_unsigned_call_token() -> None:
    il = bytes([0x28]) + (0x0A000001).to_bytes(4, "little")
    insns, _ = _disassemble_il(il, max_insns=16)
    assert insns[0]["mnemonic"] == "call"
    assert insns[0]["operand"] == 0x0A000001


def test_disassemble_il_flags_a_truncated_operand() -> None:
    insns, partial = _disassemble_il(bytes([0x28, 0x01]), max_insns=16)  # call wants 4
    assert partial is True
    assert insns == []


def test_disassemble_il_marks_a_two_byte_prefix() -> None:
    insns, partial = _disassemble_il(bytes([0xFE]), max_insns=16)
    assert partial is True
    assert insns[0]["mnemonic"] == "prefix.fe"


def test_disassemble_il_stops_at_the_instruction_cap() -> None:
    insns, partial = _disassemble_il(bytes([0x00] * 5), max_insns=2)
    assert len(insns) == 2
    assert partial is True

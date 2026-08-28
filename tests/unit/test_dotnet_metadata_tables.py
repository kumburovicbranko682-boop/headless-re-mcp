"""Metadata enumeration over a synthetic assembly with real #~ tables.

test_dotnet_metadata_enum pins the empty-tables shell and signed operands;
these build a CLR image whose #~ stream actually holds TypeDef, Field,
MethodDef, MemberRef and ManifestResource rows plus tiny and fat method
bodies, so the row walkers, the IL reader and the guard paths all run
against bytes shaped like a real assembly rather than an empty stream.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.metadata_enum import (
    _disassemble_il,
    _iter_strings_heap,
    _load_metadata_context,
    _read_index,
    _read_method_body,
    _rows_the_stream_can_hold,
    _string_at,
    _table_row_size,
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)

_TINY_RVA = 0x1E00
_FAT_RVA = 0x1F00
_TINY_FILE = 0x1200
_FAT_FILE = 0x1300
_META_FILE = 0x600
_CALL_TOKEN = 0x0A000001


def _pad4(blob: bytes) -> bytes:
    return blob + b"\0" * ((4 - len(blob) % 4) % 4)


def _strings_heap() -> tuple[bytes, dict[str, int]]:
    heap = bytearray(b"\0")
    index: dict[str, int] = {}
    for name in ("Widget", "Acme", "Run", "Fat", "Stop", "counter", "WriteLine", "res.bin"):
        index[name] = len(heap)
        heap += name.encode("ascii") + b"\0"
    return bytes(heap), index


def _tables_stream(index: dict[str, int]) -> bytes:
    header = struct.pack("<IBBBB", 0, 2, 0, 0, 1)
    valid = (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0A) | (1 << 0x28)
    header += struct.pack("<QQ", valid, 0)
    header += struct.pack("<IIIII", 1, 1, 3, 1, 1)
    rows = struct.pack("<IHHHHH", 0x100000, index["Widget"], index["Acme"], 0, 1, 1)
    rows += struct.pack("<HHH", 0x16, index["counter"], 0)
    rows += struct.pack("<IHHHHH", _TINY_RVA, 0, 0, index["Run"], 0, 1)
    rows += struct.pack("<IHHHHH", _FAT_RVA, 0, 0, index["Fat"], 0, 1)
    rows += struct.pack("<IHHHHH", 0, 0, 0, index["Stop"], 0, 1)
    rows += struct.pack("<HHH", 9, index["WriteLine"], 0)
    rows += struct.pack("<IIHH", 0, 1, index["res.bin"], 0)
    return header + rows


def _metadata_blob(streams: list[tuple[bytes, bytes]]) -> bytes:
    version = b"v4.0.30319\0"
    version_padded = _pad4(version)
    header_size = 16 + len(version_padded) + 4
    for name, _payload in streams:
        header_size += 8 + len(_pad4(name + b"\0"))
    blob = b"BSJB" + struct.pack("<HHI", 1, 1, 0)
    blob += struct.pack("<I", len(version)) + version_padded
    blob += struct.pack("<HH", 0, len(streams))
    cursor = header_size
    for name, payload in streams:
        blob += struct.pack("<II", cursor, len(payload)) + _pad4(name + b"\0")
        cursor += len(payload)
    for _name, payload in streams:
        blob += payload
    return blob


def _rich_metadata() -> bytes:
    heap, index = _strings_heap()
    return _metadata_blob([(b"#~", _tables_stream(index)), (b"#Strings", heap)])


def _write_clr(path: Path, meta_blob: bytes) -> None:
    image = bytearray(0x1600)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x400)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1200, 0x1000, 0x1200, 0x400)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    # COM descriptor at RVA 0x1100 -> file 0x500.
    cor_off = 0x500
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(meta_blob))
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    image[_META_FILE : _META_FILE + len(meta_blob)] = meta_blob
    # Tiny body: nop, call <MemberRef 1>, ret. Header byte = (7 << 2) | 0x02.
    tiny = bytes([0x00, 0x28]) + _CALL_TOKEN.to_bytes(4, "little") + bytes([0x2A])
    image[_TINY_FILE] = (len(tiny) << 2) | 0x02
    image[_TINY_FILE + 1 : _TINY_FILE + 1 + len(tiny)] = tiny
    # Fat body: 12-byte header (low bits of flags = 0x3), then ldc.i4.0, ret.
    struct.pack_into("<HHII", image, _FAT_FILE, 0x3013, 8, 2, 0)
    image[_FAT_FILE + 12 : _FAT_FILE + 14] = bytes([0x16, 0x2A])
    path.write_bytes(bytes(image))


@pytest.fixture()
def rich_assembly(tmp_path: Path) -> Path:
    binary = tmp_path / "rich.dll"
    _write_clr(binary, _rich_metadata())
    return binary


def test_page_guards_refuse_bad_offsets_limits_and_kinds(tmp_path: Path) -> None:
    missing = tmp_path / "never-read.dll"
    with pytest.raises(DotnetInspectError) as info:
        enumerate_metadata(missing, "types", offset=-1)
    assert info.value.code == "invalid_argument"
    with pytest.raises(DotnetInspectError) as info:
        enumerate_metadata(missing, "types", limit=0)
    assert info.value.code == "invalid_argument"
    with pytest.raises(DotnetInspectError) as info:
        enumerate_metadata(missing, "widgets")
    assert info.value.code == "invalid_argument"


def test_enumerate_walks_every_table_kind(rich_assembly: Path) -> None:
    types = enumerate_metadata(rich_assembly, "types")
    assert [item["name"] for item in types.items] == ["Widget"]
    assert types.items[0]["namespace"] == "Acme"
    assert types.items[0]["token"] == 0x02000001

    methods = enumerate_metadata(rich_assembly, "methods")
    assert [item["name"] for item in methods.items] == ["Run", "Fat", "Stop"]
    assert [item["rva"] for item in methods.items] == [_TINY_RVA, _FAT_RVA, 0]

    fields = enumerate_metadata(rich_assembly, "fields")
    assert [item["name"] for item in fields.items] == ["counter"]
    assert fields.items[0]["token"] == 0x04000001

    resources = enumerate_metadata(rich_assembly, "resources")
    assert [item["name"] for item in resources.items] == ["res.bin"]
    assert resources.items[0]["flags"] == 1

    strings = enumerate_metadata(rich_assembly, "strings")
    assert {item["value"] for item in strings.items} >= {"Widget", "Acme", "WriteLine"}


def test_memberref_xrefs_list_the_referenced_names(rich_assembly: Path) -> None:
    page = list_memberref_xrefs(rich_assembly)
    assert page.total == 1
    assert page.items[0]["name"] == "WriteLine"
    assert page.items[0]["token"] == _CALL_TOKEN
    assert page.items[0]["class_coded_index"] == 9


def test_disassemble_guards_name_the_bad_token(rich_assembly: Path) -> None:
    with pytest.raises(DotnetInspectError) as info:
        disassemble_method_il(rich_assembly, 0x02000001)
    assert info.value.code == "invalid_argument"
    with pytest.raises(DotnetInspectError) as info:
        disassemble_method_il(rich_assembly, 0x06000000)
    assert info.value.code == "invalid_argument"
    with pytest.raises(DotnetInspectError) as info:
        disassemble_method_il(rich_assembly, 0x06000063)
    assert info.value.code == "not_found"


def test_disassemble_reports_a_method_without_a_body(rich_assembly: Path) -> None:
    result = disassemble_method_il(rich_assembly, 0x06000003)
    assert result["instructions"] == []
    assert result["partial"] is False
    assert result["reason"] == "abstract_or_runtime_managed_no_rva"


def test_disassemble_reads_tiny_and_fat_bodies(rich_assembly: Path) -> None:
    tiny = disassemble_method_il(rich_assembly, 0x06000001)
    assert tiny["header"] == {"format": "tiny", "code_size": 7}
    assert [insn["mnemonic"] for insn in tiny["instructions"]] == ["nop", "call", "ret"]
    assert tiny["call_tokens"] == [_CALL_TOKEN]
    assert tiny["partial"] is False

    fat = disassemble_method_il(rich_assembly, 0x06000002)
    assert fat["header"]["format"] == "fat"
    assert fat["header"]["code_size"] == 2
    assert fat["header"]["max_stack"] == 8
    assert [insn["mnemonic"] for insn in fat["instructions"]] == ["ldc.i4.0", "ret"]


def test_method_body_reader_names_unreadable_rvas(rich_assembly: Path) -> None:
    meta = _load_metadata_context(rich_assembly)
    with pytest.raises(DotnetInspectError) as info:
        _read_method_body(meta, 0x9000, max_bytes=64)
    assert info.value.code == "not_found"

    cut = _load_metadata_context(rich_assembly)
    cut.pe_data = cut.pe_data[:0x1000]
    with pytest.raises(DotnetInspectError) as info:
        _read_method_body(cut, _TINY_RVA, max_bytes=64)
    assert "out of file" in str(info.value)

    torn = _load_metadata_context(rich_assembly)
    torn.pe_data = torn.pe_data[: _FAT_FILE + 5]
    with pytest.raises(DotnetInspectError) as info:
        _read_method_body(torn, _FAT_RVA, max_bytes=64)
    assert "fat method header truncated" in str(info.value)


def test_metadata_context_names_each_malformed_header(tmp_path: Path) -> None:
    heap, index = _strings_heap()

    not_bsjb = tmp_path / "not-bsjb.dll"
    _write_clr(not_bsjb, b"XXXX" + _rich_metadata()[4:])
    with pytest.raises(DotnetInspectError) as info:
        _load_metadata_context(not_bsjb)
    assert "not BSJB" in str(info.value)

    empty_meta = tmp_path / "meta-zero.dll"
    _write_clr(empty_meta, _rich_metadata())
    image = bytearray(empty_meta.read_bytes())
    struct.pack_into("<II", image, 0x500 + 8, 0, 0)
    empty_meta.write_bytes(bytes(image))
    with pytest.raises(DotnetInspectError) as info:
        _load_metadata_context(empty_meta)
    assert "metadata directory empty" in str(info.value)

    no_com = tmp_path / "no-com.dll"
    _write_clr(no_com, _rich_metadata())
    image = bytearray(no_com.read_bytes())
    dir_base = 0x80 + 4 + 20 + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0, 0)
    no_com.write_bytes(bytes(image))
    with pytest.raises(DotnetInspectError) as info:
        _load_metadata_context(no_com)
    assert "missing COM descriptor" in str(info.value)

    huge_version = tmp_path / "huge-version.dll"
    blob = bytearray(_rich_metadata())
    struct.pack_into("<I", blob, 12, 0x0FFF)
    _write_clr(huge_version, bytes(blob))
    with pytest.raises(DotnetInspectError) as info:
        _load_metadata_context(huge_version)
    assert "streams truncated" in str(info.value)

    del index, heap


def test_metadata_context_survives_hostile_stream_headers(tmp_path: Path) -> None:
    """A stream count larger than the header area and a stream name with no
    terminator both end the walk instead of running off the blob."""
    overrun = tmp_path / "stream-overrun.dll"
    blob = bytearray(_rich_metadata())
    count_at = 16 + len(_pad4(b"v4.0.30319\0")) + 2
    struct.pack_into("<H", blob, count_at, 500)
    _write_clr(overrun, bytes(blob))
    meta = _load_metadata_context(overrun)
    # The genuine #~ stream parsed before the walk ran out of header bytes.
    assert list(enumerate_metadata(overrun, "types").items) != [] or meta.tables != b""

    unterminated = tmp_path / "unterminated-name.dll"
    version = b"v4.0.30319\0"
    padded = _pad4(version)
    blob2 = b"BSJB" + struct.pack("<HHI", 1, 1, 0)
    blob2 += struct.pack("<I", len(version)) + padded
    blob2 += struct.pack("<HH", 0, 1)
    blob2 += struct.pack("<II", 0, 0) + b"A" * 16
    _write_clr(unterminated, blob2)
    meta = _load_metadata_context(unterminated)
    assert meta.tables == b""
    assert meta.row_counts == {}


def test_metadata_context_tolerates_short_tables_streams(tmp_path: Path) -> None:
    heap, _index = _strings_heap()

    stub = tmp_path / "short-tables.dll"
    _write_clr(stub, _metadata_blob([(b"#~", b"\0" * 8), (b"#Strings", heap)]))
    meta = _load_metadata_context(stub)
    assert meta.row_counts == {}
    assert enumerate_metadata(stub, "types").total == 0

    torn_counts = tmp_path / "torn-counts.dll"
    tables = struct.pack("<IBBBB", 0, 2, 0, 0, 1) + struct.pack("<QQ", 0b111, 0)
    tables += struct.pack("<I", 1)  # one row count present, two more claimed
    _write_clr(torn_counts, _metadata_blob([(b"#~", tables), (b"#Strings", heap)]))
    meta = _load_metadata_context(torn_counts)
    assert meta.row_counts == {0: 1}


def test_string_and_index_helpers_handle_edges(rich_assembly: Path) -> None:
    meta = _load_metadata_context(rich_assembly)
    assert _string_at(meta, 0) is None
    assert _string_at(meta, 10**6) is None
    unterminated = _load_metadata_context(rich_assembly)
    unterminated.strings = b"\0abc"
    assert _string_at(unterminated, 1) == "abc"

    assert _read_index(b"\x01\x02\x03\x04", 0, 4) == (0x04030201, 4)
    assert _read_index(b"\x01\x02\x03\x04", 0, 2) == (0x0201, 2)

    with pytest.raises(DotnetInspectError) as info:
        _table_row_size(meta, 0x2D)
    assert info.value.code == "unsupported_metadata"

    assert _rows_the_stream_can_hold(meta, 10**9, 14) == 0
    assert _rows_the_stream_can_hold(meta, 0, 0) == 0


def test_strings_heap_iteration_is_capped(rich_assembly: Path) -> None:
    meta = _load_metadata_context(rich_assembly)
    meta.strings = b"\0" + b"s\0" * 10_050
    items = list(_iter_strings_heap(meta))
    assert len(items) == 10_000
    assert items[0] == {"index": 1, "value": "s"}

    # Consecutive NULs yield nothing; an unterminated tail still comes back.
    meta.strings = b"\0\0tail"
    assert list(_iter_strings_heap(meta)) == [{"index": 2, "value": "tail"}]


def test_method_body_short_of_its_declared_size_is_partial(rich_assembly: Path) -> None:
    """code_size is a number out of the sample; a body cut off at EOF must
    answer partial instead of posing as a complete disassembly."""
    short = _load_metadata_context(rich_assembly)
    short.pe_data = short.pe_data[: _FAT_FILE + 13]
    body = _read_method_body(short, _FAT_RVA, max_bytes=64)
    assert body["truncated"] is True
    assert len(body["il"]) < body["il_len"]


def test_il_disassembly_names_prefixes_unknowns_and_cuts() -> None:
    instructions, partial = _disassemble_il(bytes([0xFE, 0x01, 0x2A]), max_insns=16)
    assert instructions[0]["mnemonic"] == "prefix.fe"
    assert partial is True

    instructions, partial = _disassemble_il(bytes([0x01, 0x2A]), max_insns=16)
    assert instructions[0]["mnemonic"] == "op_01"
    assert partial is False

    instructions, partial = _disassemble_il(bytes([0x28, 0x01, 0x02]), max_insns=16)
    assert [insn["mnemonic"] for insn in instructions] == []
    assert partial is True

    instructions, partial = _disassemble_il(bytes([0x00] * 5), max_insns=2)
    assert len(instructions) == 2
    assert partial is True

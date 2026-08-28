"""Table-walking arms of the bounded ECMA-335 metadata enumerator.

The suite already pins the empty-tables path and the signed-operand IL rule,
but the actual parser -- table sizing, the five row iterators, method-body
reading and the opcode subset -- was only reachable with a real managed
assembly the CI has no copy of. This builds a synthetic .NET PE whose ``#~``
tables stream and ``#Strings`` heap carry a handful of Module/TypeDef/Field/
MethodDef/MemberRef/ManifestResource rows (plus an abstract and a fat-header
method), then drives every listing, the IL disassembler and the error arms
directly against it.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet import metadata_enum
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.metadata_enum import (
    _clamp_page,
    _coded_index_size,
    _disassemble_il,
    _load_metadata_context,
    _MetaCtx,
    _read_index,
    _simple_index_size,
    _string_at,
    _table_row_size,
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)

_STRINGS = b"\x00MyType\x00MyNamespace\x00MyField\x00MyMethod\x00MyMember\x00MyResource\x00"
_TINY_RVA = 0x1400
_FAT_RVA = 0x1500


def _sidx(name: bytes) -> int:
    return _STRINGS.index(name)


def _pack_blob(order: list[str], names: dict[str, bytes]) -> bytes:
    version = b"v4.0.30319\x00"
    version_padded = version + b"\x00" * ((4 - len(version) % 4) % 4)
    blob = bytearray()
    blob += b"BSJB"
    blob += struct.pack("<HH", 1, 1)
    blob += struct.pack("<I", 0)
    blob += struct.pack("<I", len(version))
    blob += version_padded
    blob += struct.pack("<HH", 0, len(order))

    def name_bytes(name: str) -> bytes:
        raw = name.encode() + b"\x00"
        return raw + b"\x00" * ((4 - len(raw) % 4) % 4)

    hdr_len = sum(8 + len(name_bytes(n)) for n in order)
    cur = len(blob) + hdr_len
    offsets: dict[str, int] = {}
    for n in order:
        offsets[n] = cur
        cur += len(names[n])
    for n in order:
        blob += struct.pack("<II", offsets[n], len(names[n]))
        blob += name_bytes(n)
    for n in order:
        blob += names[n]
    return bytes(blob)


def _metadata_blob(method_rvas: tuple[int, ...] = (_TINY_RVA, 0, _FAT_RVA)) -> bytes:
    valid = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 0x0A) | (1 << 0x28)
    header = bytearray()
    header += b"\x00\x00\x00\x00"  # reserved
    header += bytes([2, 0])  # major, minor
    header += bytes([0x00])  # heap sizes -> all 2-byte indexes
    header += bytes([0x01])  # reserved
    header += struct.pack("<Q", valid)
    header += struct.pack("<Q", 0)  # sorted
    # Module, TypeDef, Field, MethodDef, MemberRef, ManifestResource counts.
    for count in (1, 2, 2, len(method_rvas), 1, 1):
        header += struct.pack("<I", count)

    data = bytearray()
    data += struct.pack("<HHHHH", 0, 0, 0, 0, 0)  # Module
    for _ in range(2):  # TypeDef x2
        data += struct.pack("<IHHHHH", 0, _sidx(b"MyType"), _sidx(b"MyNamespace"), 0, 1, 1)
    for _ in range(2):  # Field x2
        data += struct.pack("<HHH", 0, _sidx(b"MyField"), 0)
    for rva in method_rvas:  # MethodDef rows: tiny body, abstract, fat body, ...
        data += struct.pack("<IHHHHH", rva, 0, 0, _sidx(b"MyMethod"), 0, 1)
    data += struct.pack("<HHH", 0, _sidx(b"MyMember"), 0)  # MemberRef
    data += struct.pack("<IIHH", 0x10, 1, _sidx(b"MyResource"), 0)  # ManifestResource
    tilde = bytes(header) + bytes(data)

    return _pack_blob(["#Strings", "#~"], {"#Strings": _STRINGS, "#~": tilde})


def _write_clr_with_tables(path: Path, metadata: bytes | None = None) -> None:
    image = bytearray(0x1400)
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
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    cor_off = 0x300
    metadata = metadata if metadata is not None else _metadata_blob()
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(metadata))
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)

    meta_off = 0x400
    image[meta_off : meta_off + len(metadata)] = metadata

    tiny_il = (
        bytes([0x00])
        + bytes([0x20])
        + (-1).to_bytes(4, "little", signed=True)  # ldc.i4 -1
        + bytes([0x28])
        + (0x0A000001).to_bytes(4, "little")  # call token
        + bytes([0x2A])  # ret
    )
    tiny_off = 0x600  # RVA 0x1400
    image[tiny_off] = (len(tiny_il) << 2) | 0x02
    image[tiny_off + 1 : tiny_off + 1 + len(tiny_il)] = tiny_il

    fat_il = bytes([0x00, 0x2A])  # nop; ret
    fat_off = 0x700  # RVA 0x1500
    struct.pack_into("<HHII", image, fat_off, 0x3003, 8, len(fat_il), 0)
    image[fat_off + 12 : fat_off + 12 + len(fat_il)] = fat_il

    path.write_bytes(image)


@pytest.fixture
def managed(tmp_path: Path) -> Path:
    path = tmp_path / "tables.dll"
    _write_clr_with_tables(path)
    return path


# --------------------------------------------------------------------------- #
# fixture-driven enumeration
# --------------------------------------------------------------------------- #


def test_enumerate_types(managed: Path) -> None:
    page = enumerate_metadata(managed, "types", require_verified=False)
    assert page.total == 2
    first = page.items[0]
    assert first["token"] == 0x02000001
    assert first["name"] == "MyType"
    assert first["namespace"] == "MyNamespace"


def test_enumerate_methods_fields_resources(managed: Path) -> None:
    methods = enumerate_metadata(managed, "methods", require_verified=False)
    assert methods.total == 3
    assert methods.items[0]["token"] == 0x06000001
    assert methods.items[0]["rva"] == _TINY_RVA

    fields = enumerate_metadata(managed, "fields", require_verified=False)
    assert fields.total == 2
    assert fields.items[0]["name"] == "MyField"

    resources = enumerate_metadata(managed, "resources", require_verified=False)
    assert resources.total == 1
    assert resources.items[0]["name"] == "MyResource"
    assert resources.items[0]["offset"] == 0x10
    assert resources.items[0]["flags"] == 1


def test_enumerate_strings(managed: Path) -> None:
    page = enumerate_metadata(managed, "strings", require_verified=False)
    values = [item["value"] for item in page.items]
    assert "MyType" in values
    assert "MyResource" in values
    assert page.total == 6


def test_enumerate_pagination_and_truncation(managed: Path) -> None:
    page = enumerate_metadata(managed, "methods", offset=1, limit=1, require_verified=False)
    assert page.offset == 1
    assert page.limit == 1
    assert len(page.items) == 1
    assert page.total == 3
    assert page.truncated is True
    payload = page.to_dict()
    assert payload["not_ida_idalib"] is True
    assert payload["claims_universal_unpack"] is False


def test_enumerate_kind_normalisation(managed: Path) -> None:
    page = enumerate_metadata(managed, "  TYPES  ", require_verified=False)
    assert page.kind == "types"


def test_list_memberref_xrefs(managed: Path) -> None:
    page = list_memberref_xrefs(managed, require_verified=False)
    assert page.kind == "xrefs"
    assert page.total == 1
    assert page.items[0]["name"] == "MyMember"
    assert page.items[0]["token"] == 0x0A000001


def test_disassemble_tiny_method(managed: Path) -> None:
    result = disassemble_method_il(managed, 0x06000001, require_verified=False)
    decoded = [(insn["mnemonic"], insn["operand"]) for insn in result["instructions"]]
    assert decoded == [("nop", None), ("ldc.i4", -1), ("call", 0x0A000001), ("ret", None)]
    assert result["header"]["format"] == "tiny"
    assert result["call_tokens"] == [0x0A000001]
    assert result["partial"] is False


def test_disassemble_fat_method(managed: Path) -> None:
    result = disassemble_method_il(managed, 0x06000003, require_verified=False)
    assert result["header"]["format"] == "fat"
    assert [insn["mnemonic"] for insn in result["instructions"]] == ["nop", "ret"]


def test_disassemble_abstract_method_has_no_body(managed: Path) -> None:
    result = disassemble_method_il(managed, 0x06000002, require_verified=False)
    assert result["instructions"] == []
    assert result["reason"] == "abstract_or_runtime_managed_no_rva"


# --------------------------------------------------------------------------- #
# argument and lookup errors
# --------------------------------------------------------------------------- #


def test_clamp_page_rejects_bad_bounds() -> None:
    with pytest.raises(DotnetInspectError, match="offset"):
        _clamp_page(-1, 10)
    with pytest.raises(DotnetInspectError, match="limit"):
        _clamp_page(0, 0)
    assert _clamp_page(0, 10_000) == (0, metadata_enum.MAX_LIMIT)


def test_enumerate_rejects_unknown_kind(managed: Path) -> None:
    with pytest.raises(DotnetInspectError, match="kind must be one of"):
        enumerate_metadata(managed, "widgets", require_verified=False)


def test_disassemble_rejects_non_methoddef_token(managed: Path) -> None:
    with pytest.raises(DotnetInspectError, match="MethodDef token"):
        disassemble_method_il(managed, 0x0A000001, require_verified=False)


def test_disassemble_rejects_zero_rid(managed: Path) -> None:
    with pytest.raises(DotnetInspectError, match="rid must be >= 1"):
        disassemble_method_il(managed, 0x06000000, require_verified=False)


def test_disassemble_reports_out_of_range_rid(managed: Path) -> None:
    with pytest.raises(DotnetInspectError, match="out of range"):
        disassemble_method_il(managed, 0x06000099, require_verified=False)


# --------------------------------------------------------------------------- #
# direct helper coverage
# --------------------------------------------------------------------------- #


def test_read_index_widths() -> None:
    assert _read_index(b"\x01\x02\x03\x04", 0, 2) == (0x0201, 2)
    assert _read_index(b"\x01\x02\x03\x04", 0, 4) == (0x04030201, 4)


def test_index_size_helpers_widen_for_large_tables() -> None:
    assert _coded_index_size({0x02: 1}, (0x02,), 2) == 2
    assert _coded_index_size({0x02: 1 << 20}, (0x02,), 2) == 4
    assert _simple_index_size({0x04: 10}, 0x04) == 2
    assert _simple_index_size({0x04: 70_000}, 0x04) == 4


def _minimal_ctx(strings: bytes) -> _MetaCtx:
    return _MetaCtx(
        path=Path("x"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=strings,
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={},
        table_data_offset=0,
    )


def test_string_at_edges() -> None:
    ctx = _minimal_ctx(b"\x00abc\x00")
    assert _string_at(ctx, 0) is None
    assert _string_at(ctx, 999) is None
    assert _string_at(ctx, 1) == "abc"
    # No terminator: the reader runs to the end of the heap.
    assert _string_at(_minimal_ctx(b"abc"), 1) == "bc"


def test_table_row_size_rejects_an_unsizable_table(managed: Path) -> None:
    ctx = _load_metadata_context(managed)
    with pytest.raises(DotnetInspectError, match="cannot size metadata table"):
        _table_row_size(ctx, 0x2D)


def test_disassemble_il_prefix_unknown_and_truncation() -> None:
    # 0xFE prefix opcode is surfaced as a prefix marker and flags partial.
    insns, partial = _disassemble_il(bytes([0xFE, 0x2A]), max_insns=16)
    assert insns[0]["mnemonic"] == "prefix.fe"
    assert partial is True

    # An unknown single-byte opcode is emitted verbatim.
    insns, _ = _disassemble_il(bytes([0x99, 0x2A]), max_insns=16)
    assert insns[0]["mnemonic"] == "op_99"

    # An operand that runs off the end stops the walk and marks it partial.
    insns, partial = _disassemble_il(bytes([0x20, 0x01, 0x02]), max_insns=16)
    assert insns == []
    assert partial is True


def test_disassemble_il_caps_at_max_insns() -> None:
    insns, partial = _disassemble_il(bytes([0x00] * 10), max_insns=4)
    assert len(insns) == 4
    assert partial is True


# --------------------------------------------------------------------------- #
# _load_metadata_context error arms (called directly to bypass inspect_dotnet)
# --------------------------------------------------------------------------- #


def test_missing_com_descriptor(tmp_path: Path) -> None:
    path = tmp_path / "no_cor.dll"
    _write_clr_with_tables(path)
    raw = bytearray(path.read_bytes())
    e_lfanew = 0x80
    optional = e_lfanew + 4 + 20
    dir_base = optional + 112
    struct.pack_into("<II", raw, dir_base + 14 * 8, 0, 0)  # zero the COR directory
    path.write_bytes(raw)
    with pytest.raises(DotnetInspectError, match="missing COM descriptor"):
        _load_metadata_context(path)


def test_metadata_directory_empty(tmp_path: Path) -> None:
    path = tmp_path / "empty_meta.dll"
    _write_clr_with_tables(path)
    raw = bytearray(path.read_bytes())
    struct.pack_into("<II", raw, 0x300 + 8, 0, 0)  # zero meta rva/size in the COR header
    path.write_bytes(raw)
    with pytest.raises(DotnetInspectError, match="metadata directory empty"):
        _load_metadata_context(path)


def test_metadata_not_bsjb(tmp_path: Path) -> None:
    path = tmp_path / "not_bsjb.dll"
    _write_clr_with_tables(path)
    raw = bytearray(path.read_bytes())
    raw[0x400 : 0x400 + 4] = b"XXXX"
    path.write_bytes(raw)
    with pytest.raises(DotnetInspectError, match="not BSJB"):
        _load_metadata_context(path)


def test_metadata_streams_truncated(tmp_path: Path) -> None:
    path = tmp_path / "trunc.dll"
    _write_clr_with_tables(path)
    raw = bytearray(path.read_bytes())
    # An oversized version length pushes the stream table past end-of-metadata.
    struct.pack_into("<I", raw, 0x400 + 12, 0x100000)
    path.write_bytes(raw)
    with pytest.raises(DotnetInspectError, match="streams truncated"):
        _load_metadata_context(path)


def test_tables_stream_too_small_yields_empty(tmp_path: Path) -> None:
    """A #~ stream under the 24-byte header floor enumerates as empty."""
    blob = _pack_blob(["#Strings", "#~"], {"#Strings": b"\x00A\x00", "#~": b"\x00" * 8})
    path = tmp_path / "small_tables.dll"
    _write_clr_with_tables(path, metadata=blob)
    ctx = _load_metadata_context(path)
    assert ctx.row_counts == {}
    page = enumerate_metadata(path, "types", require_verified=False)
    assert page.total == 0


def test_strings_heap_skips_empty_entries_and_runs_to_the_end(tmp_path: Path) -> None:
    """An empty entry is skipped and the last entry is read to the heap end."""
    # index 0 is the heap NUL; index 1 is an empty entry; "tail" has no NUL.
    blob = _pack_blob(["#Strings"], {"#Strings": b"\x00\x00tail"})
    path = tmp_path / "no_terminator.dll"
    _write_clr_with_tables(path, metadata=blob)
    page = enumerate_metadata(path, "strings", require_verified=False)
    assert [item["value"] for item in page.items] == ["tail"]


def test_disassemble_reports_an_unmappable_method_rva(tmp_path: Path) -> None:
    path = tmp_path / "unmappable.dll"
    _write_clr_with_tables(
        path, metadata=_metadata_blob(method_rvas=(_TINY_RVA, 0, _FAT_RVA, 0x7FFFFFF0))
    )
    with pytest.raises(DotnetInspectError, match="not mappable"):
        disassemble_method_il(path, 0x06000004, require_verified=False)

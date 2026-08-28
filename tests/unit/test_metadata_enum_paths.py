"""Metadata enumeration paths against handcrafted ECMA-335 assemblies.

Complements test_dotnet_metadata_enum.py: this file builds a PE whose #~
stream carries real TypeDef/Field/MethodDef/MemberRef/ManifestResource rows
and real method bodies (tiny and fat), then drives every listing kind, the IL
disassembler paths, and each metadata-shape refusal in _load_metadata_context.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.metadata_enum import (
    _clamp_page,
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

# --- assembly builder --------------------------------------------------------


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


_HEAP = b"\0App\0Ns\0Main\0Helper\0NoBody\0fld\0WriteLine\0res.bin"


def _sidx(name: bytes) -> int:
    return _HEAP.index(name)


def _tables_stream() -> bytes:
    header = bytearray(24)
    valid = (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0A) | (1 << 0x28)
    struct.pack_into("<Q", header, 8, valid)
    counts = _u32(2) + _u32(1) + _u32(3) + _u32(1) + _u32(1)
    typedefs = (
        _u32(0x100000) + _u16(_sidx(b"App")) + _u16(_sidx(b"Ns")) + _u16(0) + _u16(1) + _u16(1)
    ) + (_u32(0x100001) + _u16(_sidx(b"Helper")) + _u16(0) + _u16(0) + _u16(1) + _u16(1))
    fields = _u16(0x16) + _u16(_sidx(b"fld")) + _u16(0)
    methods = (
        (_u32(0x1380) + _u16(0) + _u16(0) + _u16(_sidx(b"Main")) + _u16(0) + _u16(1))
        + (_u32(0) + _u16(0) + _u16(0x400) + _u16(_sidx(b"NoBody")) + _u16(0) + _u16(1))
        + (_u32(0x13C0) + _u16(0) + _u16(0) + _u16(_sidx(b"Helper")) + _u16(0) + _u16(1))
    )
    memberrefs = _u16(0x09) + _u16(_sidx(b"WriteLine")) + _u16(0)
    resources = _u32(0) + _u32(1) + _u16(_sidx(b"res.bin")) + _u16(0)
    return bytes(header) + counts + typedefs + fields + methods + memberrefs + resources


def _metadata_root(streams: dict[bytes, bytes]) -> bytes:
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - len(version) % 4) % 4)
    headers_len = 0
    for name in streams:
        headers_len += 8 + ((len(name) + 1 + 3) & ~3)
    data_offset = 16 + len(version_padded) + 4 + headers_len
    blob = bytearray()
    blob += b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", len(version))
    blob += version_padded
    blob += struct.pack("<HH", 0, len(streams))
    payload = b""
    for name, data in streams.items():
        blob += struct.pack("<II", data_offset + len(payload), len(data))
        name_bytes = name + b"\0"
        blob += name_bytes + b"\0" * ((4 - len(name_bytes) % 4) % 4)
        payload += data
    return bytes(blob) + payload


_TINY_IL = bytes([0x72]) + _u32(0x70000001) + bytes([0x28]) + _u32(0x0A000001) + bytes([0x2A])
_TINY_BODY = bytes([(len(_TINY_IL) << 2) | 0x02]) + _TINY_IL
_FAT_IL = bytes([0xFE, 0xA5, 0x20])  # prefix, unknown opcode, truncated ldc.i4
_FAT_BODY = _u16(0x3003) + _u16(8) + _u32(len(_FAT_IL)) + _u32(0x11000001) + _FAT_IL


def _write_clr_pe(
    path: Path,
    *,
    com_rva: int = 0x1100,
    com_size: int = 72,
    meta_rva: int = 0x1200,
    meta_size: int | None = None,
    meta_blob: bytes | None = None,
    bodies: dict[int, bytes] | None = None,
) -> None:
    image = bytearray(0x800)
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
    struct.pack_into("<II", image, dir_base + 14 * 8, com_rva, com_size)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    size = len(meta_blob) if meta_size is None and meta_blob else (meta_size or 0x40)
    struct.pack_into("<II", image, cor_off + 8, meta_rva, size)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)

    if meta_blob is not None:
        image[0x400 : 0x400 + len(meta_blob)] = meta_blob
    for file_off, body in (bodies or {}).items():
        image[file_off : file_off + len(body)] = body
    path.write_bytes(image)


def _full_assembly(tmp_path: Path) -> Path:
    path = tmp_path / "app.exe"
    blob = _metadata_root({b"#~": _tables_stream(), b"#Strings": _HEAP})
    assert len(blob) <= 0x180, "metadata must fit before the method bodies"
    _write_clr_pe(path, meta_blob=blob, bodies={0x580: _TINY_BODY, 0x5C0: _FAT_BODY})
    return path


# --- pagination / argument guards ----------------------------------------------


def test_page_arguments_are_validated() -> None:
    with pytest.raises(DotnetInspectError, match="offset"):
        _clamp_page(-1, 10)
    with pytest.raises(DotnetInspectError, match="limit"):
        _clamp_page(0, 0)
    assert _clamp_page(0, 100000) == (0, 256)


def test_an_unknown_kind_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(_full_assembly(tmp_path), "modules")

    assert caught.value.code == "invalid_argument"
    assert caught.value.details["kind"] == "modules"


# --- listing kinds ---------------------------------------------------------------


def test_types_listing_reads_names_and_namespaces(tmp_path: Path) -> None:
    page = enumerate_metadata(_full_assembly(tmp_path), "types")

    assert page.total == 2
    assert page.items[0]["token"] == 0x02000001
    assert page.items[0]["name"] == "App"
    assert page.items[0]["namespace"] == "Ns"
    assert page.items[1]["name"] == "Helper"
    assert page.items[1]["namespace"] is None


def test_methods_listing_reads_names_and_rvas(tmp_path: Path) -> None:
    page = enumerate_metadata(_full_assembly(tmp_path), "methods")

    assert page.total == 3
    assert [item["name"] for item in page.items] == ["Main", "NoBody", "Helper"]
    assert [item["rva"] for item in page.items] == [0x1380, 0, 0x13C0]


def test_fields_listing_reads_names(tmp_path: Path) -> None:
    page = enumerate_metadata(_full_assembly(tmp_path), "fields")

    assert page.total == 1
    assert page.items[0] == {"token": 0x04000001, "rid": 1, "name": "fld"}


def test_resources_listing_reads_names_and_flags(tmp_path: Path) -> None:
    page = enumerate_metadata(_full_assembly(tmp_path), "resources")

    assert page.total == 1
    assert page.items[0]["name"] == "res.bin"
    assert page.items[0]["flags"] == 1


def test_strings_listing_walks_the_heap(tmp_path: Path) -> None:
    page = enumerate_metadata(_full_assembly(tmp_path), "strings", limit=3)

    assert page.total == 8
    assert page.truncated is True
    assert page.items[0]["value"] == "App"


def test_xref_listing_reads_memberref_names(tmp_path: Path) -> None:
    page = list_memberref_xrefs(_full_assembly(tmp_path))

    assert page.total == 1
    assert page.items[0]["token"] == 0x0A000001
    assert page.items[0]["name"] == "WriteLine"
    assert page.kind == "xrefs"


# --- IL disassembly ----------------------------------------------------------------


def test_disassembling_a_tiny_method_collects_call_tokens(tmp_path: Path) -> None:
    result = disassemble_method_il(_full_assembly(tmp_path), 0x06000001)

    assert result["header"] == {"format": "tiny", "code_size": len(_TINY_IL)}
    mnemonics = [insn["mnemonic"] for insn in result["instructions"]]
    assert mnemonics == ["ldstr", "call", "ret"]
    assert result["call_tokens"] == [0x0A000001]
    assert result["partial"] is False


def test_disassembling_a_method_without_a_body_says_so(tmp_path: Path) -> None:
    result = disassemble_method_il(_full_assembly(tmp_path), 0x06000002)

    assert result["instructions"] == []
    assert result["reason"] == "abstract_or_runtime_managed_no_rva"


def test_disassembling_a_fat_method_reports_prefixes_and_truncation(
    tmp_path: Path,
) -> None:
    result = disassemble_method_il(_full_assembly(tmp_path), 0x06000003)

    assert result["header"]["format"] == "fat"
    assert result["header"]["max_stack"] == 8
    assert result["header"]["local_var_sig_tok"] == 0x11000001
    mnemonics = [insn["mnemonic"] for insn in result["instructions"]]
    assert mnemonics == ["prefix.fe", "op_a5"]
    assert result["partial"] is True


def test_method_tokens_are_validated(tmp_path: Path) -> None:
    path = _full_assembly(tmp_path)

    with pytest.raises(DotnetInspectError, match="MethodDef token"):
        disassemble_method_il(path, 0x02000001)
    with pytest.raises(DotnetInspectError, match="rid must be"):
        disassemble_method_il(path, 0x06000000)
    with pytest.raises(DotnetInspectError, match="out of range"):
        disassemble_method_il(path, 0x06000063)


def test_a_method_rva_outside_the_image_is_not_found(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))

    with pytest.raises(DotnetInspectError, match="not mappable"):
        _read_method_body(meta, 0x9000, max_bytes=64)


def test_a_method_rva_past_the_end_of_the_file_is_not_found(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))
    meta.pe_data = meta.pe_data[:0x580]

    with pytest.raises(DotnetInspectError, match="out of file"):
        _read_method_body(meta, 0x1380, max_bytes=64)


def test_a_truncated_fat_header_is_not_found(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))
    meta.pe_data = meta.pe_data[: 0x5C0 + 4]

    with pytest.raises(DotnetInspectError, match="fat method header truncated"):
        _read_method_body(meta, 0x13C0, max_bytes=64)


def test_the_disassembler_marks_a_page_cut_as_partial() -> None:
    instructions, partial = _disassemble_il(b"\x00" * 5, max_insns=2)

    assert [insn["mnemonic"] for insn in instructions] == ["nop", "nop"]
    assert partial is True


# --- metadata shape refusals ---------------------------------------------------


def test_a_pe_without_a_com_descriptor_is_not_dotnet(tmp_path: Path) -> None:
    path = tmp_path / "native.exe"
    _write_clr_pe(path, com_rva=0, com_size=0)

    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", require_verified=False)

    assert caught.value.code == "not_dotnet"


def test_an_empty_metadata_directory_is_unverified(tmp_path: Path) -> None:
    path = tmp_path / "nometa.exe"
    _write_clr_pe(path, meta_rva=0)

    with pytest.raises(DotnetInspectError, match="metadata directory empty"):
        enumerate_metadata(path, "types", require_verified=False)


def test_metadata_that_is_not_bsjb_is_unverified(tmp_path: Path) -> None:
    path = tmp_path / "nobsjb.exe"
    _write_clr_pe(path, meta_rva=0x1300)

    with pytest.raises(DotnetInspectError, match="metadata not BSJB"):
        enumerate_metadata(path, "types", require_verified=False)


def test_metadata_truncated_before_the_stream_count_is_refused(
    tmp_path: Path,
) -> None:
    version = b"v2\0\0"
    blob = b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", len(version)) + version
    path = tmp_path / "shortmeta.exe"
    _write_clr_pe(path, meta_blob=blob)

    with pytest.raises(DotnetInspectError, match="streams truncated"):
        enumerate_metadata(path, "types", require_verified=False)


def test_a_truncated_stream_header_stops_the_stream_walk(tmp_path: Path) -> None:
    version = b"v2\0\0"
    blob = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", len(version))
        + version
        + struct.pack("<HH", 0, 2)
        + b"\0\0\0\0"
    )
    path = tmp_path / "streamcut.exe"
    _write_clr_pe(path, meta_blob=blob)

    page = enumerate_metadata(path, "types", require_verified=False)

    assert page.total == 0


def test_an_unterminated_stream_name_stops_the_stream_walk(tmp_path: Path) -> None:
    version = b"v2\0\0"
    blob = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", len(version))
        + version
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 0, 0)
        + b"#~"
    )
    path = tmp_path / "namecut.exe"
    _write_clr_pe(path, meta_blob=blob)

    page = enumerate_metadata(path, "types", require_verified=False)

    assert page.total == 0


def test_a_tables_stream_shorter_than_its_header_is_empty(tmp_path: Path) -> None:
    blob = _metadata_root({b"#~": b"\0" * 8, b"#Strings": _HEAP})
    path = tmp_path / "tinytables.exe"
    _write_clr_pe(path, meta_blob=blob)

    page = enumerate_metadata(path, "types", require_verified=False)

    assert page.total == 0


def test_row_counts_truncated_inside_the_header_are_dropped(tmp_path: Path) -> None:
    header = bytearray(24)
    struct.pack_into("<Q", header, 8, 1 << 0x02)  # claims a TypeDef count
    blob = _metadata_root({b"#~": bytes(header), b"#Strings": _HEAP})
    path = tmp_path / "countcut.exe"
    _write_clr_pe(path, meta_blob=blob)

    page = enumerate_metadata(path, "types", require_verified=False)

    assert page.total == 0


# --- low-level helpers -----------------------------------------------------------


def test_string_heap_reads_are_bounded(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))

    assert _string_at(meta, 0) is None
    assert _string_at(meta, 10_000) is None
    assert _string_at(meta, _sidx(b"res.bin")) == "res.bin"  # unterminated tail


def test_wide_indexes_read_four_bytes() -> None:
    assert _read_index(b"\x01\x02\x03\x04", 0, 4) == (0x04030201, 4)
    assert _read_index(b"\x01\x02\x03\x04", 0, 2) == (0x0201, 2)


def test_an_unknown_table_cannot_be_sized(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))

    with pytest.raises(DotnetInspectError) as caught:
        _table_row_size(meta, 0x2D)

    assert caught.value.code == "unsupported_metadata"


def test_row_capacity_is_zero_for_bad_geometry(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))

    assert _rows_the_stream_can_hold(meta, 0, 0) == 0
    assert _rows_the_stream_can_hold(meta, len(meta.tables) + 1, 4) == 0


def test_page_serialization_names_the_backend(tmp_path: Path) -> None:
    page = enumerate_metadata(_full_assembly(tmp_path), "fields")

    as_dict = page.to_dict()

    assert as_dict["kind"] == "fields"
    assert as_dict["backend"] == "dotnet_metadata"
    assert as_dict["not_ida_idalib"] is True
    assert as_dict["claims_universal_unpack"] is False


def test_an_empty_strings_heap_yields_nothing(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))
    meta.strings = b""

    assert list(_iter_strings_heap(meta)) == []


def test_il_cut_off_at_end_of_file_is_reported_partial(tmp_path: Path) -> None:
    """A code_size running past EOF must not read as a complete method body."""
    meta = _load_metadata_context(_full_assembly(tmp_path))
    meta.pe_data = meta.pe_data[: 0x580 + 1 + 5]

    body = _read_method_body(meta, 0x1380, max_bytes=64)

    assert body["il_len"] == len(_TINY_IL)
    assert len(body["il"]) == 5
    assert body["truncated"] is True


def test_the_strings_heap_walk_is_capped(tmp_path: Path) -> None:
    meta = _load_metadata_context(_full_assembly(tmp_path))
    meta.strings = b"\0" + b"\0\0" + b"x\0" * 10_001

    items = list(_iter_strings_heap(meta))

    assert len(items) == 10_000
    assert items[0]["value"] == "x"

"""Parser-body and guard coverage for bounded ECMA-335 metadata enumeration.

The row counts, stream headers and heap offsets are all attacker-controlled,
and the enumerator materialises tables before paging them. The existing
hostile-table suite needs a real managed assembly and skips without one; here
a managed PE (with populated Module/TypeDef/Field/MethodDef/MemberRef/
ManifestResource tables, a #Strings heap and a couple of method bodies) is
built by hand so the enumerators, the metadata-context guards and the IL
disassembler all run without any external fixture.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture
from headless_re_mcp.detection import pe as pe_mod
from headless_re_mcp.detection.pe import _Layout, _Section
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.metadata_enum import (
    CAPABILITY,
    _clamp_page,
    _disassemble_il,
    _iter_strings_heap,
    _MetaCtx,
    _read_index,
    _read_method_body,
    _rows_the_stream_can_hold,
    _string_at,
    _table_row_size,
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)

# --------------------------------------------------------------------------
# BSJB metadata builders (shared shape with the CLR inspector tests).
# --------------------------------------------------------------------------


def _tilde(entries: list[tuple[int, int, bytes]], *, heap_sizes: int = 0) -> bytes:
    entries = sorted(entries)
    valid = 0
    for table_id, _count, _data in entries:
        valid |= 1 << table_id
    header = bytearray(24)
    header[4] = 2
    header[6] = heap_sizes
    struct.pack_into("<Q", header, 8, valid)
    body = bytearray()
    for _table_id, count, _data in entries:
        body += struct.pack("<I", count)
    for _table_id, _count, data in entries:
        body += data
    return bytes(header) + bytes(body)


def _meta_blob(streams: list[tuple[str, bytes]], *, version: bytes = b"v4.0.30319\0") -> bytes:
    version_padded = version + b"\0" * ((-len(version)) % 4)
    root = bytearray()
    root += b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0)
    root += struct.pack("<I", len(version)) + version_padded
    root += struct.pack("<HH", 0, len(streams))
    header_len = len(root)
    for name, _data in streams:
        name_bytes = name.encode("ascii") + b"\0"
        name_bytes += b"\0" * ((-len(name_bytes)) % 4)
        header_len += 8 + len(name_bytes)
    payload = bytearray()
    data_cursor = header_len
    for name, data in streams:
        name_bytes = name.encode("ascii") + b"\0"
        name_bytes += b"\0" * ((-len(name_bytes)) % 4)
        root += struct.pack("<II", data_cursor, len(data)) + name_bytes
        payload += data
        data_cursor += len(data)
    return bytes(root) + bytes(payload)


class _RichMetadata:
    """A #~/#Strings blob with a row in each table the enumerators read."""

    def __init__(self) -> None:
        strings = bytearray(b"\0")

        def add(name: str) -> int:
            index = len(strings)
            strings.extend(name.encode("ascii") + b"\0")
            return index

        self.module = add("MyModule")
        type1 = add("Widget")
        type2 = add("Gadget")
        namespace = add("MyApp")
        field1 = add("count")
        field2 = add("name")
        method1 = add(".ctor")
        self.method2 = add("Run")
        member1 = add("WriteLine")
        member2 = add("ToString")
        resource = add("app.resources")

        module_row = struct.pack("<H", 0) + struct.pack("<H", self.module) + b"\0" * 6
        typedef_rows = (
            struct.pack("<IHHHHH", 0, type1, namespace, 0, 1, 1)
            + struct.pack("<IHHHHH", 0, type2, namespace, 0, 2, 2)
        )
        field_rows = (
            struct.pack("<HHH", 0, field1, 0) + struct.pack("<HHH", 0, field2, 0)
        )
        # MethodDef row 1 is abstract (RVA 0); row 2 points at the tiny body.
        methoddef_rows = (
            struct.pack("<IHHHHH", 0, 0, 0, method1, 0, 1)
            + struct.pack("<IHHHHH", self.TINY_RVA, 0, 0, self.method2, 0, 2)
        )
        memberref_rows = (
            struct.pack("<HHH", 0, member1, 0) + struct.pack("<HHH", 0, member2, 0)
        )
        manifest_row = struct.pack("<IIHH", 0, 0, resource, 0)

        tilde = _tilde(
            [
                (0x00, 1, module_row),
                (0x02, 2, typedef_rows),
                (0x04, 2, field_rows),
                (0x06, 2, methoddef_rows),
                (0x0A, 2, memberref_rows),
                (0x28, 1, manifest_row),
            ]
        )
        self.strings = bytes(strings)
        self.blob = _meta_blob([("#~", tilde), ("#Strings", self.strings)])

    TINY_RVA = 0x2600


# --------------------------------------------------------------------------
# Managed PE builder: embeds a metadata blob and a few method bodies.
# --------------------------------------------------------------------------

_SECTION_VA = 0x2000
_SECTION_RAW = 0x200
_COR20_FILE = 0x300
_META_FILE = 0x400
_TINY_BODY_FILE = 0x800  # rva 0x2600
_FAT_BODY_FILE = 0x900  # rva 0x2700
_EOF_BODY_FILE = 0xFF0  # rva 0x2DF0

FAT_RVA = 0x2700
EOF_RVA = 0x2DF0
# ldc.i4 5 ; call 0x0A000001 ; ret  (11 IL bytes behind a tiny header)
_TINY_IL = (
    bytes([0x20])
    + struct.pack("<i", 5)
    + bytes([0x28])
    + struct.pack("<I", 0x0A000001)
    + bytes([0x2A])
)


def _rva_of(file_offset: int) -> int:
    return _SECTION_VA + (file_offset - _SECTION_RAW)


def build_pe(meta_blob: bytes) -> bytes:
    image = bytearray(0x1000)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, _SECTION_VA)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, _rva_of(_COR20_FILE), 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0xE00, _SECTION_VA, 0xE00, _SECTION_RAW)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    struct.pack_into("<I", image, _COR20_FILE, 72)
    struct.pack_into("<HH", image, _COR20_FILE + 4, 2, 5)
    struct.pack_into("<II", image, _COR20_FILE + 8, _rva_of(_META_FILE), len(meta_blob))
    struct.pack_into("<I", image, _COR20_FILE + 16, 0x1)
    struct.pack_into("<I", image, _COR20_FILE + 20, 0x06000001)

    image[_META_FILE : _META_FILE + len(meta_blob)] = meta_blob

    tiny_header = ((len(_TINY_IL) << 2) | 0x02) & 0xFF
    image[_TINY_BODY_FILE] = tiny_header
    image[_TINY_BODY_FILE + 1 : _TINY_BODY_FILE + 1 + len(_TINY_IL)] = _TINY_IL

    fat = struct.pack("<HHII", 0x3003, 8, 2, 0) + bytes([0x00, 0x2A])
    image[_FAT_BODY_FILE : _FAT_BODY_FILE + len(fat)] = fat

    # A tiny header at EOF that claims a body longer than the file can hold.
    image[_EOF_BODY_FILE] = ((30 << 2) | 0x02) & 0xFF
    return bytes(image)


_RICH = _RichMetadata()
_RICH_PE_BYTES = build_pe(_RICH.blob)


@pytest.fixture
def rich_pe(tmp_path: Path) -> Path:
    path = tmp_path / "managed.dll"
    path.write_bytes(_RICH_PE_BYTES)
    return path


def _rich_ctx() -> _MetaCtx:
    layout = pe_mod._parse_layout(_RICH_PE_BYTES)
    return _MetaCtx(
        path=Path("managed.dll"),
        pe_data=_RICH_PE_BYTES,
        layout=layout,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=b"",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={},
        table_data_offset=0,
    )


# --------------------------------------------------------------------------
# _clamp_page / kind validation.
# --------------------------------------------------------------------------


def test_clamp_page_rejects_bad_bounds() -> None:
    with pytest.raises(DotnetInspectError):
        _clamp_page(-1, 10)
    with pytest.raises(DotnetInspectError):
        _clamp_page(0, 0)


def test_enumerate_rejects_unknown_kind() -> None:
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata("/no/such/file", "bogus")
    assert caught.value.code == "invalid_argument"


# --------------------------------------------------------------------------
# enumerate_metadata over a fully populated assembly.
# --------------------------------------------------------------------------


def test_enumerate_types(rich_pe: Path) -> None:
    page = enumerate_metadata(rich_pe, "types")
    names = {item["name"] for item in page.items}
    assert {"Widget", "Gadget"} <= names
    assert all(item["namespace"] == "MyApp" for item in page.items)
    assert page.total == 2
    assert page.capability == CAPABILITY


def test_enumerate_methods(rich_pe: Path) -> None:
    page = enumerate_metadata(rich_pe, "methods")
    names = {item["name"] for item in page.items}
    assert {".ctor", "Run"} <= names
    rvas = {item["rva"] for item in page.items}
    assert _RichMetadata.TINY_RVA in rvas


def test_enumerate_fields(rich_pe: Path) -> None:
    page = enumerate_metadata(rich_pe, "fields")
    assert {item["name"] for item in page.items} == {"count", "name"}


def test_enumerate_resources(rich_pe: Path) -> None:
    page = enumerate_metadata(rich_pe, "resources")
    assert page.total == 1
    assert page.items[0]["name"] == "app.resources"


def test_enumerate_strings(rich_pe: Path) -> None:
    page = enumerate_metadata(rich_pe, "strings")
    values = {item["value"] for item in page.items}
    assert "MyModule" in values
    assert "app.resources" in values


def test_enumerate_paging_truncates(rich_pe: Path) -> None:
    page = enumerate_metadata(rich_pe, "types", offset=0, limit=1)
    assert len(page.items) == 1
    assert page.truncated is True


def test_memberref_xrefs(rich_pe: Path) -> None:
    page = list_memberref_xrefs(rich_pe)
    assert page.kind == "xrefs"
    assert {item["name"] for item in page.items} == {"WriteLine", "ToString"}
    assert all("class_coded_index" in item for item in page.items)


# --------------------------------------------------------------------------
# disassemble_method_il: token guards + happy path.
# --------------------------------------------------------------------------


def test_disassemble_rejects_non_methoddef_token(rich_pe: Path) -> None:
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(rich_pe, 0x02000001)
    assert caught.value.code == "invalid_argument"


def test_disassemble_rejects_zero_rid(rich_pe: Path) -> None:
    with pytest.raises(DotnetInspectError):
        disassemble_method_il(rich_pe, 0x06000000)


def test_disassemble_rejects_out_of_range_rid(rich_pe: Path) -> None:
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(rich_pe, 0x06000009)
    assert caught.value.code == "not_found"


def test_disassemble_abstract_method_has_no_body(rich_pe: Path) -> None:
    result = disassemble_method_il(rich_pe, 0x06000001)
    assert result["instructions"] == []
    assert result["reason"] == "abstract_or_runtime_managed_no_rva"


def test_disassemble_tiny_body(rich_pe: Path) -> None:
    result = disassemble_method_il(rich_pe, 0x06000002)
    mnemonics = [insn["mnemonic"] for insn in result["instructions"]]
    assert mnemonics == ["ldc.i4", "call", "ret"]
    assert result["call_tokens"] == [0x0A000001]
    assert result["header"]["format"] == "tiny"
    assert result["partial"] is False


# --------------------------------------------------------------------------
# _read_method_body: fat header, truncation and mapping failures.
# --------------------------------------------------------------------------


def test_read_method_body_parses_fat_header() -> None:
    body = _read_method_body(_rich_ctx(), FAT_RVA, max_bytes=4096)
    assert body["header"]["format"] == "fat"
    assert body["header"]["max_stack"] == 8
    assert body["truncated"] is False


def test_read_method_body_flags_max_bytes_truncation() -> None:
    body = _read_method_body(_rich_ctx(), _RichMetadata.TINY_RVA, max_bytes=1)
    assert body["truncated"] is True


def test_read_method_body_flags_body_running_past_eof() -> None:
    body = _read_method_body(_rich_ctx(), EOF_RVA, max_bytes=4096)
    assert body["truncated"] is True


def test_read_method_body_rejects_unmappable_rva() -> None:
    with pytest.raises(DotnetInspectError) as caught:
        _read_method_body(_rich_ctx(), 0x99999, max_bytes=64)
    assert caught.value.code == "not_found"


def test_read_method_body_rejects_offset_past_file() -> None:
    section = _Section(
        name=".text",
        virtual_size=0x1000,
        virtual_address=0x1000,
        raw_size=0x1000,
        raw_offset=0x200,
        characteristics=0x60000020,
    )
    layout = _Layout(
        machine=0x8664,
        architecture=Architecture.X64,
        characteristics=0,
        subsystem=3,
        dll_characteristics=0,
        image_base=0x400000,
        image_size=0x3000,
        entry_point_rva=0,
        section_alignment=0x1000,
        file_alignment=0x200,
        linker_version="14.0",
        size_of_headers=0x200,
        directories=(),
        sections=(section,),
    )
    ctx = _MetaCtx(
        path=Path("x"),
        pe_data=b"\x00" * 0x100,  # shorter than the section's mapped raw span
        layout=layout,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=b"",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={},
        table_data_offset=0,
    )
    with pytest.raises(DotnetInspectError) as caught:
        _read_method_body(ctx, 0x1000, max_bytes=16)
    assert caught.value.code == "not_found"


# --------------------------------------------------------------------------
# _disassemble_il: prefix, unknown opcode, truncation, insn cap.
# --------------------------------------------------------------------------


def test_disassemble_il_records_multibyte_prefix() -> None:
    insns, partial = _disassemble_il(bytes([0xFE, 0x00]), max_insns=16)
    assert insns[0]["mnemonic"] == "prefix.fe"
    assert partial is True


def test_disassemble_il_labels_unknown_opcode() -> None:
    insns, _partial = _disassemble_il(bytes([0x99, 0x2A]), max_insns=16)
    assert insns[0]["mnemonic"] == "op_99"
    assert insns[1]["mnemonic"] == "ret"


def test_disassemble_il_flags_truncated_operand() -> None:
    insns, partial = _disassemble_il(bytes([0x20, 0x01]), max_insns=16)
    assert partial is True
    assert all(insn["mnemonic"] != "ldc.i4" for insn in insns)


def test_disassemble_il_stops_at_instruction_cap() -> None:
    insns, partial = _disassemble_il(bytes([0x00] * 5), max_insns=3)
    assert len(insns) == 3
    assert partial is True


# --------------------------------------------------------------------------
# Small helpers driven directly.
# --------------------------------------------------------------------------


def test_read_index_reads_four_byte_indexes() -> None:
    assert _read_index(struct.pack("<I", 0x01020304), 0, 4) == (0x01020304, 4)
    assert _read_index(struct.pack("<H", 0x0102), 0, 2) == (0x0102, 2)


def _string_ctx(strings: bytes) -> _MetaCtx:
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


def test_string_at_bounds_and_unterminated() -> None:
    ctx = _string_ctx(b"\0abc")  # no trailing NUL after "abc"
    assert _string_at(ctx, 0) is None
    assert _string_at(ctx, 999) is None
    assert _string_at(ctx, 1) == "abc"


def test_table_row_size_rejects_unknown_table() -> None:
    ctx = _string_ctx(b"\0")
    with pytest.raises(DotnetInspectError) as caught:
        _table_row_size(ctx, 0x2D)
    assert caught.value.code == "unsupported_metadata"


def test_rows_the_stream_can_hold_is_zero_past_the_end() -> None:
    ctx = _string_ctx(b"\0")
    ctx.tables = b"\x00" * 40
    assert _rows_the_stream_can_hold(ctx, 40, 4) == 0
    assert _rows_the_stream_can_hold(ctx, 0, 0) == 0


def test_iter_strings_heap_is_empty_for_empty_heap() -> None:
    assert list(_iter_strings_heap(_string_ctx(b""))) == []


def test_iter_strings_heap_caps_at_ten_thousand() -> None:
    ctx = _string_ctx(b"\0" + b"a\0" * 10_001)
    assert len(list(_iter_strings_heap(ctx))) == 10_000


def test_iter_strings_heap_skips_empties_and_reads_to_the_end() -> None:
    # index 1 is an empty entry (two NULs); "abc" runs to EOF with no NUL.
    entries = list(_iter_strings_heap(_string_ctx(b"\0\0abc")))
    assert [item["value"] for item in entries] == ["abc"]


def test_read_method_body_rejects_truncated_fat_header() -> None:
    rva = _rva_of(0xFFB)  # a fat header this close to EOF cannot hold 12 bytes
    with pytest.raises(DotnetInspectError) as caught:
        _read_method_body(_rich_ctx(), rva, max_bytes=64)
    assert caught.value.code == "not_found"


# --------------------------------------------------------------------------
# _load_metadata_context guards (driven through enumerate_metadata).
# --------------------------------------------------------------------------


def _pe_with(patches: dict[int, tuple[str, int]]) -> bytes:
    image = bytearray(_RICH_PE_BYTES)
    for offset, (fmt, value) in patches.items():
        struct.pack_into(fmt, image, offset, value)
    return bytes(image)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_context_rejects_short_com_descriptor(tmp_path: Path) -> None:
    data = _pe_with({0x17C: ("<I", 16)})  # data directory[14].Size < 72
    path = _write(tmp_path, "shortcom.dll", data)
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", require_verified=False)
    assert caught.value.code == "not_dotnet"


def test_context_rejects_empty_metadata_directory(tmp_path: Path) -> None:
    data = _pe_with({_COR20_FILE + 12: ("<I", 8)})  # COR20 MetaData size < 16
    path = _write(tmp_path, "emptymeta.dll", data)
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", require_verified=False)
    assert caught.value.code == "clr_unverified"


def test_context_rejects_metadata_without_bsjb(tmp_path: Path) -> None:
    image = bytearray(_RICH_PE_BYTES)
    image[_META_FILE : _META_FILE + 4] = b"XXXX"
    path = _write(tmp_path, "nobsjb.dll", bytes(image))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", require_verified=False)
    assert caught.value.code == "clr_unverified"


def test_context_rejects_truncated_stream_table(tmp_path: Path) -> None:
    data = _pe_with({_META_FILE + 12: ("<I", 0x10000)})  # version length overflow
    path = _write(tmp_path, "trunc.dll", data)
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types")
    assert caught.value.code == "clr_unverified"


def _pe_with_blob(blob: bytes) -> bytes:
    image = bytearray(build_pe(blob))
    return bytes(image)


def test_context_handles_declared_but_absent_stream(tmp_path: Path) -> None:
    # Stream count says 1 but the header runs off the end of the metadata.
    blob = (
        b"BSJB"
        + struct.pack("<HH", 1, 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 4)
        + b"ABCD"
        + struct.pack("<HH", 0, 1)
    )
    path = _write(tmp_path, "streamgone.dll", _pe_with_blob(blob))
    page = enumerate_metadata(path, "types")
    assert page.total == 0


def test_context_handles_unterminated_stream_name(tmp_path: Path) -> None:
    blob = (
        b"BSJB"
        + struct.pack("<HH", 1, 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 4)
        + b"ABCD"
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 0, 0)
        + b"\xff\xff\xff\xff"
    )
    path = _write(tmp_path, "badname.dll", _pe_with_blob(blob))
    page = enumerate_metadata(path, "types")
    assert page.total == 0


def test_context_handles_tables_stream_shorter_than_header(tmp_path: Path) -> None:
    blob = _meta_blob([("#~", b"\0" * 10)])
    path = _write(tmp_path, "shorttilde.dll", _pe_with_blob(blob))
    page = enumerate_metadata(path, "types")
    assert page.total == 0


def test_context_handles_row_counts_running_past_the_stream(tmp_path: Path) -> None:
    header = bytearray(24)
    header[4] = 2
    struct.pack_into("<Q", header, 8, (1 << 0x00) | (1 << 0x02))
    blob = _meta_blob([("#~", bytes(header))])
    path = _write(tmp_path, "rowcounts.dll", _pe_with_blob(blob))
    page = enumerate_metadata(path, "types")
    assert page.total == 0


def test_context_handles_bsjb_without_tables_stream(tmp_path: Path) -> None:
    blob = _meta_blob([("#Strings", b"\0only\0")])
    path = _write(tmp_path, "notables.dll", _pe_with_blob(blob))
    page = enumerate_metadata(path, "types")
    assert page.total == 0

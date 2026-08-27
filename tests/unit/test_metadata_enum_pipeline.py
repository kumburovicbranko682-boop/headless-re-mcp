"""End-to-end coverage for the ECMA-335 enumeration engine over crafted images.

The hostile-input suites for this module all mutate a real managed assembly and
are skipped wherever that fixture is absent, so the table reader, the method-body
parser and the metadata-context loader normally run untested. These tests build
a small but complete .NET image by hand -- a #~ tables stream with Module,
TypeDef, Field, MethodDef, MemberRef and ManifestResource rows, a #Strings heap,
and real method bodies -- so the whole pipeline is exercised without a fixture,
and every malformed shape is shown to degrade to an empty page or a structured
error rather than an overread or a confident-but-wrong listing.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.metadata_enum import (
    _MetaCtx,
    _string_at,
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)

# Method RVAs used by the rich image; body layout mirrors these file offsets.
_RVA_TINY = 0x1700  # file 0x900
_RVA_FAT = 0x1780  # file 0x980
_RVA_ABSTRACT = 0x0  # no body
_RVA_UNMAPPABLE = 0x7FFFFFFF
_RVA_PAST_EOF = 0x1F80  # file 0x1180, fat header lying about code_size


def _name_block(name: str) -> bytes:
    raw = name.encode() + b"\0"
    pad = (len(raw) + 3) & ~3
    return raw + b"\0" * (pad - len(raw))


def _wrap_bsjb(tables: bytes, strings: bytes) -> bytes:
    version = b"v4.0.30319\0"
    version_len = (len(version) + 3) & ~3
    version_block = version + b"\0" * (version_len - len(version))
    head = bytearray()
    head += b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0)
    head += struct.pack("<I", version_len) + version_block
    head += struct.pack("<HH", 0, 2)  # flags, stream_count
    tilde_name = _name_block("#~")
    strings_name = _name_block("#Strings")
    header_len = len(head) + (8 + len(tilde_name)) + (8 + len(strings_name))
    off_tilde = header_len
    off_strings = off_tilde + len(tables)
    head += struct.pack("<II", off_tilde, len(tables)) + tilde_name
    head += struct.pack("<II", off_strings, len(strings)) + strings_name
    return bytes(head) + tables + strings


def _pe_shell(
    meta: bytes, *, com_rva: int, com_size: int, meta_rva: int, meta_size: int
) -> bytearray:
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
    struct.pack_into("<II", image, dir_base + 14 * 8, com_rva, com_size)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    if com_rva == 0x1100:
        cor = 0x300
        struct.pack_into("<I", image, cor, 72)
        struct.pack_into("<HH", image, cor + 4, 2, 5)
        struct.pack_into("<II", image, cor + 8, meta_rva, meta_size)
        struct.pack_into("<I", image, cor + 16, 0x1)
        struct.pack_into("<I", image, cor + 20, 0x06000001)
    if meta and meta_rva == 0x1200:
        image[0x400 : 0x400 + len(meta)] = meta
    return image


def _build_rich_clr_pe(*, wide: bool = False) -> bytes:
    """A complete managed image: six tables, a #Strings heap and method bodies."""
    heap = bytearray(b"\0")
    index: dict[str, int] = {}

    def intern(name: str) -> int:
        at = len(heap)
        heap.extend(name.encode() + b"\0")
        index[name] = at
        return at

    i_mod = intern("MyModule")
    i_type = intern("MyType")
    i_ns = intern("MyNs")
    i_field = intern("myField")
    method_names = [intern(f"Method{k}") for k in range(5)]
    i_ref = intern("RefMethod")
    i_res = intern("MyResource")
    strings = bytes(heap)

    def sidx(value: int) -> bytes:
        return struct.pack("<I", value) if wide else struct.pack("<H", value)

    heap_sizes = 0x01 if wide else 0x00
    valid = (1 << 0x00) | (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0A) | (1 << 0x28)
    tables = bytearray()
    tables += b"\0\0\0\0" + bytes([2, 0, heap_sizes, 0])
    tables += struct.pack("<Q", valid) + struct.pack("<Q", 0)
    for row_count in (1, 1, 1, 5, 1, 1):
        tables += struct.pack("<I", row_count)
    tables += struct.pack("<H", 0) + sidx(i_mod) + struct.pack("<HHH", 0, 0, 0)  # Module
    tables += struct.pack("<I", 0x100000) + sidx(i_type) + sidx(i_ns)  # TypeDef
    tables += struct.pack("<HHH", 0, 1, 1)  # Extends, FieldList, MethodList
    tables += struct.pack("<H", 0x6) + sidx(i_field) + struct.pack("<H", 0)  # Field
    rvas = [_RVA_TINY, _RVA_FAT, _RVA_ABSTRACT, _RVA_UNMAPPABLE, _RVA_PAST_EOF]
    for k in range(5):  # MethodDef rows
        tables += struct.pack("<IHH", rvas[k], 0, 0x86) + sidx(method_names[k])
        tables += struct.pack("<HH", 0, 1)  # Signature, ParamList
    tables += struct.pack("<H", 0x02) + sidx(i_ref) + struct.pack("<H", 0)  # MemberRef
    tables += struct.pack("<II", 0, 1) + sidx(i_res) + struct.pack("<H", 0)  # ManifestResource

    meta = _wrap_bsjb(bytes(tables), strings)
    image = _pe_shell(meta, com_rva=0x1100, com_size=72, meta_rva=0x1200, meta_size=len(meta))

    tiny_il = (
        bytes([0x00, 0x20])
        + (5).to_bytes(4, "little")
        + bytes([0x28])
        + (0x0A000001).to_bytes(4, "little")
        + bytes([0x2A])
    )
    image[0x900] = (len(tiny_il) << 2) | 0x02
    image[0x901 : 0x901 + len(tiny_il)] = tiny_il

    fat_il = bytes([0x00, 0x2A])
    struct.pack_into("<HHI", image, 0x980, 0x3003, 8, len(fat_il))
    struct.pack_into("<I", image, 0x980 + 8, 0)
    image[0x980 + 12 : 0x980 + 12 + len(fat_il)] = fat_il

    # A fat header that claims far more code than the file can hold.
    struct.pack_into("<HHI", image, 0x1180, 0x3003, 8, 0x1000)
    image[0x1180 + 12 : 0x1180 + 14] = bytes([0x00, 0x2A])
    return bytes(image)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    return path


# --- enumeration over a well-formed image ----------------------------------


@pytest.mark.parametrize("wide", [False, True], ids=["narrow-index", "wide-index"])
def test_enumerate_every_kind(tmp_path: Path, wide: bool) -> None:
    """Each table reader must surface its rows with both index widths.

    The heap-size flags decide whether string indexes are two or four bytes; a
    reader that assumes one width reads shifted bytes on the other and returns
    garbage names.
    """
    path = _write(tmp_path, _build_rich_clr_pe(wide=wide))

    types = enumerate_metadata(path, "types", limit=50)
    assert [item["name"] for item in types.items] == ["MyType"]
    assert types.items[0]["namespace"] == "MyNs"

    methods = enumerate_metadata(path, "methods", limit=50)
    assert methods.total == 5
    assert methods.items[0]["name"] == "Method0"
    assert methods.items[0]["rva"] == _RVA_TINY

    fields = enumerate_metadata(path, "fields", limit=50)
    assert [item["name"] for item in fields.items] == ["myField"]

    resources = enumerate_metadata(path, "resources", limit=50)
    assert resources.items[0]["name"] == "MyResource"
    assert resources.items[0]["flags"] == 1

    strings = enumerate_metadata(path, "strings", limit=50)
    assert "MyModule" in {item["value"] for item in strings.items}


def test_enumerate_paginates_the_method_table(tmp_path: Path) -> None:
    """offset/limit slice the materialised table and report truncation honestly."""
    path = _write(tmp_path, _build_rich_clr_pe())
    page = enumerate_metadata(path, "methods", offset=1, limit=2)
    assert [item["name"] for item in page.items] == ["Method1", "Method2"]
    assert page.total == 5
    assert page.truncated is True


def test_list_memberref_xrefs_surfaces_names(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    xrefs = list_memberref_xrefs(path, limit=10)
    assert xrefs.kind == "xrefs"
    assert [item["name"] for item in xrefs.items] == ["RefMethod"]


# --- IL disassembly across body shapes -------------------------------------


def test_disassemble_tiny_method_body(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    result = disassemble_method_il(path, 0x06000001)
    assert result["header"]["format"] == "tiny"
    assert [insn["mnemonic"] for insn in result["instructions"]] == [
        "nop",
        "ldc.i4",
        "call",
        "ret",
    ]
    assert result["call_tokens"] == [0x0A000001]
    assert result["partial"] is False


def test_disassemble_fat_method_body(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    result = disassemble_method_il(path, 0x06000002)
    assert result["header"]["format"] == "fat"
    assert result["header"]["max_stack"] == 8
    assert [insn["mnemonic"] for insn in result["instructions"]] == ["nop", "ret"]


def test_disassemble_abstract_method_has_no_body(tmp_path: Path) -> None:
    """A MethodDef with RVA 0 is abstract/runtime; report it, do not read bytes."""
    path = _write(tmp_path, _build_rich_clr_pe())
    result = disassemble_method_il(path, 0x06000003)
    assert result["instructions"] == []
    assert result["reason"] == "abstract_or_runtime_managed_no_rva"


def test_disassemble_unmappable_rva_is_not_found(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(path, 0x06000004)
    assert caught.value.code == "not_found"


def test_disassemble_code_size_past_eof_is_partial(tmp_path: Path) -> None:
    """A fat header that claims more code than the file holds must read partial."""
    path = _write(tmp_path, _build_rich_clr_pe())
    result = disassemble_method_il(path, 0x06000005)
    assert result["partial"] is True


def test_disassemble_max_bytes_cap_is_partial(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    result = disassemble_method_il(path, 0x06000001, max_bytes=1)
    assert result["partial"] is True


# --- argument validation ----------------------------------------------------


def test_enumerate_rejects_negative_offset(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", offset=-1)
    assert caught.value.code == "invalid_argument"


def test_enumerate_rejects_zero_limit(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", limit=0)
    assert caught.value.code == "invalid_argument"


def test_enumerate_rejects_unknown_kind(tmp_path: Path) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "widgets")
    assert caught.value.code == "invalid_argument"


@pytest.mark.parametrize(
    ("token", "code"),
    [
        (0x02000001, "invalid_argument"),  # not a MethodDef token
        (0x06000000, "invalid_argument"),  # rid 0 is never valid
        (0x06009999, "not_found"),  # rid past the table
    ],
)
def test_disassemble_rejects_bad_tokens(tmp_path: Path, token: int, code: str) -> None:
    path = _write(tmp_path, _build_rich_clr_pe())
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(path, token)
    assert caught.value.code == code


# --- metadata-context loader: malformed images degrade quietly --------------


def _pe_with_meta(
    meta: bytes,
    *,
    com_rva: int = 0x1100,
    com_size: int = 72,
    meta_rva: int = 0x1200,
    meta_size: int | None = None,
) -> bytes:
    size = len(meta) if meta_size is None else meta_size
    return bytes(
        _pe_shell(meta, com_rva=com_rva, com_size=com_size, meta_rva=meta_rva, meta_size=size)
    )


_BSJB16 = b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0) + struct.pack("<I", 0)


@pytest.mark.parametrize(
    ("label", "kwargs", "code"),
    [
        ("missing COM descriptor", {"com_rva": 0, "com_size": 0}, "not_dotnet"),
        ("empty metadata directory", {"meta_rva": 0}, "clr_unverified"),
    ],
)
def test_loader_rejects_missing_directories(
    tmp_path: Path, label: str, kwargs: dict[str, int], code: str
) -> None:
    path = _write(tmp_path, _pe_with_meta(_BSJB16, meta_size=0x40, **kwargs))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", require_verified=False)
    assert caught.value.code == code, label


def test_loader_rejects_non_bsjb_metadata(tmp_path: Path) -> None:
    path = _write(tmp_path, _pe_with_meta(b"XXXX" + b"\0" * 60, meta_size=0x40))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", require_verified=False)
    assert caught.value.code == "clr_unverified"


def test_loader_rejects_truncated_stream_directory(tmp_path: Path) -> None:
    path = _write(tmp_path, _pe_with_meta(_BSJB16, meta_size=16))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "types", require_verified=False)
    assert caught.value.code == "clr_unverified"


@pytest.mark.parametrize(
    "meta",
    [
        _BSJB16 + struct.pack("<HH", 0, 1),  # declares one stream, no header bytes
        _BSJB16 + struct.pack("<HH", 0, 1) + struct.pack("<II", 50, 4) + b"nonull",
    ],
    ids=["stream-header-truncated", "stream-name-unterminated"],
)
def test_loader_with_broken_stream_headers_yields_empty_pages(tmp_path: Path, meta: bytes) -> None:
    """A stream table the loader cannot walk leaves no streams, so pages are empty."""
    path = _write(tmp_path, _pe_with_meta(meta))
    page = enumerate_metadata(path, "types", require_verified=False)
    assert page.total == 0


def _with_tilde(tables: bytes) -> bytes:
    head = _BSJB16 + struct.pack("<HH", 0, 1)
    tilde_name = _name_block("#~")
    off = len(head) + 8 + len(tilde_name)
    head += struct.pack("<II", off, len(tables)) + tilde_name
    return head + tables


def test_loader_tables_header_too_small_is_empty(tmp_path: Path) -> None:
    path = _write(tmp_path, _pe_with_meta(_with_tilde(b"\0" * 10)))
    page = enumerate_metadata(path, "types", require_verified=False)
    assert page.total == 0


def test_loader_row_count_running_past_stream_is_empty(tmp_path: Path) -> None:
    """A valid bit that claims a row count the stream cannot hold yields no rows."""
    tables = bytearray(24)
    struct.pack_into("<Q", tables, 8, 1 << 0x02)  # TypeDef present, no room for its count
    path = _write(tmp_path, _pe_with_meta(_with_tilde(bytes(tables))))
    page = enumerate_metadata(path, "types", require_verified=False)
    assert page.total == 0


def test_declared_rows_cannot_exceed_the_stream(tmp_path: Path) -> None:
    """Row counts are attacker-controlled; the #~ stream length is the real bound.

    A TypeDef table declaring far more rows than the stream holds must be clamped
    to what is present, and a later table whose start is pushed past the stream
    end must yield nothing rather than materialising a giant list.
    """
    valid = (1 << 0x02) | (1 << 0x06)  # TypeDef then MethodDef
    tables = bytearray()
    tables += b"\0\0\0\0" + bytes([2, 0, 0, 0])
    tables += struct.pack("<Q", valid) + struct.pack("<Q", 0)
    tables += struct.pack("<I", 0x7FFFFFFF)  # TypeDef claims two billion rows
    tables += struct.pack("<I", 1)  # MethodDef claims one
    tables += b"\0" * 64  # only a handful of rows actually fit
    path = _write(tmp_path, _pe_with_meta(_with_tilde(bytes(tables))))

    types = enumerate_metadata(path, "types", require_verified=False, limit=20)
    assert types.total < 100_000
    methods = enumerate_metadata(path, "methods", require_verified=False, limit=20)
    assert methods.total == 0  # its start was pushed past the stream end


def test_strings_heap_skips_empty_entries_and_reads_an_unterminated_tail(tmp_path: Path) -> None:
    """The #Strings walker drops empty slots and takes a final name to the heap end."""
    tables = bytearray(24)  # a #~ header with no tables present
    strings = b"\0\0abc"  # index 1 is empty; "abc" at the end has no NUL
    meta = _wrap_bsjb(bytes(tables), strings)
    path = _write(tmp_path, _pe_with_meta(meta))
    page = enumerate_metadata(path, "strings", require_verified=False)
    assert [item["value"] for item in page.items] == ["abc"]


# --- _string_at edge cases --------------------------------------------------


def _ctx_with_strings(strings: bytes) -> _MetaCtx:
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


@pytest.mark.parametrize("index", [0, -1, 999], ids=["zero", "negative", "out-of-range"])
def test_string_at_rejects_indexes_outside_the_heap(index: int) -> None:
    ctx = _ctx_with_strings(b"\0hello\0")
    assert _string_at(ctx, index) is None


def test_string_at_reads_a_name_running_to_the_heap_end(tmp_path: Path) -> None:
    """A name with no trailing NUL is taken to the end of the heap, not overrun."""
    ctx = _ctx_with_strings(b"\0abc")
    assert _string_at(ctx, 1) == "abc"

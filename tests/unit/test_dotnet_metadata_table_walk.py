"""End-to-end table walk over a synthetic assembly that actually has tables.

The existing metadata fixtures carry an empty ``#~`` stream, so the enumeration
path that steps across real rows -- cumulative table offsets, per-row index
reads, the #Strings heap, and the tiny-header method body -- only ever ran
against real assemblies that are not present in this checkout. This fixture is
a hand-assembled ECMA-335 image with Module, TypeDef, Field, MethodDef,
MemberRef and ManifestResource rows plus one IL method body, small enough that
every offset below is checkable by hand against ECMA-335 II.22/II.24.
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
    _MetaCtx,
    _string_at,
    _table_row_size,
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)

# ldstr 0x70000001; call 0x0A000001 (the MemberRef row below); nop; ret.
_IL = (
    bytes([0x72])
    + (0x70000001).to_bytes(4, "little")
    + bytes([0x28])
    + (0x0A000001).to_bytes(4, "little")
    + bytes([0x00, 0x2A])
)

# RVA of the method body; the .text section maps RVA 0x1000.. to file 0x200..,
# so this lands at file offset 0x1000 inside the 0x1200-byte image.
_METHOD_RVA = 0x1E00

_HEAP_NAMES = ("<Module>", "Widget", "App.Core", "Run", "value", "Res.bin", "Concat")


def _strings_heap() -> tuple[bytes, dict[str, int]]:
    blob = bytearray(b"\0")
    offsets: dict[str, int] = {}
    for name in _HEAP_NAMES:
        offsets[name] = len(blob)
        blob += name.encode("ascii") + b"\0"
    while len(blob) % 4:
        blob += b"\0"
    return bytes(blob), offsets


def _tables_stream(
    at: dict[str, int],
    *,
    wide: bool = False,
    method_rva: int = _METHOD_RVA,
    typedef_declared: int | None = None,
) -> bytes:
    header = bytearray(24)
    # major=2, minor=0, heap_sizes (0x07 = 4-byte string/guid/blob indexes),
    # reserved=1.
    struct.pack_into("<BBBB", header, 4, 2, 0, 0x07 if wide else 0, 1)
    valid = (1 << 0x00) | (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0A) | (1 << 0x28)
    struct.pack_into("<Q", header, 8, valid)
    # Row counts in table-bit order: Module, TypeDef, Field, MethodDef,
    # MemberRef, ManifestResource. typedef_declared lets a test claim more
    # TypeDef rows than the stream actually holds.
    counts = struct.pack("<6I", 1, typedef_declared or 2, 1, 1, 1, 1)
    # Every table below MethodDef has rows, so methods (and everything after
    # them) are only found if each intervening row size is computed right.
    s = "I" if wide else "H"  # string-heap index column width
    g = "I" if wide else "H"  # guid-heap index column width
    b = "I" if wide else "H"  # blob-heap index column width
    module = struct.pack(f"<H{s}{g}{g}{g}", 0, at["<Module>"], 0, 0, 0)
    typedef_module = struct.pack(f"<I{s}{s}HHH", 0, at["<Module>"], 0, 0, 1, 1)
    typedef_widget = struct.pack(f"<I{s}{s}HHH", 0x00100001, at["Widget"], at["App.Core"], 0, 1, 1)
    field = struct.pack(f"<H{s}{b}", 0x0001, at["value"], 0)
    method = struct.pack(f"<IHH{s}{b}H", method_rva, 0, 0x0086, at["Run"], 0, 1)
    # MemberRefParent coded index: TypeRef rid 1 under a 3-bit tag => (1<<3)|1.
    memberref = struct.pack(f"<H{s}{b}", (1 << 3) | 1, at["Concat"], 0)
    resource = struct.pack(f"<II{s}H", 0, 1, at["Res.bin"], 0)
    return (
        bytes(header)
        + counts
        + module
        + typedef_module
        + typedef_widget
        + field
        + method
        + memberref
        + resource
    )


def _metadata_root(tables: bytes, strings: bytes) -> bytes:
    version = b"v4.0.30319\0"
    padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    head = bytearray()
    head += b"BSJB"
    head += struct.pack("<HHI", 1, 1, 0)
    head += struct.pack("<I", len(version))
    head += padded
    head += struct.pack("<HH", 0, 2)  # flags, stream count
    # Stream offsets are relative to the BSJB root; the two headers occupy
    # 12 (#~) + 20 (#Strings) bytes, and stream data follows immediately.
    tables_off = len(head) + 12 + 20
    strings_off = tables_off + len(tables)
    head += struct.pack("<II", tables_off, len(tables)) + b"#~\0\0"
    head += struct.pack("<II", strings_off, len(strings)) + b"#Strings\0\0\0\0"
    return bytes(head) + tables + strings


def _tiny_body() -> bytes:
    return bytes([(len(_IL) << 2) | 0x02]) + _IL


def _write_image(
    path: Path,
    meta: bytes,
    *,
    body: bytes | None = None,
    cor_dir: tuple[int, int] = (0x1100, 72),
    cor_meta_size: int | None = None,
) -> None:
    image = bytearray(0x1200)
    pe = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe)
    image[pe : pe + 4] = b"PE\0\0"
    file_header = pe + 4
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
    struct.pack_into("<II", image, dir_base + 14 * 8, *cor_dir)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into(
        "<II", image, cor_off + 8, 0x1200, len(meta) if cor_meta_size is None else cor_meta_size
    )
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    image[0x400 : 0x400 + len(meta)] = meta
    if body is None:
        body = _tiny_body()
    image[0x1000 : 0x1000 + len(body)] = body
    path.write_bytes(image)


def _write_assembly(
    path: Path,
    *,
    wide: bool = False,
    method_rva: int = _METHOD_RVA,
    typedef_declared: int | None = None,
    body: bytes | None = None,
) -> None:
    strings, at = _strings_heap()
    tables = _tables_stream(at, wide=wide, method_rva=method_rva, typedef_declared=typedef_declared)
    _write_image(path, _metadata_root(tables, strings), body=body)


@pytest.fixture
def assembly(tmp_path: Path) -> Path:
    binary = tmp_path / "tables.exe"
    _write_assembly(binary)
    return binary


def test_types_walk_yields_both_typedef_rows(assembly: Path) -> None:
    page = enumerate_metadata(assembly, "types", limit=10)
    assert page.total == 2
    assert page.truncated is False
    module_row, widget_row = page.items
    assert module_row == {
        "token": 0x02000001,
        "rid": 1,
        "name": "<Module>",
        "namespace": None,
    }
    assert widget_row == {
        "token": 0x02000002,
        "rid": 2,
        "name": "Widget",
        "namespace": "App.Core",
    }


def test_methods_walk_reports_name_and_rva(assembly: Path) -> None:
    # MethodDef sits behind Module, TypeDef and Field rows, so reaching it at
    # all proves the cumulative row-size stepping across those tables.
    page = enumerate_metadata(assembly, "methods", limit=10)
    assert page.total == 1
    (method,) = page.items
    assert method == {"token": 0x06000001, "rid": 1, "name": "Run", "rva": _METHOD_RVA}


def test_fields_walk_reads_the_name_past_the_flags(assembly: Path) -> None:
    page = enumerate_metadata(assembly, "fields", limit=10)
    assert page.total == 1
    assert page.items[0] == {"token": 0x04000001, "rid": 1, "name": "value"}


def test_resources_walk_reports_offset_flags_and_name(assembly: Path) -> None:
    # ManifestResource is the highest table bit in the fixture (0x28), so its
    # start offset sums every other table's rows.
    page = enumerate_metadata(assembly, "resources", limit=10)
    assert page.total == 1
    assert page.items[0] == {
        "token": 0x28000001,
        "rid": 1,
        "name": "Res.bin",
        "offset": 0,
        "flags": 1,
    }


def test_strings_kind_lists_every_heap_entry_with_its_index(assembly: Path) -> None:
    _, offsets = _strings_heap()
    page = enumerate_metadata(assembly, "strings", limit=50)
    assert page.total == len(_HEAP_NAMES)
    assert [item["value"] for item in page.items] == list(_HEAP_NAMES)
    assert [item["index"] for item in page.items] == [offsets[n] for n in _HEAP_NAMES]


def test_pagination_over_the_strings_heap_is_honest_about_truncation(assembly: Path) -> None:
    first = enumerate_metadata(assembly, "strings", offset=0, limit=3)
    assert [item["value"] for item in first.items] == ["<Module>", "Widget", "App.Core"]
    assert first.truncated is True

    # A window past the end is empty and, having shown everything before it,
    # must not claim more data remains.
    beyond = enumerate_metadata(assembly, "strings", offset=len(_HEAP_NAMES), limit=3)
    assert beyond.items == ()
    assert beyond.truncated is False


def test_memberref_xrefs_decode_name_and_class(assembly: Path) -> None:
    page = list_memberref_xrefs(assembly)
    assert page.kind == "xrefs"
    assert page.total == 1
    assert page.items[0] == {
        "token": 0x0A000001,
        "rid": 1,
        "name": "Concat",
        "class_coded_index": (1 << 3) | 1,
    }


def test_disassemble_reads_the_tiny_body_through_the_pe_mapping(assembly: Path) -> None:
    result = disassemble_method_il(assembly, 0x06000001)
    assert result["header"] == {"format": "tiny", "code_size": len(_IL)}
    assert result["il_bytes"] == len(_IL)
    assert result["partial"] is False
    decoded = [(insn["mnemonic"], insn["operand"]) for insn in result["instructions"]]
    assert decoded == [
        ("ldstr", 0x70000001),
        ("call", 0x0A000001),
        ("nop", None),
        ("ret", None),
    ]
    assert result["call_tokens"] == [0x0A000001]


def test_disassemble_rejects_a_token_from_another_table(assembly: Path) -> None:
    with pytest.raises(DotnetInspectError, match="MethodDef token"):
        disassemble_method_il(assembly, 0x02000001)


def test_disassemble_reports_a_rid_beyond_the_table(assembly: Path) -> None:
    with pytest.raises(DotnetInspectError, match="out of range"):
        disassemble_method_il(assembly, 0x06000002)


# ---------------------------------------------------------------------------
# Paging and argument guards on the public entry points.
# ---------------------------------------------------------------------------


def test_enumerate_rejects_a_negative_offset(assembly: Path) -> None:
    with pytest.raises(DotnetInspectError, match="offset must be >= 0"):
        enumerate_metadata(assembly, "types", offset=-1)


def test_enumerate_rejects_a_zero_limit(assembly: Path) -> None:
    with pytest.raises(DotnetInspectError, match="limit must be >= 1"):
        enumerate_metadata(assembly, "types", limit=0)


def test_enumerate_rejects_an_unknown_kind(assembly: Path) -> None:
    with pytest.raises(DotnetInspectError, match="kind must be one of"):
        enumerate_metadata(assembly, "modules")


def test_disassemble_rejects_a_rid_of_zero(assembly: Path) -> None:
    with pytest.raises(DotnetInspectError, match="rid must be >= 1"):
        disassemble_method_il(assembly, 0x06000000)


# ---------------------------------------------------------------------------
# Method-body variants: no RVA, fat header, unmappable RVA.
# ---------------------------------------------------------------------------


def test_a_method_without_an_rva_reports_abstract_not_empty_success(tmp_path: Path) -> None:
    binary = tmp_path / "abstract.exe"
    _write_assembly(binary, method_rva=0)

    result = disassemble_method_il(binary, 0x06000001)

    # RVA 0 is an abstract/runtime-provided body; the reply must say so rather
    # than pass off the empty instruction list as a disassembled method.
    assert result["reason"] == "abstract_or_runtime_managed_no_rva"
    assert result["instructions"] == []
    assert result["partial"] is False
    assert result["method"]["name"] == "Run"


def test_a_fat_method_header_is_decoded_with_its_locals_token(tmp_path: Path) -> None:
    binary = tmp_path / "fat.exe"
    fat_body = struct.pack("<HHII", 0x3003, 8, len(_IL), 0x11000001) + _IL
    _write_assembly(binary, body=fat_body)

    result = disassemble_method_il(binary, 0x06000001)

    assert result["header"] == {
        "format": "fat",
        "flags": 0x3003,
        "max_stack": 8,
        "code_size": len(_IL),
        "local_var_sig_tok": 0x11000001,
    }
    assert result["partial"] is False
    assert [insn["mnemonic"] for insn in result["instructions"]] == [
        "ldstr",
        "call",
        "nop",
        "ret",
    ]


def test_an_rva_outside_every_section_is_reported_not_mapped(tmp_path: Path) -> None:
    binary = tmp_path / "unmapped.exe"
    _write_assembly(binary, method_rva=0x9000)
    with pytest.raises(DotnetInspectError, match="not mappable"):
        disassemble_method_il(binary, 0x06000001)


# ---------------------------------------------------------------------------
# Wide (4-byte) heap indexes: heap_sizes=0x07 changes every row size.
# ---------------------------------------------------------------------------


def test_wide_heap_indexes_still_walk_to_the_right_rows(tmp_path: Path) -> None:
    # With heap_sizes=0x07 every string/guid/blob column is four bytes, so all
    # row sizes change; the walk only lands on MethodDef and ManifestResource
    # if the wide widths are applied to every table in between.
    binary = tmp_path / "wide.exe"
    _write_assembly(binary, wide=True)

    types = enumerate_metadata(binary, "types", limit=10)
    assert [(t["name"], t["namespace"]) for t in types.items] == [
        ("<Module>", None),
        ("Widget", "App.Core"),
    ]

    methods = enumerate_metadata(binary, "methods", limit=10)
    assert methods.items[0]["name"] == "Run"
    assert methods.items[0]["rva"] == _METHOD_RVA

    resources = enumerate_metadata(binary, "resources", limit=10)
    assert resources.items[0]["name"] == "Res.bin"

    xrefs = list_memberref_xrefs(binary)
    assert xrefs.items[0]["name"] == "Concat"


# ---------------------------------------------------------------------------
# Row counts are attacker data: capacity clamping.
# ---------------------------------------------------------------------------


def test_a_declared_row_count_is_clamped_to_what_the_stream_holds(tmp_path: Path) -> None:
    binary = tmp_path / "overdeclared.exe"
    # 3000 stays below the index-widening thresholds (2**14 for coded indexes),
    # so the row layout is unchanged and only the count itself is a lie.
    _write_assembly(binary, typedef_declared=3_000)

    types = enumerate_metadata(binary, "types", limit=50)
    # The stream physically holds four TypeDef-sized rows past the table start,
    # so the claimed three thousand collapse to that; the two real rows still
    # decode, and the walk never allocates for rows that are not there.
    assert types.total < 3_000
    assert [t["name"] for t in types.items[:2]] == ["<Module>", "Widget"]

    # Tables placed after the over-declared one start beyond the stream end,
    # which must read as empty rather than crash.
    assert enumerate_metadata(binary, "fields", limit=50).total == 0


# ---------------------------------------------------------------------------
# Loader guards: hostile or truncated metadata roots refuse loudly (or fall
# back to an empty context) instead of reading out of bounds.
# ---------------------------------------------------------------------------


def _load(path: Path) -> _MetaCtx:
    return _load_metadata_context(path)


def test_loader_rejects_a_pe_without_a_com_descriptor(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    strings, at = _strings_heap()
    _write_image(binary, _metadata_root(_tables_stream(at), strings), cor_dir=(0, 0))
    with pytest.raises(DotnetInspectError, match="missing COM descriptor"):
        _load(binary)


def test_loader_rejects_an_empty_metadata_directory(tmp_path: Path) -> None:
    binary = tmp_path / "nometa.exe"
    strings, at = _strings_heap()
    _write_image(binary, _metadata_root(_tables_stream(at), strings), cor_meta_size=8)
    with pytest.raises(DotnetInspectError, match="metadata directory empty"):
        _load(binary)


def test_loader_rejects_a_root_without_the_bsjb_magic(tmp_path: Path) -> None:
    binary = tmp_path / "badmagic.exe"
    _write_image(binary, b"XSJB" + b"\0" * 28)
    with pytest.raises(DotnetInspectError, match="not BSJB"):
        _load(binary)


def test_loader_rejects_a_version_length_that_overruns_the_root(tmp_path: Path) -> None:
    binary = tmp_path / "badversion.exe"
    # version_len 0x100 pushes the stream-count cursor past the 16-byte root.
    _write_image(binary, b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", 0x100))
    with pytest.raises(DotnetInspectError, match="streams truncated"):
        _load(binary)


def test_a_stream_count_larger_than_the_root_yields_no_streams(tmp_path: Path) -> None:
    binary = tmp_path / "overcount.exe"
    meta = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", 4)
        + b"v1\0\0"
        + struct.pack("<HH", 0, 3)  # claims three streams; the root ends here
    )
    _write_image(binary, meta)
    ctx = _load(binary)
    assert ctx.stream_map == {}
    assert ctx.tables == b""


def test_a_stream_name_without_a_terminator_stops_the_header_walk(tmp_path: Path) -> None:
    binary = tmp_path / "unterminated.exe"
    meta = (
        b"BSJB"
        + struct.pack("<HHI", 1, 1, 0)
        + struct.pack("<I", 4)
        + b"v1\0\0"
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 64, 4)
        + b"#~AA"  # no NUL before the root ends
    )
    _write_image(binary, meta)
    ctx = _load(binary)
    assert ctx.stream_map == {}


def test_a_tables_stream_shorter_than_its_header_reads_as_empty(tmp_path: Path) -> None:
    binary = tmp_path / "shorttables.exe"
    strings, _ = _strings_heap()
    _write_image(binary, _metadata_root(b"\0" * 8, strings))
    ctx = _load(binary)
    assert ctx.row_counts == {}
    assert ctx.table_data_offset == 0
    # The #Strings heap is still served even though the tables are unusable.
    assert list(_iter_strings_heap(ctx))[0]["value"] == "<Module>"


def test_a_valid_bitmap_with_truncated_row_counts_reads_as_empty(tmp_path: Path) -> None:
    binary = tmp_path / "shortcounts.exe"
    header = bytearray(24)
    struct.pack_into("<BBBB", header, 4, 2, 0, 0, 1)
    struct.pack_into("<Q", header, 8, 1)  # Module bit set...
    strings, _ = _strings_heap()
    # ...but only two bytes follow where its four-byte row count should be.
    _write_image(binary, _metadata_root(bytes(header) + b"\0\0", strings))
    ctx = _load(binary)
    assert ctx.row_counts == {}


# ---------------------------------------------------------------------------
# Heap and disassembler helpers on their own contexts.
# ---------------------------------------------------------------------------


def _ctx(**overrides: object) -> _MetaCtx:
    fields: dict[str, object] = {
        "path": Path("synthetic"),
        "pe_data": b"",
        "layout": None,
        "meta": b"",
        "stream_map": {},
        "tables": b"",
        "strings": b"",
        "heap_sizes": 0,
        "string_index_size": 2,
        "blob_index_size": 2,
        "guid_index_size": 2,
        "row_counts": {},
        "table_data_offset": 0,
    }
    fields.update(overrides)
    return _MetaCtx(**fields)  # type: ignore[arg-type]


def test_a_string_without_a_terminator_reads_to_the_heap_end() -> None:
    assert _string_at(_ctx(strings=b"\0tail"), 1) == "tail"


def test_the_strings_iterator_survives_a_missing_final_terminator() -> None:
    items = list(_iter_strings_heap(_ctx(strings=b"\0first\0tail")))
    assert [item["value"] for item in items] == ["first", "tail"]


def test_the_strings_iterator_stops_at_ten_thousand_entries() -> None:
    heap = b"\0" + b"s\0" * 10_050
    assert len(list(_iter_strings_heap(_ctx(strings=heap)))) == 10_000


def test_sizing_an_unmodelled_table_refuses_instead_of_guessing() -> None:
    # 0x1E is not a table this walker models; a guessed size would silently
    # desync every table behind it, so the sizing must abort enumeration.
    with pytest.raises(DotnetInspectError, match="cannot size metadata table"):
        _table_row_size(_ctx(), 0x1E)


def test_an_operand_cut_off_by_the_buffer_end_is_partial() -> None:
    # `call` wants four operand bytes but only two remain.
    instructions, partial = _disassemble_il(b"\x28\x01\x02", max_insns=8)
    assert instructions == []
    assert partial is True


def test_an_unknown_opcode_is_named_not_skipped() -> None:
    instructions, partial = _disassemble_il(b"\xf7\x2a", max_insns=8)
    assert instructions[0] == {"ip": 0, "mnemonic": "op_f7", "operand": None}
    assert instructions[1]["mnemonic"] == "ret"
    assert partial is False


def test_the_instruction_cap_reports_a_partial_listing() -> None:
    instructions, partial = _disassemble_il(b"\x00" * 5, max_insns=3)
    assert len(instructions) == 3
    assert partial is True

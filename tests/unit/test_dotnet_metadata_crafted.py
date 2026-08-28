"""Drive the ECMA-335 enumerator with a hand-built managed PE -- no fixture.

The existing enumeration tests only exercise the empty-tables shell, and the
hostile-tables suite mutates a real managed ``.dll`` that is absent from CI,
so the row walkers, the IL disassembler and the fail-closed error codes in
``metadata_enum.py`` never ran on a hosted platform. Everything here is built
from raw bytes: a ``#~`` stream with Module/TypeDef/Field/MethodDef/MemberRef/
ManifestResource rows, a ``#Strings`` heap, and tiny/fat IL method bodies --
plus hostile variants (forged row counts, unknown table bits, truncated
streams) that must produce bounded results or precise error codes, not hangs.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError, inspect_dotnet
from headless_re_mcp.dotnet.metadata_enum import (
    MAX_LIMIT,
    _disassemble_il,
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)

_TINY_BODY_RVA = 0x1380  # file 0x580
_FAT_BODY_RVA = 0x13C0  # file 0x5C0


def _strings_heap(names: Iterable[str]) -> tuple[bytes, dict[str, int]]:
    """#Strings heap: a leading NUL, then each name NUL-terminated."""
    heap = bytearray(b"\0")
    index: dict[str, int] = {}
    for name in names:
        index[name] = len(heap)
        heap += name.encode("ascii") + b"\0"
    return bytes(heap), index


def _tables_stream(
    row_counts: dict[int, int],
    rows: bytes,
    *,
    declared: dict[int, int] | None = None,
) -> bytes:
    """A #~ stream: 24-byte header, u32 count per valid bit, then the rows.

    ``declared`` lets a test forge the count in the header away from the rows
    actually present, which is exactly what a hostile assembly does.
    """
    header = bytearray(24)
    header[4] = 2  # major version
    valid = 0
    for bit in row_counts:
        valid |= 1 << bit
    struct.pack_into("<Q", header, 8, valid)
    counts = b"".join(
        struct.pack("<I", (declared or {}).get(bit, row_counts[bit])) for bit in sorted(row_counts)
    )
    return bytes(header) + counts + rows


def _bsjb_root(streams: list[tuple[str, bytes]]) -> bytes:
    """A BSJB metadata root with the given streams laid out back to back."""
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - len(version) % 4) % 4)
    headers_len = sum(8 + ((len(name) + 1 + 3) & ~3) for name, _ in streams)
    data_offset = 16 + len(version_padded) + 4 + headers_len
    headers = b""
    payload = b""
    for name, blob in streams:
        headers += struct.pack("<II", data_offset + len(payload), len(blob))
        raw = name.encode("ascii") + b"\0"
        raw += b"\0" * (((len(raw) + 3) & ~3) - len(raw))
        headers += raw
        payload += blob
    root = b"BSJB" + struct.pack("<HHI", 1, 1, 0)
    root += struct.pack("<I", len(version)) + version_padded
    root += struct.pack("<HH", 0, len(streams))
    return root + headers + payload


def _pe_image(
    meta: bytes | None,
    *,
    com_directory: bool = True,
    meta_rva: int = 0x1200,
    bodies: dict[int, bytes] | None = None,
) -> bytes:
    """Minimal PE32+ shell; .text maps RVA 0x1000..0x1400 to file 0x200..0x600."""
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
    if com_directory:
        struct.pack_into("<II", image, optional + 112 + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    # COR20 at file 0x300 (RVA 0x1100).
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, meta_rva, len(meta) if meta else 0)
    struct.pack_into("<I", image, cor_off + 16, 0x1)  # ILONLY
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    if meta is not None:
        assert len(meta) <= 0x180, "metadata would collide with the method bodies"
        image[0x400 : 0x400 + len(meta)] = meta
    for file_off, blob in (bodies or {}).items():
        image[file_off : file_off + len(blob)] = blob
    return bytes(image)


def _standard_image(tmp_path: Path, name: str = "crafted.exe") -> Path:
    """One TypeDef, one Field, three MethodDefs (tiny IL / no RVA / fat IL),
    one MemberRef and one ManifestResource, with all names in #Strings."""
    heap, idx = _strings_heap(
        [
            "CraftedModule",
            "Widget",
            "Demo",
            "DoWork",
            "Ghost",
            "FatOne",
            "count",
            "WriteLine",
            "res.bin",
        ]
    )
    rows = b""
    # Module: generation, Name, Mvid, EncId, EncBaseId.
    rows += struct.pack("<HHHHH", 0, idx["CraftedModule"], 1, 0, 0)
    # TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList.
    rows += struct.pack("<IHHHHH", 0x00100001, idx["Widget"], idx["Demo"], 0, 1, 1)
    # Field: Flags, Name, Signature.
    rows += struct.pack("<HHH", 0x0006, idx["count"], 0)
    # MethodDef: RVA, ImplFlags, Flags, Name, Signature, ParamList.
    rows += struct.pack("<IHHHHH", _TINY_BODY_RVA, 0, 0x0086, idx["DoWork"], 0, 1)
    rows += struct.pack("<IHHHHH", 0, 0, 0x05C6, idx["Ghost"], 0, 1)
    rows += struct.pack("<IHHHHH", _FAT_BODY_RVA, 0, 0x0086, idx["FatOne"], 0, 1)
    # MemberRef: Class (coded), Name, Signature.
    rows += struct.pack("<HHH", 0x0009, idx["WriteLine"], 0)
    # ManifestResource: Offset, Flags, Name, Implementation.
    rows += struct.pack("<IIHH", 0, 1, idx["res.bin"], 0)
    tables = _tables_stream({0x00: 1, 0x02: 1, 0x04: 1, 0x06: 3, 0x0A: 1, 0x28: 1}, rows)
    meta = _bsjb_root([("#~", tables), ("#Strings", heap)])
    # Tiny header: code_size 8 << 2 | 0x2; IL: nop, ldc.i4.1, call 0x0A000001, ret.
    tiny = b"\x22" + bytes([0x00, 0x17, 0x28, 0x01, 0x00, 0x00, 0x0A, 0x2A])
    # Fat header: flags 0x3003, max_stack 8, code_size 2, local sig 0; ldnull, ret.
    fat = struct.pack("<HHII", 0x3003, 8, 2, 0) + b"\x14\x2a"
    path = tmp_path / name
    path.write_bytes(_pe_image(meta, bodies={0x580: tiny, 0x5C0: fat}))
    return path


def test_enumeration_reads_names_out_of_the_crafted_tables(tmp_path: Path) -> None:
    path = _standard_image(tmp_path)

    types = enumerate_metadata(path, "types")
    assert types.total == 1
    assert types.items[0]["name"] == "Widget"
    assert types.items[0]["namespace"] == "Demo"
    assert types.items[0]["token"] == 0x02000001

    methods = enumerate_metadata(path, "methods")
    assert [m["name"] for m in methods.items] == ["DoWork", "Ghost", "FatOne"]
    assert [m["rva"] for m in methods.items] == [_TINY_BODY_RVA, 0, _FAT_BODY_RVA]

    fields = enumerate_metadata(path, "fields")
    assert [f["name"] for f in fields.items] == ["count"]

    resources = enumerate_metadata(path, "resources")
    assert resources.items[0]["name"] == "res.bin"
    assert resources.items[0]["flags"] == 1

    strings = enumerate_metadata(path, "strings")
    values = {item["value"] for item in strings.items}
    assert {"Widget", "DoWork", "res.bin"} <= values


def test_pagination_clamps_and_reports_truncation(tmp_path: Path) -> None:
    path = _standard_image(tmp_path)
    page = enumerate_metadata(path, "methods", offset=1, limit=1)
    assert page.total == 3
    assert [m["name"] for m in page.items] == ["Ghost"]
    assert page.truncated is True
    assert enumerate_metadata(path, "methods", limit=9999).limit == MAX_LIMIT


@pytest.mark.parametrize(
    ("kind", "offset", "limit"),
    [("bogus", 0, 10), ("types", -1, 10), ("types", 0, 0)],
)
def test_bad_arguments_are_rejected(tmp_path: Path, kind: str, offset: int, limit: int) -> None:
    path = _standard_image(tmp_path)
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, kind, offset=offset, limit=limit)
    assert caught.value.code == "invalid_argument"


def test_tiny_method_disassembles_and_collects_call_tokens(tmp_path: Path) -> None:
    result = disassemble_method_il(_standard_image(tmp_path), 0x06000001)
    assert result["header"]["format"] == "tiny"
    assert [i["mnemonic"] for i in result["instructions"]] == [
        "nop",
        "ldc.i4.1",
        "call",
        "ret",
    ]
    assert result["call_tokens"] == [0x0A000001]
    assert result["partial"] is False


def test_method_without_rva_reports_abstract_not_error(tmp_path: Path) -> None:
    result = disassemble_method_il(_standard_image(tmp_path), 0x06000002)
    assert result["instructions"] == []
    assert result["reason"] == "abstract_or_runtime_managed_no_rva"


def test_fat_method_header_is_decoded(tmp_path: Path) -> None:
    result = disassemble_method_il(_standard_image(tmp_path), 0x06000003)
    assert result["header"]["format"] == "fat"
    assert result["header"]["code_size"] == 2
    assert [i["mnemonic"] for i in result["instructions"]] == ["ldnull", "ret"]


def test_disassembly_rejects_bad_tokens_with_precise_codes(tmp_path: Path) -> None:
    path = _standard_image(tmp_path)
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(path, 0x02000001)  # a TypeDef token
    assert caught.value.code == "invalid_argument"
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(path, 0x06000000)  # rid 0
    assert caught.value.code == "invalid_argument"
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(path, 0x06000063)  # rid 99, out of range
    assert caught.value.code == "not_found"


def test_xrefs_list_memberref_names(tmp_path: Path) -> None:
    page = list_memberref_xrefs(_standard_image(tmp_path))
    assert page.kind == "xrefs"
    assert [i["name"] for i in page.items] == ["WriteLine"]
    assert page.items[0]["class_coded_index"] == 0x0009


def test_a_forged_row_count_is_bounded_by_the_stream(tmp_path: Path) -> None:
    # The header claims 0x7FFFFFFF TypeDef rows; only two fit in the stream.
    # The walk must stop at what the bytes can hold, not at what the header says.
    # Note the forged count itself widens the coded indexes: Extends becomes
    # 4 bytes and the row grows to 16, so the rows are written in that width.
    heap, idx = _strings_heap(["M", "A", "B"])
    rows = struct.pack("<HHHHH", 0, idx["M"], 1, 0, 0)
    rows += struct.pack("<IHHIHH", 0, idx["A"], 0, 0, 1, 1)
    rows += struct.pack("<IHHIHH", 0, idx["B"], 0, 0, 1, 1)
    tables = _tables_stream({0x00: 1, 0x02: 2}, rows, declared={0x02: 0x7FFFFFFF})
    path = tmp_path / "forged.exe"
    path.write_bytes(_pe_image(_bsjb_root([("#~", tables), ("#Strings", heap)])))

    page = enumerate_metadata(path, "types", limit=5)
    assert page.total == 2
    assert [t["name"] for t in page.items] == ["A", "B"]


def test_an_unknown_table_bit_aborts_instead_of_misreading(tmp_path: Path) -> None:
    # Bit 0x1E is reserved and unsized: rows after it cannot be located, so the
    # enumerator must refuse rather than walk misaligned rows as real data.
    tables = _tables_stream({0x1E: 1, 0x28: 1}, struct.pack("<IIHH", 0, 0, 0, 0))
    path = tmp_path / "unknown.exe"
    path.write_bytes(_pe_image(_bsjb_root([("#~", tables)])))

    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(path, "resources", require_verified=False)
    assert caught.value.code == "unsupported_metadata"


def test_metadata_context_failures_carry_precise_codes(tmp_path: Path) -> None:
    no_com = tmp_path / "no_com.exe"
    no_com.write_bytes(_pe_image(None, com_directory=False))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(no_com, "types", require_verified=False)
    assert caught.value.code == "not_dotnet"

    empty_dir = tmp_path / "empty_dir.exe"
    empty_dir.write_bytes(_pe_image(None, meta_rva=0))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(empty_dir, "types", require_verified=False)
    assert caught.value.code == "clr_unverified"

    not_bsjb = tmp_path / "not_bsjb.exe"
    not_bsjb.write_bytes(_pe_image(b"\0" * 64))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(not_bsjb, "types", require_verified=False)
    assert "not BSJB" in str(caught.value)

    # A BSJB root cut off right after the version: streams unreadable.
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - len(version) % 4) % 4)
    truncated_root = (
        b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", len(version)) + version_padded
    )
    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(_pe_image(truncated_root))
    with pytest.raises(DotnetInspectError) as caught:
        enumerate_metadata(truncated, "types", require_verified=False)
    assert "truncated" in str(caught.value)


def test_a_tables_stream_shorter_than_its_header_yields_nothing(tmp_path: Path) -> None:
    path = tmp_path / "short_tables.exe"
    path.write_bytes(_pe_image(_bsjb_root([("#~", b"\0" * 8)])))
    page = enumerate_metadata(path, "types", require_verified=False)
    assert page.total == 0


def _one_method_image(tmp_path: Path, name: str, rva: int, *, size: int = 0x800) -> Path:
    heap, idx = _strings_heap(["M", "Only"])
    rows = struct.pack("<HHHHH", 0, idx["M"], 1, 0, 0)
    rows += struct.pack("<IHHHHH", rva, 0, 0, idx["Only"], 0, 1)
    tables = _tables_stream({0x00: 1, 0x06: 1}, rows)
    image = _pe_image(_bsjb_root([("#~", tables), ("#Strings", heap)]))
    path = tmp_path / name
    path.write_bytes(image[:size])
    return path


def test_a_method_rva_that_maps_nowhere_is_not_found(tmp_path: Path) -> None:
    path = _one_method_image(tmp_path, "nowhere.exe", 0x9000)
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(path, 0x06000001)
    assert caught.value.code == "not_found"
    assert "not mappable" in str(caught.value)


def test_a_fat_header_running_past_end_of_file_is_refused(tmp_path: Path) -> None:
    # The section legitimately ends at the file's last byte (0x600), and the
    # method RVA sits 8 bytes before it: a 12-byte fat header cannot fit, so
    # the read must refuse rather than run off the end.
    path = _one_method_image(tmp_path, "fat_trunc.exe", 0x13F8, size=0x600)
    with pytest.raises(DotnetInspectError) as caught:
        disassemble_method_il(path, 0x06000001)
    assert caught.value.code == "not_found"
    assert "truncated" in str(caught.value)


def test_il_decoder_reports_edges_instead_of_guessing() -> None:
    # The 0xFE two-byte prefix is outside the decoded subset: named and marked
    # partial so a caller knows the listing is incomplete, not wrong.
    insns, partial = _disassemble_il(b"\xfe\x2a", max_insns=10)
    assert insns[0]["mnemonic"] == "prefix.fe"
    assert partial is True

    # An unknown one-byte opcode is reported by number, and is not "partial".
    insns, partial = _disassemble_il(b"\xf0", max_insns=10)
    assert insns[0]["mnemonic"] == "op_f0"
    assert partial is False

    # An immediate running past the buffer stops the decode as partial.
    insns, partial = _disassemble_il(b"\x28\x01", max_insns=10)
    assert insns == []
    assert partial is True

    # Short branches carry signed displacements.
    insns, _partial = _disassemble_il(b"\x2b\xfe", max_insns=10)
    assert insns[0]["mnemonic"] == "br.s"
    assert insns[0]["operand"] == -2

    # The instruction budget bounds hostile bodies and says so.
    insns, partial = _disassemble_il(b"\x00" * 5, max_insns=2)
    assert len(insns) == 2
    assert partial is True


def test_inspect_reads_module_name_and_stats_from_the_tables(tmp_path: Path) -> None:
    # The crafted image also drives clr_inspect's table walk: module name and
    # row-count stats must come back out of the report, not placeholders.
    report = inspect_dotnet(_standard_image(tmp_path))
    assert report.verified_clr is True
    assert report.module_name == "CraftedModule"
    assert report.metadata_stats is not None
    assert report.metadata_stats.type_count == 1
    assert report.metadata_stats.method_count == 3
    assert report.metadata_stats.resource_count == 1
    assert report.to_dict()["metadata_stats"]["type_count"] == 1


def test_inspect_reads_the_assembly_name_when_the_table_is_adjacent(
    tmp_path: Path,
) -> None:
    # Module + Assembly only: the name walk reaches the Assembly branch, and a
    # #US stream present is reflected in the heap stats.
    heap, idx = _strings_heap(["Mod", "CraftedAssembly"])
    rows = struct.pack("<HHHHH", 0, idx["Mod"], 1, 0, 0)
    # Assembly: HashAlgId, four version words, Flags, PublicKey, Name, Culture.
    rows += struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, 0, idx["CraftedAssembly"], 0)
    tables = _tables_stream({0x00: 1, 0x20: 1}, rows)
    meta = _bsjb_root([("#~", tables), ("#Strings", heap), ("#US", b"\0")])
    path = tmp_path / "assembly.exe"
    path.write_bytes(_pe_image(meta))

    report = inspect_dotnet(path)
    assert report.module_name == "Mod"
    assert report.assembly_name == "CraftedAssembly"
    assert report.metadata_stats is not None
    assert report.metadata_stats.us_heap_bytes == 1

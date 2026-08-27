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


def _tables_stream(at: dict[str, int]) -> bytes:
    header = bytearray(24)
    # major=2, minor=0, heap_sizes=0 (2-byte string/guid/blob indexes), reserved=1.
    struct.pack_into("<BBBB", header, 4, 2, 0, 0, 1)
    valid = (1 << 0x00) | (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0A) | (1 << 0x28)
    struct.pack_into("<Q", header, 8, valid)
    # Row counts in table-bit order: Module, TypeDef, Field, MethodDef,
    # MemberRef, ManifestResource.
    counts = struct.pack("<6I", 1, 2, 1, 1, 1, 1)
    # Every table below MethodDef has rows, so methods (and everything after
    # them) are only found if each intervening row size is computed right.
    module = struct.pack("<HHHHH", 0, at["<Module>"], 0, 0, 0)
    typedef_module = struct.pack("<IHHHHH", 0, at["<Module>"], 0, 0, 1, 1)
    typedef_widget = struct.pack("<IHHHHH", 0x00100001, at["Widget"], at["App.Core"], 0, 1, 1)
    field = struct.pack("<HHH", 0x0001, at["value"], 0)
    method = struct.pack("<IHHHHH", _METHOD_RVA, 0, 0x0086, at["Run"], 0, 1)
    # MemberRefParent coded index: TypeRef rid 1 under a 3-bit tag => (1<<3)|1.
    memberref = struct.pack("<HHH", (1 << 3) | 1, at["Concat"], 0)
    resource = struct.pack("<IIHH", 0, 1, at["Res.bin"], 0)
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


def _write_assembly(path: Path) -> None:
    strings, at = _strings_heap()
    meta = _metadata_root(_tables_stream(at), strings)
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
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(meta))
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    image[0x400 : 0x400 + len(meta)] = meta
    body = bytes([(len(_IL) << 2) | 0x02]) + _IL
    image[0x1000 : 0x1000 + len(body)] = body
    path.write_bytes(image)


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

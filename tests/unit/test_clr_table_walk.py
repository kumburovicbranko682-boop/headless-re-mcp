"""Direct tests for clr_inspect's metadata table walk to Module/Assembly names.

``_parse_tables_and_names`` used to know how to advance past only the Module and
Assembly tables and broke on the first other table. Because every real assembly
has TypeRef/TypeDef rows right after Module, the walk stopped before ever
reaching the Assembly row and ``assembly_name`` came back ``None`` for
essentially all of them. These build a tiny ``#~`` + ``#Strings`` pair by hand
so the behaviour can be pinned without a full managed PE fixture.
"""

from __future__ import annotations

import struct

from headless_re_mcp.dotnet.clr_inspect import _parse_tables_and_names


def _tables_stream(
    valid_bits: list[int],
    row_counts_in_order: list[int],
    rows_blob: bytes,
    *,
    heap_sizes: int = 0,
) -> bytes:
    valid = 0
    for bit in valid_bits:
        valid |= 1 << bit
    # reserved(4) major(1) minor(1) heap_sizes(1) reserved(1) valid(8) sorted(8)
    header = struct.pack("<IBBBBQQ", 0, 2, 0, heap_sizes, 1, valid, 0)
    counts = b"".join(struct.pack("<I", n) for n in row_counts_in_order)
    return header + counts + rows_blob


def _pack_meta(tables: bytes, strings: bytes) -> tuple[bytes, dict[str, tuple[int, int]]]:
    meta = bytearray(b"\x00" * 8)  # leading padding; offsets are explicit below
    t_off = len(meta)
    meta += tables
    s_off = len(meta)
    meta += strings
    stream_map = {"#~": (t_off, len(tables)), "#Strings": (s_off, len(strings))}
    return bytes(meta), stream_map


def test_assembly_name_is_read_past_an_intervening_typedef_table() -> None:
    strings = b"\x00" + b"MyModule\x00" + b"MyAssembly\x00"
    # index("MyModule") == 1, index("MyAssembly") == 10
    module_row = struct.pack("<HHHHH", 0, 1, 0, 0, 0)  # Generation, Name=1, 3 GUIDs
    typedef_row = b"\x00" * 14  # Flags(4) + 2 str + TypeDefOrRef + 2 simple, all 2-byte
    # Assembly: HashAlgId(4) + Major/Minor/Build/Rev(2 each) + Flags(4)
    # + PublicKey(blob 2) + Name(str 2)=10 + Culture(str 2)
    assembly_row = struct.pack("<IHHHHIHHH", 0, 0, 0, 0, 0, 0, 0, 10, 0)
    tables = _tables_stream(
        [0x00, 0x02, 0x20], [1, 1, 1], module_row + typedef_row + assembly_row
    )
    meta, stream_map = _pack_meta(tables, strings)

    module_name, assembly_name, _stats = _parse_tables_and_names(meta, stream_map)

    assert module_name == "MyModule"
    assert assembly_name == "MyAssembly"


def test_a_module_without_an_assembly_row_does_not_crash_on_a_later_table() -> None:
    # A .netmodule has no Assembly row. A table the sizing does not model
    # (0x35 is a Portable-PDB table) sits after Module; the walk must capture the
    # module name and stop cleanly rather than raise out of the sizing helper.
    strings = b"\x00" + b"NetModule\x00"
    module_row = struct.pack("<HHHHH", 0, 1, 0, 0, 0)
    tables = _tables_stream([0x00, 0x35], [1, 1], module_row + b"\x00" * 4)
    meta, stream_map = _pack_meta(tables, strings)

    module_name, assembly_name, _stats = _parse_tables_and_names(meta, stream_map)

    assert module_name == "NetModule"
    assert assembly_name is None

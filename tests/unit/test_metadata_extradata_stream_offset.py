"""HeapSizes bit 0x40 (ExtraData) must be skipped before the first table row.

An uncompressed "#-" tables stream -- and obfuscated "#~" streams that set the
same flag to trip naive parsers -- places a 4-byte ExtraData value between the
row-count array and the first table row. If it is not skipped, ``cursor`` sits
four bytes early and Module/Assembly names are read from the ExtraData field
(and every enumerated table start is shifted). The blob below sets 0x40 and
wedges a 0xFFFFFFFF ExtraData word; the Module name resolves only when those four
bytes are skipped, otherwise the name index reads 0xFFFF and comes back None.
"""

from __future__ import annotations

from headless_re_mcp.dotnet.clr_inspect import _parse_tables_and_names


def _tables_with_extradata() -> bytes:
    # #~ header: reserved(4) + major(1) + minor(1) + HeapSizes(1) + reserved(1)
    # + Valid(8) + Sorted(8), then one 4-byte row count, then the ExtraData word,
    # then the Module row.
    header = (
        b"\x00" * 6
        + bytes([0x40])  # HeapSizes: ExtraData only (narrow string/guid indexes)
        + b"\x00"
        + (1).to_bytes(8, "little")  # Valid: only Module (bit 0)
        + b"\x00" * 8  # Sorted
    )
    row_counts = (1).to_bytes(4, "little")  # one Module row
    extra_data = (0xFFFFFFFF).to_bytes(4, "little")  # the 4 bytes that must be skipped
    # Module row (II.22.30): Generation(2) + Name(str,2) + Mvid/EncId/EncBaseId(guid,2 each).
    module_row = (
        (0).to_bytes(2, "little")  # Generation
        + (1).to_bytes(2, "little")  # Name -> #Strings index 1
        + b"\x00" * 6  # three 2-byte GUID indexes
    )
    return header + row_counts + extra_data + module_row


def test_module_name_is_read_after_skipping_the_extradata_word() -> None:
    tables = _tables_with_extradata()
    strings = b"\x00App.dll\x00"
    meta = tables + strings
    stream_map = {"#~": (0, len(tables)), "#Strings": (len(tables), len(strings))}

    module_name, assembly_name, stats = _parse_tables_and_names(meta, stream_map)

    # With the 4-byte skip the name index is 1 -> "App.dll"; without it the parser
    # reads the 0xFFFF from the ExtraData word and returns None.
    assert module_name == "App.dll"
    assert assembly_name is None
    assert stats is not None

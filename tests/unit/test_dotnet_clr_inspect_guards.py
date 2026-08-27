"""Metadata-root and table parsers of the CLR inspector, fed crafted blobs.

``test_dotnet_inspect.py`` builds whole PEs to exercise ``inspect_dotnet`` end to
end; the bit-level parsers underneath it -- the BSJB root walk, the ``#~`` table
row-count/name reader, kind classification and flag decoding -- keep their honesty
branches (a truncated root, a stream header that runs off the end, a name with no
terminator, a heap with no strings) untested that way. This drives those helpers
directly with hand-assembled metadata so each guard returns its tri-state ``None``
rather than reading past the buffer, and one well-formed blob proves the Module
and Assembly names and table row counts are read at the right offsets.
"""

from __future__ import annotations

import struct

from headless_re_mcp.dotnet.clr_inspect import (
    _FLAG_ILONLY,
    _FLAG_NATIVE_ENTRYPOINT,
    DotnetKind,
    MetadataStats,
    _classify_kind,
    _decode_flags,
    _parse_metadata_root,
    _parse_tables_and_names,
)

# A #Strings heap: index 0 is the empty string, then null-separated names.
# "Module.dll" starts at byte 1, "MyAssembly" at byte 12.
_STRINGS = b"\x00Module.dll\x00MyAssembly\x00"
_MODULE_NAME_INDEX = 1
_ASSEMBLY_NAME_INDEX = 12


def _tables_stream() -> bytes:
    """A minimal ``#~`` stream carrying one Module (0x00) and one Assembly (0x20)
    row, 2-byte heap indexes throughout (heap_sizes == 0)."""
    tables = bytearray(64)
    tables[4] = 2  # schema major
    tables[6] = 0  # heap_sizes: all heaps use 2-byte indexes
    tables[7] = 1  # reserved (conventionally 1)
    struct.pack_into("<Q", tables, 8, (1 << 0x00) | (1 << 0x20))  # valid bitmask
    # sorted bitmask at [16:24] stays zero.
    struct.pack_into("<II", tables, 24, 1, 1)  # row counts: Module=1, Assembly=1
    # Module row at 32: [gen u16][name u16][mvid/enc/encbase u16 x3].
    struct.pack_into("<H", tables, 34, _MODULE_NAME_INDEX)
    # Assembly row at 42: name string index sits 18 bytes in (see reader).
    struct.pack_into("<H", tables, 60, _ASSEMBLY_NAME_INDEX)
    return bytes(tables)


def _root(version: bytes, streams: list[tuple[str, bytes]]) -> bytes:
    """Assemble a BSJB metadata root with the given streams laid out after the
    stream headers, offsets recorded relative to the root start."""
    vlen = len(version)
    vpad = (vlen + 3) & ~3
    head = bytearray()
    head += b"BSJB"
    head += struct.pack("<HH", 1, 1)
    head += struct.pack("<I", 0)
    head += struct.pack("<I", vlen)
    head += version + b"\x00" * (vpad - vlen)
    head += struct.pack("<HH", 0, len(streams))

    def name_field(name: str) -> bytes:
        raw = name.encode("ascii") + b"\x00"
        pad = (len(raw) + 3) & ~3
        return raw + b"\x00" * (pad - len(raw))

    name_fields = [name_field(name) for name, _ in streams]
    headers_size = sum(8 + len(field) for field in name_fields)
    data_start = len(head) + headers_size

    body = bytearray()
    offsets: list[tuple[int, int]] = []
    cursor = data_start
    for (_name, data) in streams:
        offsets.append((cursor, len(data)))
        body += data
        cursor += len(data)

    for (offset, size), field in zip(offsets, name_fields, strict=True):
        head += struct.pack("<II", offset, size) + field
    return bytes(head) + bytes(body)


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------
def test_classify_kind_reads_verification_and_flags() -> None:
    assert _classify_kind(verified=False, flags=_FLAG_ILONLY) is DotnetKind.CLR_HINT
    assert _classify_kind(verified=True, flags=_FLAG_ILONLY) is DotnetKind.PURE_MANAGED
    assert _classify_kind(verified=True, flags=_FLAG_NATIVE_ENTRYPOINT) is DotnetKind.MIXED_MODE
    # Verified but not IL-only is still mixed mode (native code present).
    assert _classify_kind(verified=True, flags=0) is DotnetKind.MIXED_MODE


def test_decode_flags_names_each_set_bit_in_order() -> None:
    decoded = _decode_flags(_FLAG_ILONLY | _FLAG_NATIVE_ENTRYPOINT)
    assert decoded == ("ILONLY", "NATIVE_ENTRYPOINT")
    assert _decode_flags(0) == ()


def test_metadata_stats_to_dict_round_trips() -> None:
    stats = MetadataStats(type_count=3, method_count=7, field_count=2, resource_count=1)
    payload = stats.to_dict()
    assert payload["type_count"] == 3
    assert payload["method_count"] == 7
    assert payload["source"] == "metadata_tables"


# ---------------------------------------------------------------------------
# _parse_tables_and_names
# ---------------------------------------------------------------------------
def test_tables_reader_extracts_module_and_assembly_names() -> None:
    meta = _tables_stream() + _STRINGS
    stream_map = {"#~": (0, 64), "#Strings": (64, len(_STRINGS)), "#US": (0, 40)}
    module, assembly, stats = _parse_tables_and_names(meta, stream_map)
    assert module == "Module.dll"
    assert assembly == "MyAssembly"
    assert stats is not None
    assert stats.strings_heap_bytes == len(_STRINGS)
    assert stats.us_heap_bytes == 40


def test_tables_reader_without_a_tables_stream_is_null() -> None:
    assert _parse_tables_and_names(b"", {"#Strings": (0, 4)}) == (None, None, None)


def test_tables_reader_with_a_short_tables_header_is_null() -> None:
    stream_map = {"#~": (0, 8), "#Strings": (8, len(_STRINGS))}
    assert _parse_tables_and_names(b"\x00" * 8 + _STRINGS, stream_map) == (None, None, None)


def test_tables_reader_without_strings_returns_stats_only() -> None:
    tables = _tables_stream()
    module, assembly, stats = _parse_tables_and_names(tables, {"#~": (0, 64)})
    assert module is None
    assert assembly is None
    assert stats is not None
    assert stats.strings_heap_bytes is None


def test_tables_reader_stops_when_row_counts_run_off_the_end() -> None:
    # valid claims two tables but the stream ends before their row counts.
    tables = bytearray(28)
    struct.pack_into("<Q", tables, 8, (1 << 0) | (1 << 1))
    struct.pack_into("<I", tables, 24, 1)  # only one of the two counts fits
    module, assembly, stats = _parse_tables_and_names(bytes(tables), {"#~": (0, 28)})
    assert (module, assembly, stats) == (None, None, None)


def test_tables_reader_stops_at_an_unhandled_table() -> None:
    # A TypeDef (0x02) row is neither Module nor Assembly; the name walk stops
    # there but the row count is still reported in the stats.
    tables = bytearray(64)
    tables[7] = 1
    struct.pack_into("<Q", tables, 8, 1 << 0x02)
    struct.pack_into("<I", tables, 24, 1)
    meta = bytes(tables) + _STRINGS
    module, assembly, stats = _parse_tables_and_names(
        meta, {"#~": (0, 64), "#Strings": (64, len(_STRINGS))}
    )
    assert module is None
    assert assembly is None
    assert stats is not None
    assert stats.type_count == 1


# ---------------------------------------------------------------------------
# _parse_metadata_root
# ---------------------------------------------------------------------------
def test_root_too_short_is_null() -> None:
    assert _parse_metadata_root(b"BSJB") == (None, [], None, None, None)


def test_root_with_an_impossible_version_length_is_null() -> None:
    blob = b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0) + struct.pack("<I", 4096)
    assert _parse_metadata_root(blob + b"\x00" * 8) == (None, [], None, None, None)


def test_root_truncated_after_version_returns_version_only() -> None:
    version = b"v4\x00\x00"
    blob = b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0)
    blob += struct.pack("<I", len(version)) + version  # nothing after the version block
    parsed = _parse_metadata_root(blob)
    assert parsed[0] == "v4"
    assert parsed[1] == []


def test_root_with_a_stream_header_off_the_end_stops() -> None:
    version = b"v4\x00\x00"
    blob = bytearray(b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0))
    blob += struct.pack("<I", len(version)) + version
    blob += struct.pack("<HH", 0, 1)  # claims one stream, but no header bytes follow
    parsed = _parse_metadata_root(bytes(blob))
    assert parsed[1] == []


def test_root_with_an_unterminated_stream_name_stops() -> None:
    version = b"v4XX"  # deliberately no terminator; parsed as-is
    blob = bytearray(b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0))
    blob += struct.pack("<I", len(version)) + version
    blob += struct.pack("<HH", 0, 1)  # one stream
    blob += struct.pack("<II", 0, 0)  # its offset/size
    blob += b"ABCD"  # a name with no null before the buffer ends
    parsed = _parse_metadata_root(bytes(blob))
    assert parsed[1] == []


def test_root_with_a_full_stream_table_reads_names_and_stats() -> None:
    root = _root(b"v4.0.30319\x00", [("#~", _tables_stream()), ("#Strings", _STRINGS)])
    version, streams, module, assembly, stats = _parse_metadata_root(root)
    assert version == "v4.0.30319"
    assert streams == ["#~", "#Strings"]
    assert module == "Module.dll"
    assert assembly == "MyAssembly"
    assert stats is not None
    # Only Module and Assembly tables are declared, so TypeDef/Method counts are
    # absent (null) rather than zero -- the reader reports what the blob carries.
    assert stats.type_count is None
    assert stats.strings_heap_bytes == len(_STRINGS)

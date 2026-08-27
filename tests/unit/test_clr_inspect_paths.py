"""Guard and parser-body coverage for the bounded CLR inspector.

The inspector walks attacker-controlled stream headers, table row counts and
heap offsets out of a file nobody trusts. The existing hostile-input suite
needs a real managed assembly on disk and skips without one; these tests build
the BSJB metadata by hand so the parser bodies -- module/assembly name lookup,
the stream and table guards, and the CLR-header downgrade arms -- run without
any external fixture.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet import clr_inspect
from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    DotnetInspectReport,
    DotnetKind,
    MetadataStats,
    _classify_kind,
    _decode_flags,
    _parse_metadata_root,
    inspect_dotnet,
)

# --------------------------------------------------------------------------
# In-memory BSJB metadata builders (no PE, no disk).
# --------------------------------------------------------------------------


def _tilde(entries: list[tuple[int, int, bytes]], *, heap_sizes: int = 0) -> bytes:
    """A #~ tables stream: 24-byte header, row-count array, then row data."""
    entries = sorted(entries)
    valid = 0
    for table_id, _count, _data in entries:
        valid |= 1 << table_id
    header = bytearray(24)
    header[4] = 2  # major
    header[5] = 0  # minor
    header[6] = heap_sizes
    struct.pack_into("<Q", header, 8, valid)
    struct.pack_into("<Q", header, 16, 0)  # sorted mask (unused here)
    body = bytearray()
    for _table_id, count, _data in entries:
        body += struct.pack("<I", count)
    for _table_id, _count, data in entries:
        body += data
    return bytes(header) + bytes(body)


def _meta_blob(streams: list[tuple[str, bytes]], *, version: bytes = b"v4.0.30319\0") -> bytes:
    """A BSJB metadata root with the given named streams appended after it."""
    version_padded = version + b"\0" * ((-len(version)) % 4)
    root = bytearray()
    root += b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0)
    root += struct.pack("<I", len(version)) + version_padded
    root += struct.pack("<HH", 0, len(streams))  # flags, stream count

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


def _module_row(name_idx: int, *, index_size: int = 2) -> bytes:
    packer = "<I" if index_size == 4 else "<H"
    return struct.pack("<H", 0) + struct.pack(packer, name_idx) + b"\0" * 6


def _assembly_row(name_idx: int) -> bytes:
    return (
        struct.pack("<I", 0)  # HashAlgId
        + struct.pack("<HHHH", 1, 2, 3, 4)  # version quad
        + struct.pack("<I", 0)  # Flags
        + struct.pack("<H", 0)  # PublicKey blob index
        + struct.pack("<H", name_idx)  # Name string index
        + struct.pack("<H", 0)  # Culture string index
    )


# --------------------------------------------------------------------------
# Minimal verified managed PE (empty metadata tables) for inspect_dotnet arms.
# --------------------------------------------------------------------------


class _ManagedPe:
    """A minimal PE32+ image with a readable COR20 header + BSJB metadata."""

    COM_DIR_SIZE = 0x17C  # data directory[14].Size
    COR20_META_RVA = 0x308  # COR20 header MetaData RVA field
    COR20_FLAGS = 0x310  # COR20 header Flags field

    def __init__(self) -> None:
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
        struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
        section = optional + 0xF0
        image[section : section + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
        struct.pack_into("<I", image, section + 36, 0x60000020)
        cor_off = 0x300
        struct.pack_into("<I", image, cor_off, 72)
        struct.pack_into("<HH", image, cor_off + 4, 2, 5)
        struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
        struct.pack_into("<I", image, cor_off + 16, 0x1)
        struct.pack_into("<I", image, cor_off + 20, 0x06000001)
        meta_off = 0x400
        version = b"v4.0.30319\0"
        version_padded = version + b"\0" * ((-len(version)) % 4)
        image[meta_off : meta_off + 4] = b"BSJB"
        struct.pack_into("<HH", image, meta_off + 4, 1, 1)
        struct.pack_into("<I", image, meta_off + 8, 0)
        struct.pack_into("<I", image, meta_off + 12, len(version))
        image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
        cursor = meta_off + 16 + len(version_padded)
        struct.pack_into("<HH", image, cursor, 0, 0)
        self._image = image

    def patch32(self, offset: int, value: int) -> _ManagedPe:
        struct.pack_into("<I", self._image, offset, value)
        return self

    def write(self, path: Path) -> Path:
        path.write_bytes(bytes(self._image))
        return path


# --------------------------------------------------------------------------
# _parse_metadata_root: root/stream guards.
# --------------------------------------------------------------------------


def test_parse_metadata_root_rejects_short_or_unsigned_blob() -> None:
    assert _parse_metadata_root(b"BSJB" + b"\0" * 5) == (None, [], None, None, None)
    assert _parse_metadata_root(b"XXXX" + b"\0" * 20) == (None, [], None, None, None)


def test_parse_metadata_root_rejects_impossible_version_length() -> None:
    blob = b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0) + struct.pack("<I", 0x7FFFFFFF)
    assert _parse_metadata_root(blob) == (None, [], None, None, None)


def test_parse_metadata_root_stops_when_stream_table_is_missing() -> None:
    blob = (
        b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0) + struct.pack("<I", 4) + b"ABCD"
    )
    version, streams, module, assembly, stats = _parse_metadata_root(blob)
    assert version == "ABCD"
    assert streams == []
    assert (module, assembly, stats) == (None, None, None)


def test_parse_metadata_root_stops_on_truncated_stream_header() -> None:
    blob = (
        b"BSJB"
        + struct.pack("<HH", 1, 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 4)
        + b"ABCD"
        + struct.pack("<HH", 0, 1)  # flags, one declared stream, but no header bytes
    )
    version, streams, *_rest = _parse_metadata_root(blob)
    assert version == "ABCD"
    assert streams == []


def test_parse_metadata_root_stops_on_unterminated_stream_name() -> None:
    blob = (
        b"BSJB"
        + struct.pack("<HH", 1, 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 4)
        + b"ABCD"
        + struct.pack("<HH", 0, 1)
        + struct.pack("<II", 0, 0)  # stream offset/size
        + b"\xff\xff\xff\xff"  # name with no NUL terminator
    )
    version, streams, *_rest = _parse_metadata_root(blob)
    assert version == "ABCD"
    assert streams == []


# --------------------------------------------------------------------------
# _parse_metadata_root -> _parse_tables_and_names: module/assembly bodies.
# --------------------------------------------------------------------------


def test_module_and_assembly_names_are_recovered() -> None:
    strings = b"\0" + b"MyModule\0" + b"MyAssembly\0"
    module_idx = 1
    assembly_idx = 1 + len(b"MyModule\0")
    tilde = _tilde(
        [(0x00, 1, _module_row(module_idx)), (0x20, 1, _assembly_row(assembly_idx))]
    )
    blob = _meta_blob([("#~", tilde), ("#Strings", strings)])

    version, streams, module_name, assembly_name, stats = _parse_metadata_root(blob)

    assert version == "v4.0.30319"
    assert streams == ["#~", "#Strings"]
    assert module_name == "MyModule"
    assert assembly_name == "MyAssembly"
    assert stats is not None
    assert stats.source == "metadata_tables"


def test_four_byte_string_indexes_are_read() -> None:
    strings = b"\0" + b"WideModule\0"
    tilde = _tilde([(0x00, 1, _module_row(1, index_size=4))], heap_sizes=0x01)
    blob = _meta_blob([("#~", tilde), ("#Strings", strings)])

    _version, _streams, module_name, _assembly, stats = _parse_metadata_root(blob)

    assert module_name == "WideModule"
    assert stats is not None


def test_tables_without_a_strings_heap_yield_no_names() -> None:
    tilde = _tilde([(0x00, 1, _module_row(1))])
    blob = _meta_blob([("#~", tilde)])

    _version, streams, module_name, assembly_name, stats = _parse_metadata_root(blob)

    assert streams == ["#~"]
    assert module_name is None
    assert assembly_name is None
    assert stats is not None  # row counts are still summarised


def test_module_name_index_out_of_range_yields_none() -> None:
    tilde = _tilde([(0x00, 1, _module_row(50))])  # index points past the heap
    blob = _meta_blob([("#~", tilde), ("#Strings", b"\0MyModule\0")])

    _version, _streams, module_name, _assembly, stats = _parse_metadata_root(blob)

    assert module_name is None
    assert stats is not None


def test_unterminated_final_string_is_read_to_the_heap_end() -> None:
    strings = b"\0Unterminated"  # no trailing NUL
    tilde = _tilde([(0x00, 1, _module_row(1))])
    blob = _meta_blob([("#~", tilde), ("#Strings", strings)])

    _version, _streams, module_name, _assembly, _stats = _parse_metadata_root(blob)

    assert module_name == "Unterminated"


def test_table_walk_stops_at_the_first_unhandled_table() -> None:
    # Module is parsed, then a TypeDef row stops the name walk before Assembly.
    typedef_row = struct.pack("<I", 0) + struct.pack("<HHHHH", 1, 0, 0, 1, 1)
    tilde = _tilde(
        [
            (0x00, 1, _module_row(1)),
            (0x02, 1, typedef_row),
            (0x20, 1, _assembly_row(1)),
        ]
    )
    blob = _meta_blob([("#~", tilde), ("#Strings", b"\0Only\0")])

    _version, _streams, module_name, assembly_name, _stats = _parse_metadata_root(blob)

    assert module_name == "Only"
    assert assembly_name is None  # the walk broke at TypeDef, never reaching Assembly


def test_us_heap_size_is_summarised_when_present() -> None:
    tilde = _tilde([(0x00, 1, _module_row(1))])
    blob = _meta_blob([("#~", tilde), ("#Strings", b"\0Mod\0"), ("#US", b"\0\0\0\0\0\0")])

    _version, _streams, _module, _assembly, stats = _parse_metadata_root(blob)

    assert stats is not None
    assert stats.us_heap_bytes == 6


def test_tables_stream_shorter_than_its_header_is_rejected() -> None:
    blob = _meta_blob([("#~", b"\0" * 10)])
    assert _parse_metadata_root(blob)[2:] == (None, None, None)


def test_tables_stream_too_short_for_declared_row_counts() -> None:
    # valid declares Module + TypeDef but the stream ends after the header.
    header = bytearray(24)
    header[4] = 2
    struct.pack_into("<Q", header, 8, (1 << 0x00) | (1 << 0x02))
    blob = _meta_blob([("#~", bytes(header))])
    assert _parse_metadata_root(blob)[2:] == (None, None, None)


def test_name_parsing_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    strings = b"\0" + b"MyModule\0"
    tilde = _tilde([(0x00, 1, _module_row(1))])
    blob = _meta_blob([("#~", tilde), ("#Strings", strings)])

    def _boom(_meta: bytes, _stream_map: dict[str, tuple[int, int]]) -> object:
        raise ValueError("crafted table walk failure")

    monkeypatch.setattr(clr_inspect, "_parse_tables_and_names", _boom)

    version, streams, module_name, assembly_name, stats = _parse_metadata_root(blob)

    assert streams == ["#~", "#Strings"]  # stream headers still parsed
    assert (module_name, assembly_name, stats) == (None, None, None)


# --------------------------------------------------------------------------
# _classify_kind / _decode_flags / dataclass serialisation.
# --------------------------------------------------------------------------


def test_classify_kind_covers_each_arm() -> None:
    assert _classify_kind(verified=False, flags=0x1) is DotnetKind.CLR_HINT
    assert _classify_kind(verified=True, flags=0x10) is DotnetKind.MIXED_MODE
    assert _classify_kind(verified=True, flags=0x0) is DotnetKind.MIXED_MODE
    assert _classify_kind(verified=True, flags=0x1) is DotnetKind.PURE_MANAGED


def test_decode_flags_lists_every_known_bit() -> None:
    decoded = _decode_flags(0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20000)
    assert decoded == (
        "ILONLY",
        "32BITREQUIRED",
        "IL_LIBRARY",
        "STRONGNAMESIGNED",
        "NATIVE_ENTRYPOINT",
        "32BITPREFERRED",
    )


def test_metadata_stats_and_report_serialise_with_stats() -> None:
    stats = MetadataStats(
        type_count=3,
        method_count=7,
        field_count=2,
        resource_count=1,
        strings_heap_bytes=64,
        us_heap_bytes=8,
    )
    stats_dict = stats.to_dict()
    assert stats_dict["type_count"] == 3
    assert stats_dict["source"] == "metadata_tables"

    report = DotnetInspectReport(
        path="x.dll",
        sha256="0" * 64,
        architecture="x64",
        is_dotnet=True,
        kind=DotnetKind.PURE_MANAGED,
        verified_clr=True,
        runtime_major=2,
        runtime_minor=5,
        metadata_version="v4.0.30319",
        entry_point_token=0x06000001,
        flags=0x1,
        flags_decoded=("ILONLY",),
        streams=("#~", "#Strings"),
        module_name="mod",
        assembly_name="asm",
        note="verified",
        metadata_stats=stats,
    )
    report_dict = report.to_dict()
    assert report_dict["metadata_stats"] == stats_dict
    assert report_dict["claims_universal_unpack"] is False


# --------------------------------------------------------------------------
# inspect_dotnet: PE-level downgrade / verification arms.
# --------------------------------------------------------------------------


def test_inspect_reports_mixed_mode_for_non_ilonly_flags(tmp_path: Path) -> None:
    binary = _ManagedPe().patch32(_ManagedPe.COR20_FLAGS, 0x0).write(tmp_path / "mixed.dll")

    report = inspect_dotnet(binary)

    assert report.is_dotnet is True
    assert report.verified_clr is True
    assert report.kind is DotnetKind.MIXED_MODE


def test_inspect_downgrades_when_cor20_header_is_unreadable(tmp_path: Path) -> None:
    # An oversized COM directory makes the COR20 header slice fall off the section.
    binary = _ManagedPe().patch32(_ManagedPe.COM_DIR_SIZE, 0x5000).write(tmp_path / "hint.dll")

    report = inspect_dotnet(binary)

    assert report.is_dotnet is True
    assert report.verified_clr is False
    assert report.kind is DotnetKind.CLR_HINT
    assert "COR20 header unreadable" in report.note

    with pytest.raises(DotnetInspectError) as caught:
        inspect_dotnet(binary, require_verified=True)
    assert caught.value.code == "clr_unverified"


def test_inspect_notes_metadata_rva_that_does_not_map(tmp_path: Path) -> None:
    binary = _ManagedPe().patch32(_ManagedPe.COR20_META_RVA, 0x99999).write(tmp_path / "nomap.dll")

    report = inspect_dotnet(binary)

    assert report.verified_clr is False
    assert report.note == "COR20 MetaData RVA not mappable"

    with pytest.raises(DotnetInspectError):
        inspect_dotnet(binary, require_verified=True)


def test_inspect_notes_metadata_rva_that_is_not_bsjb(tmp_path: Path) -> None:
    binary = _ManagedPe().patch32(_ManagedPe.COR20_META_RVA, 0x1000).write(tmp_path / "notbsjb.dll")

    report = inspect_dotnet(binary)

    assert report.verified_clr is False
    assert report.note == "COR20 MetaData RVA does not point at BSJB"


def test_inspect_flags_a_plain_pe_as_not_dotnet(tmp_path: Path) -> None:
    binary = _ManagedPe().patch32(0x178, 0).patch32(_ManagedPe.COM_DIR_SIZE, 0).write(
        tmp_path / "plain.dll"
    )

    report = inspect_dotnet(binary)

    assert report.is_dotnet is False
    assert report.kind is DotnetKind.NOT_DOTNET

    with pytest.raises(DotnetInspectError) as caught:
        inspect_dotnet(binary, require_verified=True)
    assert caught.value.code == "not_dotnet"

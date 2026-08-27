"""Direct coverage for the CLR metadata-root parser and #~ table walker.

The hostile-input suite in ``test_clr_hostile_input.py`` needs a real managed
assembly to mutate and is skipped wherever that fixture is absent, so the code
that walks attacker-controlled stream headers, table row counts and heap
indexes normally runs untested. These tests craft BSJB metadata by hand so the
parser is exercised without a fixture: a well-formed image must yield the module
and assembly names, and every truncated or inconsistent shape must degrade to a
quiet ``None`` rather than an exception or a confident-but-wrong report.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet import clr_inspect
from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    DotnetKind,
    MetadataStats,
    inspect_dotnet,
)

MODULE_NAME = "MyModule.dll"
ASSEMBLY_NAME = "MyAssembly"


def _build_metadata(*, wide_indexes: bool = False, extra_table_bit: int | None = None) -> bytes:
    """A BSJB root with a #~ tables stream (Module + Assembly) and a #Strings heap.

    ``wide_indexes`` sets the heap-size flags so string/GUID/blob indexes are
    four bytes instead of two. ``extra_table_bit`` inserts one more present
    table between Module (0x00) and Assembly (0x20) to force the walker's early
    ``break`` on an unexpected table.
    """
    heap_sizes = (0x01 | 0x02 | 0x04) if wide_indexes else 0
    wide = wide_indexes

    strings = b"\0" + MODULE_NAME.encode() + b"\0" + ASSEMBLY_NAME.encode() + b"\0"
    idx_module = 1
    idx_assembly = 1 + len(MODULE_NAME.encode()) + 1

    valid = (1 << 0x00) | (1 << 0x20)
    present_bits = [0x00, 0x20]
    if extra_table_bit is not None:
        valid |= 1 << extra_table_bit
        present_bits = sorted({*present_bits, extra_table_bit})

    def stridx(value: int) -> bytes:
        return struct.pack("<I", value) if wide else struct.pack("<H", value)

    def guid(value: int = 0) -> bytes:
        return struct.pack("<I", value) if wide else struct.pack("<H", value)

    def blob(value: int = 0) -> bytes:
        return struct.pack("<I", value) if wide else struct.pack("<H", value)

    tilde = bytearray()
    tilde += b"\0\0\0\0"  # reserved
    tilde += bytes([2, 0])  # schema major/minor
    tilde += bytes([heap_sizes])
    tilde += b"\0"  # reserved
    tilde += struct.pack("<Q", valid)
    tilde += struct.pack("<Q", 0)  # sorted
    for _ in present_bits:
        tilde += struct.pack("<I", 1)  # one row per present table
    for bit in present_bits:
        if bit == 0x00:  # Module: Generation, Name, Mvid, EncId, EncBaseId
            tilde += struct.pack("<H", 0) + stridx(idx_module) + guid() + guid() + guid()
        elif bit == 0x20:  # Assembly
            tilde += struct.pack("<I", 0x8004)  # HashAlgId
            tilde += struct.pack("<HHHH", 1, 0, 0, 0)  # version quad
            tilde += struct.pack("<I", 0)  # flags
            tilde += blob()  # PublicKey
            tilde += stridx(idx_assembly)  # Name
            tilde += stridx(0)  # Culture
        else:  # an unexpected table row the walker refuses to interpret
            tilde += b"\0\0\0\0"
    tilde_bytes = bytes(tilde)

    version = b"v4.0.30319\0"
    version_len = (len(version) + 3) & ~3
    version_block = version + b"\0" * (version_len - len(version))

    def name_block(name: str) -> bytes:
        raw = name.encode() + b"\0"
        pad = (len(raw) + 3) & ~3
        return raw + b"\0" * (pad - len(raw))

    tilde_name = name_block("#~")
    strings_name = name_block("#Strings")

    head = bytearray()
    head += b"BSJB"
    head += struct.pack("<HH", 1, 1)
    head += struct.pack("<I", 0)  # reserved
    head += struct.pack("<I", version_len)
    head += version_block
    head += struct.pack("<HH", 0, 2)  # flags, stream_count

    header_len = len(head) + (8 + len(tilde_name)) + (8 + len(strings_name))
    off_tilde = header_len
    off_strings = off_tilde + len(tilde_bytes)
    head += struct.pack("<II", off_tilde, len(tilde_bytes)) + tilde_name
    head += struct.pack("<II", off_strings, len(strings)) + strings_name

    return bytes(head) + tilde_bytes + strings


def _build_clr_pe(
    *,
    com_rva: int = 0x1100,
    com_size: int = 72,
    meta_rva: int = 0x1200,
    meta_size: int = 0x40,
    meta_sig: bytes = b"BSJB",
    cor_flags: int = 0x1,
    metadata_blob: bytes | None = None,
) -> bytes:
    """A minimal 64-bit PE carrying a COR20 header and a metadata region."""
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
    # COR20 header at file 0x300 / RVA 0x1100
    cor = 0x300
    struct.pack_into("<I", image, cor, 72)  # cb
    struct.pack_into("<HH", image, cor + 4, 2, 5)  # runtime 2.5
    struct.pack_into("<II", image, cor + 8, meta_rva, meta_size)
    struct.pack_into("<I", image, cor + 16, cor_flags)
    struct.pack_into("<I", image, cor + 20, 0x06000001)  # entry token
    # Metadata region at file 0x400 / RVA 0x1200
    meta_off = 0x400
    if metadata_blob is not None:
        image[meta_off : meta_off + len(metadata_blob)] = metadata_blob
    else:
        image[meta_off : meta_off + 4] = meta_sig
        version = b"v4.0.30319\0"
        version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
        struct.pack_into("<HH", image, meta_off + 4, 1, 1)
        struct.pack_into("<I", image, meta_off + 8, 0)
        struct.pack_into("<I", image, meta_off + 12, len(version))
        image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
        struct.pack_into("<HH", image, meta_off + 16 + len(version_padded), 0, 0)
    return bytes(image)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    return path


# --- metadata-root parser: the happy path yields real names -----------------


@pytest.mark.parametrize("wide", [False, True], ids=["narrow-index", "wide-index"])
def test_metadata_root_reads_module_and_assembly_names(wide: bool) -> None:
    """Both 2- and 4-byte heap indexes must resolve the Module and Assembly rows.

    The heap-size flags choose the index width for every table; a parser that
    hard-codes one width silently reads the wrong bytes on the other.
    """
    version, streams, module_name, assembly_name, stats = clr_inspect._parse_metadata_root(
        _build_metadata(wide_indexes=wide)
    )

    assert version == "v4.0.30319"
    assert streams == ["#~", "#Strings"]
    assert module_name == MODULE_NAME
    assert assembly_name == ASSEMBLY_NAME
    assert isinstance(stats, MetadataStats)
    assert stats.strings_heap_bytes is not None


def test_metadata_root_stops_at_an_unexpected_table() -> None:
    """A table between Module and Assembly halts the walk without guessing.

    The walker only understands Module (0x00) and Assembly (0x20); any other
    present table means row sizes it cannot compute, so it must stop rather than
    stride blindly into the wrong offset and report a bogus assembly name.
    """
    _, _, module_name, assembly_name, stats = clr_inspect._parse_metadata_root(
        _build_metadata(extra_table_bit=0x02)  # TypeDef sits before Assembly
    )

    assert module_name == MODULE_NAME
    assert assembly_name is None
    assert stats is not None
    assert stats.type_count == 1


@pytest.mark.parametrize(
    "blob",
    [b"XXXX", b"XXXX" + b"\0" * 20],
    ids=["too-short", "wrong-signature"],
)
def test_metadata_root_rejects_non_bsjb(blob: bytes) -> None:
    assert clr_inspect._parse_metadata_root(blob) == (None, [], None, None, None)


def test_metadata_root_rejects_version_length_past_end() -> None:
    """A version length that runs off the buffer must not read out of bounds."""
    blob = b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0) + struct.pack("<I", 9999)
    assert clr_inspect._parse_metadata_root(blob) == (None, [], None, None, None)


def test_metadata_root_truncated_before_stream_count() -> None:
    """When the buffer ends right after the version, no streams can be read."""
    blob = b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0) + struct.pack("<I", 0)
    version, streams, module_name, assembly_name, stats = clr_inspect._parse_metadata_root(blob)
    assert version == ""
    assert streams == []
    assert (module_name, assembly_name, stats) == (None, None, None)


def _root_with_streams(flags_count: bytes, stream_bytes: bytes) -> bytes:
    version_block = b"v1\0\0"
    return (
        b"BSJB"
        + struct.pack("<HH", 1, 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", len(version_block))
        + version_block
        + flags_count
        + stream_bytes
    )


def test_metadata_root_stops_when_a_stream_header_is_truncated() -> None:
    """A declared stream with no header bytes must end the loop, not overrun."""
    blob = _root_with_streams(struct.pack("<HH", 0, 1), b"")
    assert clr_inspect._parse_metadata_root(blob)[1] == []


def test_metadata_root_stops_when_a_stream_name_is_unterminated() -> None:
    """A stream name that never hits a NUL cannot be measured, so the walk ends."""
    stream = struct.pack("<II", 100, 4) + b"#~noNull"
    blob = _root_with_streams(struct.pack("<HH", 0, 1), stream)
    assert clr_inspect._parse_metadata_root(blob)[1] == []


# --- table walker: inconsistent shapes degrade quietly ----------------------


def test_table_walker_without_a_tables_stream_returns_nothing() -> None:
    assert clr_inspect._parse_tables_and_names(b"", {}) == (None, None, None)


def test_table_walker_rejects_a_tables_header_that_is_too_small() -> None:
    """A #~ stream shorter than the fixed header cannot hold valid data."""
    assert clr_inspect._parse_tables_and_names(b"\0" * 40, {"#~": (0, 10)}) == (None, None, None)


def test_table_walker_rejects_row_counts_running_past_the_stream() -> None:
    """A ``valid`` bit claims a row count that the stream is too short to hold."""
    tables = bytearray(24)
    struct.pack_into("<Q", tables, 8, 1 << 0)  # Module present, but no room for its count
    assert clr_inspect._parse_tables_and_names(bytes(tables), {"#~": (0, 24)}) == (
        None,
        None,
        None,
    )


def _module_only_meta(name_index: int, strings: bytes) -> tuple[bytes, dict[str, tuple[int, int]]]:
    """A #~ stream with a single Module row plus a #Strings heap after it."""
    tables = bytearray(28)
    struct.pack_into("<Q", tables, 8, 1 << 0)  # Module present, 2-byte indexes
    struct.pack_into("<I", tables, 24, 1)  # one Module row
    row = struct.pack("<HHHHH", 0, name_index, 0, 0, 0)  # Gen, Name, Mvid, EncId, EncBaseId
    tables += row
    meta = bytes(tables) + strings
    return meta, {"#~": (0, len(tables)), "#Strings": (len(tables), len(strings))}


def test_table_walker_ignores_an_out_of_range_name_index() -> None:
    """A Module name index past the heap must resolve to no name, not an overrun."""
    meta, stream_map = _module_only_meta(999, b"\0hello\0")
    module_name, _, stats = clr_inspect._parse_tables_and_names(meta, stream_map)
    assert module_name is None
    assert stats is not None


def test_table_walker_reads_a_name_that_runs_to_the_heap_end() -> None:
    """A name with no trailing NUL is taken to the end of the #Strings heap."""
    meta, stream_map = _module_only_meta(1, b"\0abc")
    module_name, _, _ = clr_inspect._parse_tables_and_names(meta, stream_map)
    assert module_name == "abc"


def test_table_walker_without_strings_returns_stats_but_no_names() -> None:
    """Row counts still produce stats even when there is no #Strings heap to name from."""
    tables = bytearray(28)
    struct.pack_into("<Q", tables, 8, 1 << 0)  # Module present
    struct.pack_into("<I", tables, 24, 1)  # one Module row
    module_name, assembly_name, stats = clr_inspect._parse_tables_and_names(
        bytes(tables), {"#~": (0, 28)}
    )
    assert module_name is None
    assert assembly_name is None
    assert stats is not None
    assert stats.strings_heap_bytes is None


# --- inspect_dotnet: header-level branches over synthetic images ------------


def test_inspect_reports_mixed_mode_for_a_native_entrypoint(tmp_path: Path) -> None:
    """A verified image whose flags lack ILONLY / carry NATIVE_ENTRYPOINT is mixed mode."""
    report = inspect_dotnet(_write(tmp_path, _build_clr_pe(cor_flags=0x10)))
    assert report.verified_clr is True
    assert report.kind is DotnetKind.MIXED_MODE
    assert "NATIVE_ENTRYPOINT" in report.flags_decoded


def test_inspect_metadata_rva_not_pointing_at_bsjb_is_unverified(tmp_path: Path) -> None:
    """A COR20 metadata pointer that lands on non-BSJB bytes must not verify."""
    report = inspect_dotnet(_write(tmp_path, _build_clr_pe(meta_sig=b"XXXX")))
    assert report.verified_clr is False
    assert report.kind is DotnetKind.CLR_HINT
    assert "does not point at BSJB" in report.note


def test_inspect_unmappable_metadata_rva_is_refused(tmp_path: Path) -> None:
    """A metadata RVA that maps nowhere downgrades and blocks external tools."""
    path = _write(tmp_path, _build_clr_pe(meta_rva=0x7FFFFFFF))
    report = inspect_dotnet(path)
    assert report.verified_clr is False
    assert "not mappable" in report.note
    with pytest.raises(DotnetInspectError) as caught:
        inspect_dotnet(path, require_verified=True)
    assert caught.value.code == "clr_unverified"


def test_inspect_unreadable_cor20_header_is_a_hint_only(tmp_path: Path) -> None:
    """A COM directory whose header cannot be sliced is a hint, never verified."""
    path = _write(tmp_path, _build_clr_pe(com_rva=0x7FFFFFFF))
    report = inspect_dotnet(path)
    assert report.is_dotnet is True
    assert report.verified_clr is False
    assert report.kind is DotnetKind.CLR_HINT
    assert "COR20 header unreadable" in report.note
    with pytest.raises(DotnetInspectError) as caught:
        inspect_dotnet(path, require_verified=True)
    assert caught.value.code == "clr_unverified"


def test_inspect_full_metadata_reports_names_and_stats(tmp_path: Path) -> None:
    """End to end: a crafted BSJB blob surfaces module/assembly names and stats."""
    blob = _build_metadata()
    path = _write(tmp_path, _build_clr_pe(meta_size=len(blob), metadata_blob=blob))
    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.kind is DotnetKind.PURE_MANAGED
    assert report.module_name == MODULE_NAME
    assert report.assembly_name == ASSEMBLY_NAME
    assert report.metadata_stats is not None
    payload = report.to_dict()
    assert payload["metadata_stats"]["source"] == "metadata_tables"
    assert payload["module_name"] == MODULE_NAME

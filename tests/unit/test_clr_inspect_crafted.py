"""Hostile CLR headers must degrade to a hint, never a confident report -- and
this must hold on every platform, not only where a managed assembly happens to
sit on disk.

``test_clr_hostile_input.py`` mutates a real ``.dll`` and is skipped wherever
that fixture is absent (all of CI). These build a minimal PE from raw bytes so
the same fail-closed paths -- an unmappable CLR directory, a COR20 MetaData RVA
that points at the wrong place or nowhere, mixed-mode flags -- are exercised
with no fixture. The metadata-root parser is also driven directly across its
truncation branches, since a mangled ``BSJB`` block is exactly attacker input.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    DotnetKind,
    _parse_metadata_root,
    inspect_dotnet,
)


def _build_clr_pe(
    *,
    com_rva: int = 0x1100,
    com_size: int = 72,
    meta_rva: int = 0x1200,
    cor_flags: int = 0x1,
    write_bsjb: bool = True,
) -> bytes:
    """A minimal PE32+ carrying a COR20 header, with knobs for the error paths.

    Defaults produce a verified pure-managed image (COR20 + BSJB in .text);
    the RVA/flag knobs let a caller point the CLR directory or MetaData RVA at
    unmappable or wrong locations to drive the fail-closed branches.
    """
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
    # Data directory 14 is the COM descriptor (CLI header).
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, com_rva, com_size)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    # VirtualSize, VirtualAddress=0x1000, SizeOfRawData, PointerToRawData=0x200.
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    # COR20 at file 0x300 (RVA 0x1100).
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)  # cb
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)  # runtime 2.5
    struct.pack_into("<II", image, cor_off + 8, meta_rva, 0x40)  # metadata rva/size
    struct.pack_into("<I", image, cor_off + 16, cor_flags)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)  # entry token

    if write_bsjb:
        # BSJB metadata root at file 0x400 (RVA 0x1200).
        meta_off = 0x400
        version = b"v4.0.30319\0"
        version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
        image[meta_off : meta_off + 4] = b"BSJB"
        struct.pack_into("<HH", image, meta_off + 4, 1, 1)
        struct.pack_into("<I", image, meta_off + 8, 0)
        struct.pack_into("<I", image, meta_off + 12, len(version))
        image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
        cursor = meta_off + 16 + len(version_padded)
        struct.pack_into("<HH", image, cursor, 0, 0)  # flags + 0 streams
    return bytes(image)


def _write(tmp_path: Path, name: str, **kwargs: object) -> Path:
    path = tmp_path / name
    path.write_bytes(_build_clr_pe(**kwargs))  # type: ignore[arg-type]
    return path


def test_unmappable_clr_directory_is_a_hint_not_a_verified_image(tmp_path: Path) -> None:
    # COM descriptor present but its RVA maps into no section: the COR20 header
    # is unreadable, so the image is a hint only, never verified.
    path = _write(tmp_path, "com.exe", com_rva=0x9000)
    report = inspect_dotnet(path)
    assert report.is_dotnet is True
    assert report.kind is DotnetKind.CLR_HINT
    assert report.verified_clr is False
    assert "unreadable" in report.note

    # And the external-tools gate refuses it rather than proceeding on a hint.
    with pytest.raises(DotnetInspectError) as caught:
        inspect_dotnet(path, require_verified=True)
    assert caught.value.code == "clr_unverified"


def test_metadata_rva_pointing_at_non_bsjb_stays_unverified(tmp_path: Path) -> None:
    # COR20 readable, but its MetaData RVA points at bytes that are not BSJB.
    path = _write(tmp_path, "notbsjb.exe", meta_rva=0x1000)
    report = inspect_dotnet(path)
    assert report.verified_clr is False
    assert report.kind is DotnetKind.CLR_HINT
    assert "does not point at BSJB" in report.note


def test_metadata_rva_that_is_unmappable_stays_unverified(tmp_path: Path) -> None:
    # COR20 readable, MetaData RVA maps nowhere: reported, not crashed.
    path = _write(tmp_path, "metabad.exe", meta_rva=0x9000)
    report = inspect_dotnet(path)
    assert report.verified_clr is False
    assert report.kind is DotnetKind.CLR_HINT
    assert "not mappable" in report.note


def test_verified_image_without_ilonly_is_mixed_mode(tmp_path: Path) -> None:
    # A verified BSJB image whose flags lack ILONLY classifies as mixed-mode,
    # which downstream unpackers treat differently from pure managed.
    path = _write(tmp_path, "mixed.exe", cor_flags=0)
    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.kind is DotnetKind.MIXED_MODE
    assert "ILONLY" not in report.flags_decoded


def _meta_root(
    version: bytes = b"v4.0\0",
    *,
    declared_streams: int | None = None,
    streams: list[tuple[bytes, int, int, bool]] | None = None,
    drop_stream_count: bool = False,
) -> bytes:
    vlen = len(version)
    vpad = (vlen + 3) & ~3
    version_block = version + b"\0" * (vpad - vlen)
    body = b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", vlen) + version_block
    if drop_stream_count:
        return body
    entries = streams or []
    count = declared_streams if declared_streams is not None else len(entries)
    body += struct.pack("<HH", 0, count)
    for name, off, size, include_name in entries:
        entry = struct.pack("<II", off, size)
        if include_name:
            raw = name + b"\0"
            raw += b"\0" * (((len(raw) + 3) & ~3) - len(raw))
            entry += raw
        body += entry
    return body


# _parse_metadata_root now takes the COR20 entry-point token and returns a
# wider tuple (name resolution, refs, framework...). These crafted-root tests
# pin only the hostile-input semantics: version/streams/module/assembly stay
# the first four slots and MetadataStats the last, so unpack with a star to
# stay out of the way as the middle of the tuple evolves.


def test_metadata_root_rejects_short_or_mis_signed_blocks() -> None:
    for hostile in (b"BSJB\0\0\0\0", b"XXXX" + b"\0" * 20):
        version, streams, *rest = _parse_metadata_root(hostile, 0)
        assert version is None and streams == []
        assert rest[-1] is None  # no MetadataStats for a rejected root


def test_metadata_root_rejects_an_oversized_version_length() -> None:
    # A version_len that runs past the buffer must fail closed, not slice wild.
    forged = b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", 9999)
    version, streams, *rest = _parse_metadata_root(forged, 0)
    assert version is None and streams == []
    assert rest[-1] is None


def test_metadata_root_truncated_before_stream_count_returns_version_only() -> None:
    version, streams, module, assembly, *rest = _parse_metadata_root(
        _meta_root(drop_stream_count=True), 0
    )
    assert version == "v4.0"
    assert streams == [] and module is None and assembly is None and rest[-1] is None


def test_metadata_root_reads_stream_names() -> None:
    version, streams, *_rest = _parse_metadata_root(
        _meta_root(streams=[(b"#Strings", 0x10, 0x20, True)]), 0
    )
    assert version == "v4.0"
    assert streams == ["#Strings"]


def test_metadata_root_stops_when_a_declared_stream_entry_is_missing() -> None:
    # stream_count claims one entry but the buffer ends: the loop must break,
    # not read past the end.
    _version, streams, *_rest = _parse_metadata_root(_meta_root(declared_streams=1, streams=[]), 0)
    assert streams == []


def test_metadata_root_stops_on_a_stream_name_with_no_terminator() -> None:
    # An entry present but with no NUL to end the name: break rather than scan on.
    _version, streams, *_rest = _parse_metadata_root(
        _meta_root(streams=[(b"#Strings", 0x10, 0x20, False)]), 0
    )
    assert streams == []

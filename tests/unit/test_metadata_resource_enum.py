"""End-to-end resource enumeration over a hand-built managed PE.

The AssemblyRef (0x23) row width feeds ``_table_start`` for every later table,
including ManifestResource (0x28). Nearly every assembly has an AssemblyRef row,
so an off-by-two width there shifts where resource enumeration starts reading.
The repository's other managed-metadata tests need a real .NET DLL fixture that
is not present in every environment; this synthesises the smallest PE that
carries Module + AssemblyRef + ManifestResource so the resource read lands on
the right row only when AssemblyRef is sized to the ECMA-335 20 bytes, not the
22 the row briefly measured while it mirrored the Assembly row.
"""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import enumerate_metadata


def _managed_metadata() -> bytes:
    strings = b"\x00MyModule\x00mscorlib\x00MyResource\x00"  # idx 1, 10, 19
    assert len(strings) == 30

    valid = (1 << 0x00) | (1 << 0x23) | (1 << 0x28)
    tilde = bytearray()
    tilde += struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)  # 24-byte #~ header
    tilde += struct.pack("<III", 1, 1, 1)  # rows: Module, AssemblyRef, ManifestResource
    tilde += struct.pack("<HHHHH", 0, 1, 0, 0, 0)  # Module: Generation, Name=1, 3 GUIDs
    # AssemblyRef: Major/Minor/Build/Rev(2 each), Flags(4), PublicKeyOrToken(blob 2),
    # Name(str 2)=mscorlib, Culture(str 2), HashValue(blob 2) -> 20 bytes.
    tilde += struct.pack("<HHHHIHHHH", 0, 0, 0, 0, 0, 0, 10, 0, 0)
    # ManifestResource: Offset(4)=0x1234, Flags(4)=1, Name(str 2)=MyResource, Implementation(2).
    tilde += struct.pack("<IIHH", 0x1234, 0x0001, 19, 0)
    tilde = bytes(tilde)
    assert len(tilde) == 78, len(tilde)

    version = b"v4.0.30319\x00"
    version_padded = version + b"\x00" * ((4 - len(version) % 4) % 4)
    meta = bytearray()
    meta += b"BSJB"
    meta += struct.pack("<HH", 1, 1)
    meta += struct.pack("<I", 0)
    meta += struct.pack("<I", len(version))
    meta += version_padded
    meta += struct.pack("<HH", 0, 2)  # flags, stream_count
    hdr_start = len(meta)
    assert hdr_start == 32, hdr_start
    data_start = hdr_start + 12 + 20  # two stream headers precede the stream data
    tilde_off = data_start
    strings_off = tilde_off + len(tilde)
    meta += struct.pack("<II", tilde_off, len(tilde)) + b"#~\x00\x00"
    meta += struct.pack("<II", strings_off, len(strings)) + b"#Strings\x00\x00\x00\x00"
    assert len(meta) == data_start, (len(meta), data_start)
    meta += tilde
    meta += strings
    return bytes(meta)


def _write_managed_pe(path: Path) -> None:
    """Minimal verified-CLR PE carrying real #~ tables and a #Strings heap."""
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
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)  # COM descriptor
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    metadata = _managed_metadata()
    cor_off = 0x300  # RVA 0x1100
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(metadata))  # metadata dir
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)

    meta_off = 0x400  # RVA 0x1200
    image[meta_off : meta_off + len(metadata)] = metadata
    path.write_bytes(image)


def test_resource_enumeration_reads_past_an_assemblyref_row(tmp_path: Path) -> None:
    path = tmp_path / "managed.dll"
    _write_managed_pe(path)

    page = enumerate_metadata(path, kind="resources", offset=0, limit=20, require_verified=False)

    assert page.total == 1
    (resource,) = page.items
    assert resource["name"] == "MyResource"
    assert resource["offset"] == 0x1234
    assert resource["flags"] == 0x0001
    assert resource["token"] == 0x28000001

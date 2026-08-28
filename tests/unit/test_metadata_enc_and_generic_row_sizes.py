"""Row widths for the ENC tables and the MethodSpec/GenericParamConstraint pair.

``_table_start`` sums the width of every populated table in front of the one
being read, so a single missing or mis-sized entry silently shifts -- or
aborts -- every table behind it. ENCLog (0x1E) and ENCMap (0x1F) are emitted
into #- ("uncompressed") metadata by edit-and-continue builds, and
``_load_metadata_context`` accepts #- streams, yet ``_table_row_size`` had no
entry for either: any image carrying them lost resource enumeration to an
``unsupported_metadata`` abort. MethodSpec (0x2B) and GenericParamConstraint
(0x2C) had each other's column layouts, which diverge as soon as the blob heap
grows past 64 KiB or TypeDef crosses 2^14 rows.
"""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.dotnet.metadata_enum import (
    _MetaCtx,
    _table_row_size,
    enumerate_metadata,
)


def _ctx(row_counts: dict[int, int], *, heap_sizes: int = 0) -> _MetaCtx:
    """A context with only the fields row sizing reads populated meaningfully."""
    return _MetaCtx(
        path=Path("crafted.dll"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=b"",
        strings=b"",
        heap_sizes=heap_sizes,
        string_index_size=4 if heap_sizes & 0x01 else 2,
        blob_index_size=4 if heap_sizes & 0x04 else 2,
        guid_index_size=4 if heap_sizes & 0x02 else 2,
        row_counts=row_counts,
        table_data_offset=24,
    )


def test_enclog_and_encmap_have_their_fixed_widths() -> None:
    """ENCLog is Token+FuncCode (8), ENCMap is Token (4); no heap indexes."""
    ctx = _ctx({0x1E: 3, 0x1F: 3})
    assert _table_row_size(ctx, 0x1E) == 8
    assert _table_row_size(ctx, 0x1F) == 4


def test_methodspec_instantiation_is_a_blob_index() -> None:
    """MethodSpec = MethodDefOrRef coded index + Instantiation blob index.

    With a wide blob heap (flag 0x04) and small tables the correct width is
    2 + 4 = 6; the swapped GenericParamConstraint layout said 2 + 2 = 4.
    """
    ctx = _ctx({0x2B: 1}, heap_sizes=0x04)
    assert _table_row_size(ctx, 0x2B) == 2 + 4


def test_genericparamconstraint_constraint_is_a_typedeforref_coded_index() -> None:
    """GenericParamConstraint = GenericParam index + TypeDefOrRef coded index.

    2^14 TypeDef rows push the 2-tag-bit TypeDefOrRef coded index to 4 bytes,
    so the correct width is 2 + 4 = 6; the swapped MethodSpec layout stayed at
    2 + 2 = 4 because neither MethodDef count nor the blob heap grew.
    """
    ctx = _ctx({0x02: 1 << 14, 0x2C: 1})
    assert _table_row_size(ctx, 0x2C) == 2 + 4


def _write_clr_with_enc_tables_before_resources(path: Path) -> None:
    """Minimal managed PE whose #~ declares ENCLog + ENCMap + ManifestResource."""
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

    cor_off = 0x300  # RVA 0x1100
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x100)  # MetaData RVA/size
    struct.pack_into("<I", image, cor_off + 16, 0x1)  # ILONLY
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)

    meta_off = 0x400  # RVA 0x1200
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded

    strings_heap = b"\0payload.resources\0"

    # #~ stream: header (24) + three row counts (12) + ENCLog row (8)
    # + ENCMap row (4) + ManifestResource row (12).
    tilde = bytearray(60)
    struct.pack_into("<I", tilde, 0, 0)
    tilde[4] = 2  # MajorVersion
    tilde[5] = 0  # MinorVersion
    tilde[6] = 0  # HeapSizes: 2-byte string/guid/blob indexes
    tilde[7] = 1
    valid = (1 << 0x1E) | (1 << 0x1F) | (1 << 0x28)
    struct.pack_into("<Q", tilde, 8, valid)
    struct.pack_into("<Q", tilde, 16, 0)  # Sorted
    struct.pack_into("<III", tilde, 24, 1, 1, 1)  # rows: ENCLog, ENCMap, ManifestResource
    struct.pack_into("<II", tilde, 36, 0x06000001, 0)  # ENCLog: Token + FuncCode
    struct.pack_into("<I", tilde, 44, 0x06000001)  # ENCMap: Token
    # ManifestResource: Offset(4) + Flags(4) + Name(#Strings idx 1) + Implementation(0).
    struct.pack_into("<IIHH", tilde, 48, 0, 1, 1, 0)

    # Stream headers: flags/count at +28, "#~" header is 12 bytes, "#Strings" is 20.
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 2)
    headers_end = 16 + len(version_padded) + 4 + 12 + 20
    tilde_offset = headers_end
    strings_offset = tilde_offset + len(tilde)
    struct.pack_into("<II", image, cursor + 4, tilde_offset, len(tilde))
    image[cursor + 12 : cursor + 16] = b"#~\0\0"
    struct.pack_into("<II", image, cursor + 16, strings_offset, len(strings_heap))
    image[cursor + 24 : cursor + 36] = b"#Strings\0\0\0\0"
    image[meta_off + tilde_offset : meta_off + tilde_offset + len(tilde)] = tilde
    image[meta_off + strings_offset : meta_off + strings_offset + len(strings_heap)] = (
        strings_heap
    )
    path.write_bytes(image)


def test_resources_survive_enc_tables_in_front_of_the_manifest(tmp_path: Path) -> None:
    """ENC rows ahead of ManifestResource must be skipped, not fatal.

    Before the fix ``_table_start`` hit table 0x1E, could not size it, and the
    whole enumeration aborted with ``unsupported_metadata`` -- from an image
    whose resource table was perfectly readable.
    """
    binary = tmp_path / "enc_image.exe"
    _write_clr_with_enc_tables_before_resources(binary)

    page = enumerate_metadata(binary, "resources", limit=10)

    assert page.total == 1
    assert page.items[0]["name"] == "payload.resources"
    assert page.items[0]["flags"] == 1

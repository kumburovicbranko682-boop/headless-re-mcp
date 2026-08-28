"""The import reader must flag a thunk array that runs off its section unterminated.

``_parse_imports`` has two independent truncation shapes. The outer descriptor
array running off its directory without a null descriptor is already covered
(``test_parse_imports_marks_truncation_when_table_is_not_null_terminated`` in
``test_pe_parser_crafted``). This pins the *inner* shape: a single well-formed
descriptor whose thunk (IAT) array reaches the end of its section's raw bytes
with no NUL terminator. Its tail is not in the file, so the functions counted
are an undercount -- exactly what ``truncated`` exists to disclose, matching the
sibling ``_parse_tls`` callback reader. Without the inner ``else`` the summary
reported the functions that happened to fit with ``truncated=False`` and read as
a complete import list.
"""

from __future__ import annotations

import struct

from headless_re_mcp.core.models import Architecture
from headless_re_mcp.detection.pe import _Layout, _parse_imports, _Section

_IMAGE_BASE = 0x140000000
_ORDINAL_FLAG_X64 = 1 << 63


def _layout(import_size: int) -> _Layout:
    # One .text section mapping rva 0x1000 -> file offset 0x200, raw window
    # [0x200, 0x600). Every table below lives inside that window.
    section = _Section(
        name=".text",
        virtual_size=0x400,
        virtual_address=0x1000,
        raw_size=0x400,
        raw_offset=0x200,
        characteristics=0x60000020,
    )
    directories = [(0, 0)] * 16
    directories[1] = (0x1000, import_size)  # import directory
    return _Layout(
        machine=0x8664,
        architecture=Architecture.X64,
        characteristics=0x22,
        subsystem=3,
        dll_characteristics=0,
        image_base=_IMAGE_BASE,
        image_size=0x4000,
        entry_point_rva=0x1000,
        section_alignment=0x1000,
        file_alignment=0x200,
        linker_version="14.0",
        size_of_headers=0x200,
        directories=tuple(directories),
        sections=(section,),
    )


def _base_image() -> bytearray:
    data = bytearray(0x800)
    # Descriptor 1 at rva 0x1000 -> offset 0x200: OFT/FT both point at the thunk
    # table (rva 0x1200 -> offset 0x400); Name is rva 0x1100 -> offset 0x300.
    struct.pack_into("<IIIII", data, 0x200, 0x1200, 0, 0, 0x1100, 0x1200)
    # Descriptor 2 at offset 0x214 stays all-zero: the outer loop breaks on it,
    # so the outer "ran off the directory" truncation cannot fire and mask the
    # inner one under test.
    data[0x300:0x30D] = b"KERNEL32.dll\0"
    return data


def test_thunk_array_running_off_the_section_marks_truncation() -> None:
    data = _base_image()
    # Fill the thunk window 0x400..0x600 solid with ordinal thunks and no NUL,
    # so the inner loop exits on its section bound, not a terminator. Ordinals
    # avoid name resolution and stay well under _MAX_IMPORT_FUNCTIONS (16384).
    ordinals = 0
    for offset in range(0x400, 0x600, 8):
        ordinals += 1
        struct.pack_into("<Q", data, offset, _ORDINAL_FLAG_X64 | ordinals)

    summary = _parse_imports(bytes(data), _layout(import_size=40))

    assert summary.library_count == 1
    assert summary.function_count == ordinals == 64
    assert summary.ordinal_count == 64
    # The load-bearing assertion: an undercounted tail is disclosed, not hidden.
    assert summary.truncated is True


def test_null_terminated_thunk_array_within_the_section_is_not_truncated() -> None:
    # Control: the same descriptor whose thunk array carries a NUL terminator
    # before the section bound must read as complete.
    data = _base_image()
    struct.pack_into("<Q", data, 0x400, _ORDINAL_FLAG_X64 | 1)
    struct.pack_into("<Q", data, 0x408, _ORDINAL_FLAG_X64 | 2)
    struct.pack_into("<Q", data, 0x410, 0)  # terminator, well inside the window

    summary = _parse_imports(bytes(data), _layout(import_size=40))

    assert summary.library_count == 1
    assert summary.function_count == 2
    assert summary.ordinal_count == 2
    assert summary.truncated is False

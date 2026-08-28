"""The import reader must flag truncation when a thunk array runs off its section.

``_parse_imports`` walks each library's thunk (IAT/ILT) array until it reads a
NUL terminator. When the array instead reaches the end of its section's raw
bytes with no terminator, its tail is not present in the file and the library's
imports are undercounted. The sibling TLS callback reader already marks that
shape as ``truncated``; the import reader did not, so a summary built from a
truncated dump read back as a complete import list. These pin the flag and the
control cases around it.
"""

from __future__ import annotations

import struct

from headless_re_mcp.core.models import Architecture
from headless_re_mcp.detection.pe import _Layout, _parse_imports, _Section

IMAGE_BASE = 0x140000000
_ORDINAL64 = 1 << 63


def _layout(import_size: int) -> _Layout:
    """A PE32+ layout whose single section maps rva 0x1000 -> file offset 0x200.

    The section's raw window is 0x200..0x600 (rva 0x1000..0x1400), so a thunk
    array placed at its tail runs to the section bound.
    """
    section = _Section(
        name=".text",
        virtual_size=0x400,
        virtual_address=0x1000,
        raw_size=0x400,
        raw_offset=0x200,
        characteristics=0x60000020,
    )
    dirs = [(0, 0)] * 16
    dirs[1] = (0x1000, import_size)
    return _Layout(
        machine=0x8664,
        architecture=Architecture.X64,
        characteristics=0x22,
        subsystem=3,
        dll_characteristics=0,
        image_base=IMAGE_BASE,
        image_size=0x4000,
        entry_point_rva=0x1000,
        section_alignment=0x1000,
        file_alignment=0x200,
        linker_version="14.0",
        size_of_headers=0x200,
        directories=tuple(dirs),
        sections=(section,),
    )


def _with_name_and_descriptor(data: bytearray, thunk_rva: int) -> None:
    # Import descriptor at rva 0x1000 -> offset 0x200, then a NUL descriptor so
    # the descriptor list itself terminates cleanly and cannot be what sets the
    # truncated flag.
    struct.pack_into("<IIIII", data, 0x200, thunk_rva, 0, 0, 0x1100, thunk_rva)
    struct.pack_into("<IIIII", data, 0x214, 0, 0, 0, 0, 0)
    data[0x300:0x308] = b"K32.dll\0"  # name at rva 0x1100 -> offset 0x300


def test_thunk_array_running_off_section_marks_truncation() -> None:
    data = bytearray(0x800)
    # Thunk array at rva 0x13F0 -> offset 0x5F0 fills the section's last two
    # 8-byte slots (0x5F0, 0x5F8) with non-null ordinal thunks; the next slot
    # would be at 0x600, the section bound, so there is no NUL terminator.
    _with_name_and_descriptor(data, thunk_rva=0x13F0)
    struct.pack_into("<Q", data, 0x5F0, _ORDINAL64 | 1)
    struct.pack_into("<Q", data, 0x5F8, _ORDINAL64 | 2)

    summary = _parse_imports(bytes(data), _layout(import_size=40))

    assert summary.library_count == 1
    assert summary.function_count == 2
    assert summary.ordinal_count == 2
    assert summary.truncated is True


def test_null_terminated_thunk_array_is_not_truncated() -> None:
    # Control: same shape, but the array has room for and includes a NUL
    # terminator, so the read is complete.
    data = bytearray(0x800)
    _with_name_and_descriptor(data, thunk_rva=0x1300)
    struct.pack_into("<Q", data, 0x500, _ORDINAL64 | 1)  # rva 0x1300 -> offset 0x500
    struct.pack_into("<Q", data, 0x508, 0)  # NUL terminator, within the section

    summary = _parse_imports(bytes(data), _layout(import_size=40))

    assert summary.library_count == 1
    assert summary.function_count == 1
    assert summary.ordinal_count == 1
    assert summary.truncated is False


def test_named_thunk_array_running_off_section_marks_truncation() -> None:
    # The truncation flag holds for name-based thunks too, not only ordinals.
    data = bytearray(0x800)
    _with_name_and_descriptor(data, thunk_rva=0x13F0)
    # Two by-name thunks pointing at hint/name records earlier in the section.
    struct.pack_into("<Q", data, 0x5F0, 0x1200)  # -> offset 0x400
    struct.pack_into("<Q", data, 0x5F8, 0x1220)  # -> offset 0x420
    data[0x402:0x40F] = b"VirtualAlloc\0"  # hint(2) + name at rva 0x1200
    data[0x422:0x429] = b"Benign\0"  # hint(2) + name at rva 0x1220

    summary = _parse_imports(bytes(data), _layout(import_size=40))

    assert summary.library_count == 1
    assert summary.function_count == 2
    assert summary.ordinal_count == 0
    assert summary.suspicious_apis == ("VirtualAlloc",)
    assert summary.truncated is True

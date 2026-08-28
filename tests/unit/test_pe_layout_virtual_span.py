"""Layout validation must measure a section's virtual footprint, not its disk size.

The Windows loader maps ``VirtualSize`` bytes of a section into memory (falling
back to ``SizeOfRawData`` only when ``VirtualSize`` is zero). A section may
legitimately carry more bytes on disk than it maps -- padding to file alignment
or a packer stashing compressed data past the mapped tail -- so validating the
in-memory layout against ``max(VirtualSize, SizeOfRawData)`` invents overlaps
and SizeOfImage overruns the loader never sees, rejecting images it accepts.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.detection.pe import PeFormatError, _Section, _validate_layout


def _section(
    name: str,
    *,
    virtual_address: int,
    virtual_size: int,
    raw_offset: int,
    raw_size: int,
    characteristics: int = 0x40000000,
) -> _Section:
    return _Section(
        name=name,
        virtual_size=virtual_size,
        virtual_address=virtual_address,
        raw_size=raw_size,
        raw_offset=raw_offset,
        characteristics=characteristics,
    )


def test_virtual_span_uses_virtual_size_when_present() -> None:
    section = _section(
        ".text", virtual_address=0x1000, virtual_size=0x400, raw_offset=0x400, raw_size=0x2000
    )
    assert section.virtual_span == 0x400
    # mapped_size still reaches into the larger on-disk tail for RVA lookups.
    assert section.mapped_size == 0x2000


def test_virtual_span_falls_back_to_raw_size_only_when_virtual_size_is_zero() -> None:
    section = _section(
        ".data", virtual_address=0x1000, virtual_size=0, raw_offset=0x400, raw_size=0x600
    )
    assert section.virtual_span == 0x600
    assert section.mapped_size == 0x600


def test_layout_accepts_sections_whose_disk_size_exceeds_their_virtual_size() -> None:
    """A packed image maps 0x400 bytes per section but stores 0x2000 on disk.

    Measured by the on-disk size the two sections would overrun SizeOfImage and
    collide in virtual memory; measured by the mapped VirtualSize they sit apart
    and inside the image, which is what the loader actually does.
    """
    data = b"\x00" * 0x5000
    sections = (
        _section(
            ".a", virtual_address=0x1000, virtual_size=0x400, raw_offset=0x400, raw_size=0x2000
        ),
        _section(
            ".b", virtual_address=0x2000, virtual_size=0x400, raw_offset=0x2400, raw_size=0x2000
        ),
    )

    _validate_layout(
        data,
        image_base=0x400000,
        image_size=0x3000,
        section_alignment=0x1000,
        file_alignment=0x200,
        size_of_headers=0x400,
        section_table_end=0x200,
        sections=sections,
    )


def test_layout_still_rejects_a_genuine_virtual_overlap() -> None:
    """Overlap measured by the mapped VirtualSize is a real defect and must fail."""
    data = b"\x00" * 0x5000
    sections = (
        _section(
            ".a", virtual_address=0x1000, virtual_size=0x1800, raw_offset=0x400, raw_size=0x400
        ),
        _section(
            ".b", virtual_address=0x2000, virtual_size=0x400, raw_offset=0x800, raw_size=0x400
        ),
    )

    with pytest.raises(PeFormatError, match="overlapping virtual ranges"):
        _validate_layout(
            data,
            image_base=0x400000,
            image_size=0x9000,
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x200,
            sections=sections,
        )


def test_layout_still_rejects_a_section_mapped_past_size_of_image() -> None:
    data = b"\x00" * 0x5000
    sections = (
        _section(
            ".a", virtual_address=0x1000, virtual_size=0x4000, raw_offset=0x400, raw_size=0x400
        ),
    )

    with pytest.raises(PeFormatError, match="exceeds SizeOfImage"):
        _validate_layout(
            data,
            image_base=0x400000,
            image_size=0x3000,
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x200,
            sections=sections,
        )

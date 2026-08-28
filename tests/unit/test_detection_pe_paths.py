"""Coverage for detection/pe.py guard, parse-error, table, and finding arms.

The heavy structural arms reuse the ``_SyntheticPe`` writer from
``test_detection_pe``; the small validators and RVA/string helpers are called
directly with crafted layouts so their refusal paths don't need a full image.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from test_detection_pe import (
    _IMAGE_SCN_MEM_EXECUTE,
    _IMAGE_SCN_MEM_READ,
    _sample,
    _SyntheticPe,
)

from headless_re_mcp.core.models import Architecture
from headless_re_mcp.detection.pe import (
    PeFormatError,
    _alignment_is_conventional,
    _architecture,
    _entropy,
    _is_power_of_two,
    _Layout,
    _read_c_string,
    _read_pe_bytes,
    _rva_raw_span,
    _Section,
    _slice,
    _validate_layout,
    scan_pe,
)

_RX = _IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE


def _sec(
    *,
    virtual_size: int = 0x1000,
    virtual_address: int = 0x1000,
    raw_size: int = 0x400,
    raw_offset: int = 0x400,
    characteristics: int = 0,
) -> _Section:
    return _Section(
        name=".sec",
        virtual_size=virtual_size,
        virtual_address=virtual_address,
        raw_size=raw_size,
        raw_offset=raw_offset,
        characteristics=characteristics,
    )


def _layout(**over: object) -> _Layout:
    defaults: dict[str, object] = {
        "machine": 0x8664,
        "architecture": Architecture.X64,
        "characteristics": 0,
        "subsystem": 3,
        "dll_characteristics": 0,
        "image_base": 0x140000000,
        "image_size": 0x3000,
        "entry_point_rva": 0x1000,
        "section_alignment": 0x1000,
        "file_alignment": 0x200,
        "linker_version": "14.0",
        "size_of_headers": 0x400,
        "directories": (),
        "sections": (_sec(),),
    }
    defaults.update(over)
    return _Layout(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _read_pe_bytes chunked-read arms
# ---------------------------------------------------------------------------


def test_read_pe_bytes_chunks_and_refuses_over_budget(tmp_path: Path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"\0" * (2 * 1024 * 1024))  # two full chunks, past the budget
    with pytest.raises(PeFormatError, match="scan limit"):
        _read_pe_bytes(path, max_file_size=1024 * 1024)


# ---------------------------------------------------------------------------
# scan_pe front-door guards
# ---------------------------------------------------------------------------


def test_scan_pe_rejects_a_non_regular_file(tmp_path: Path) -> None:
    with pytest.raises(PeFormatError, match="not a regular file"):
        scan_pe(tmp_path)


# ---------------------------------------------------------------------------
# _parse_layout error arms, driven by mutating a valid image
# ---------------------------------------------------------------------------


def _valid_x64() -> bytearray:
    return bytearray(_sample("x64", imports=False, tls=False, dotnet=False))


def test_parse_rejects_a_truncated_optional_header(tmp_path: Path) -> None:
    data = _valid_x64()
    struct.pack_into("<H", data, 0x84 + 16, 0xF000)  # SizeOfOptionalHeader
    path = tmp_path / "opt.exe"
    path.write_bytes(bytes(data))
    with pytest.raises(PeFormatError, match="optional header is truncated"):
        scan_pe(path)


def test_parse_rejects_a_magic_inconsistent_with_the_machine(tmp_path: Path) -> None:
    data = _valid_x64()
    struct.pack_into("<H", data, 0x98, 0x999)  # optional magic
    path = tmp_path / "magic.exe"
    path.write_bytes(bytes(data))
    with pytest.raises(PeFormatError, match="inconsistent with its machine"):
        scan_pe(path)


def test_parse_rejects_a_truncated_directory_array(tmp_path: Path) -> None:
    data = _valid_x64()
    struct.pack_into("<H", data, 0x84 + 16, 112)  # shrink optional header past directories
    path = tmp_path / "dirs.exe"
    path.write_bytes(bytes(data))
    with pytest.raises(PeFormatError, match="data directory array is truncated"):
        scan_pe(path)


def test_parse_rejects_a_section_count_out_of_range(tmp_path: Path) -> None:
    data = _valid_x64()
    struct.pack_into("<H", data, 0x84 + 2, 0)  # NumberOfSections
    path = tmp_path / "sections.exe"
    path.write_bytes(bytes(data))
    with pytest.raises(PeFormatError, match="section count is outside"):
        scan_pe(path)


def test_architecture_rejects_an_unsupported_machine() -> None:
    with pytest.raises(PeFormatError, match="unsupported PE machine"):
        _architecture(0x1234)


# ---------------------------------------------------------------------------
# _validate_layout arms
# ---------------------------------------------------------------------------


def test_validate_layout_rejects_non_positive_base_size_and_alignment() -> None:
    with pytest.raises(PeFormatError, match="image base and image size"):
        _validate_layout(
            b"\0" * 0x400,
            image_base=0,
            image_size=0x2000,
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x400,
            sections=(),
        )
    with pytest.raises(PeFormatError, match="alignments must be positive"):
        _validate_layout(
            b"\0" * 0x400,
            image_base=0x1000,
            image_size=0x2000,
            section_alignment=0,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x400,
            sections=(),
        )


def test_validate_layout_rejects_bad_size_of_headers() -> None:
    with pytest.raises(PeFormatError, match="SizeOfHeaders is outside"):
        _validate_layout(
            b"\0" * 0x100,
            image_base=0x1000,
            image_size=0x2000,
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x200,  # beyond the 0x100-byte input
            section_table_end=0x100,
            sections=(),
        )
    with pytest.raises(PeFormatError, match="headers exceed SizeOfImage"):
        _validate_layout(
            b"\0" * 0x400,
            image_base=0x1000,
            image_size=0x200,  # smaller than size_of_headers
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x400,
            sections=(),
        )


def test_validate_layout_rejects_sections_that_overlap_headers_or_image() -> None:
    with pytest.raises(PeFormatError, match="overlaps PE headers"):
        _validate_layout(
            b"\0" * 0x2000,
            image_base=0x1000,
            image_size=0x3000,
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x400,
            sections=(_sec(raw_offset=0x10, raw_size=0x100, virtual_size=0x100),),
        )
    with pytest.raises(PeFormatError, match="exceeds SizeOfImage"):
        _validate_layout(
            b"\0" * 0x2000,
            image_base=0x1000,
            image_size=0x3000,
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x400,
            sections=(
                _sec(
                    virtual_address=0x2000,
                    virtual_size=0x2000,
                    raw_size=0,
                    raw_offset=0x400,
                ),
            ),
        )


def test_validate_layout_skips_a_zero_mapped_section_and_flags_overlap() -> None:
    # A zero-sized section is neither mapped nor raw; validation returns cleanly.
    _validate_layout(
        b"\0" * 0x2000,
        image_base=0x1000,
        image_size=0x3000,
        section_alignment=0x1000,
        file_alignment=0x200,
        size_of_headers=0x400,
        section_table_end=0x400,
        sections=(_sec(virtual_size=0, raw_size=0, raw_offset=0, virtual_address=0x1000),),
    )
    with pytest.raises(PeFormatError, match="overlapping virtual ranges"):
        _validate_layout(
            b"\0" * 0x2000,
            image_base=0x1000,
            image_size=0x10000,
            section_alignment=0x1000,
            file_alignment=0x200,
            size_of_headers=0x400,
            section_table_end=0x400,
            sections=(
                _sec(virtual_address=0x1000, virtual_size=0x1000, raw_size=0, raw_offset=0),
                _sec(virtual_address=0x1800, virtual_size=0x1000, raw_size=0, raw_offset=0),
            ),
        )


# ---------------------------------------------------------------------------
# _rva_raw_span / _read_c_string / _slice / alignment helpers
# ---------------------------------------------------------------------------


def test_rva_raw_span_arms() -> None:
    layout = _layout()
    with pytest.raises(PeFormatError, match="non-negative RVA and positive size"):
        _rva_raw_span(layout, -1, size=4)
    with pytest.raises(PeFormatError, match="outside PE headers"):
        _rva_raw_span(layout, 0x300, size=0x200)  # crosses the header boundary
    assert _rva_raw_span(layout, 0x10, size=0x10) == (0x10, 0x400)  # inside headers
    with pytest.raises(PeFormatError, match="not mapped by the PE image"):
        _rva_raw_span(layout, 0x9000, size=4)  # beyond every section
    with pytest.raises(PeFormatError, match="outside section raw data"):
        _rva_raw_span(layout, 0x1300, size=0x200)  # past the section's raw span


def test_read_c_string_arms() -> None:
    with pytest.raises(PeFormatError, match="outside the input"):
        _read_c_string(b"abc", 5)
    with pytest.raises(PeFormatError, match="outside its PE section"):
        _read_c_string(b"abc\0", 2, limit=1)
    with pytest.raises(PeFormatError, match="unterminated"):
        _read_c_string(b"abcd", 0, limit=4)
    assert _read_c_string(b"hi\0there", 0) == "hi"


def test_slice_rejects_out_of_range() -> None:
    with pytest.raises(PeFormatError, match="truncated"):
        _slice(b"abc", 2, 4)


def test_alignment_helpers() -> None:
    assert _is_power_of_two(0x200) is True
    assert _is_power_of_two(0x300) is False
    assert _alignment_is_conventional(0x1000, 0x200) is True
    assert _alignment_is_conventional(0x1000, 0x300) is False  # file not power of two
    assert _alignment_is_conventional(0x1500, 0x1000) is False  # section not power of two


def test_entropy_of_empty_input_is_zero() -> None:
    assert _entropy(b"") == 0.0


# ---------------------------------------------------------------------------
# import descriptor / TLS / CLR arms through scan_pe
# ---------------------------------------------------------------------------


def test_import_descriptor_without_a_thunk_table_is_rejected(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    idata = pe.add_section(".idata", size=0x400)
    pe.write(idata, 0x200, b"KERNEL32.dll\0")
    name_rva = pe.rva(idata, 0x200)
    pe.write(idata, 0, struct.pack("<IIIII", 0, 0, 0, name_rva, 0))  # no thunk RVAs
    pe.directories[1] = (pe.rva(idata, 0), 40)
    path = tmp_path / "no-thunk.exe"
    path.write_bytes(pe.build())
    with pytest.raises(PeFormatError, match="no thunk table"):
        scan_pe(path)


def test_tls_directory_smaller_than_header_is_rejected(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_RX)
    tls = pe.add_section(".tls", size=0x400)
    pe.directories[9] = (pe.rva(tls), 8)  # below the 40-byte x64 header
    path = tmp_path / "short-tls.exe"
    path.write_bytes(pe.build())
    with pytest.raises(PeFormatError, match="TLS directory is smaller"):
        scan_pe(path)


def test_tls_with_no_callback_array_is_present_but_empty(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_RX)
    tls = pe.add_section(".tls", size=0x400)
    pe.write(tls, 0, b"\0" * 40)  # AddressOfCallBacks == 0
    pe.directories[9] = (pe.rva(tls), 40)
    path = tmp_path / "empty-tls.exe"
    path.write_bytes(pe.build())
    report = scan_pe(path)
    assert report.pe.tls.present is True
    assert report.pe.tls.callback_count == 0


def test_tls_callback_va_below_image_base_is_rejected(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_RX)
    tls = pe.add_section(".tls", size=0x400)
    pe.write(tls, 24, (1).to_bytes(8, "little"))  # AddressOfCallBacks below ImageBase
    pe.directories[9] = (pe.rva(tls), 40)
    path = tmp_path / "low-tls.exe"
    path.write_bytes(pe.build())
    with pytest.raises(PeFormatError, match="precedes ImageBase"):
        scan_pe(path)


def test_tls_callback_array_is_bounded_to_the_maximum(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_RX)
    tls = pe.add_section(".tls", size=0x100 + 131 * pe.pointer_size)
    pe.add_tls(tls, [pe.image_base + 0x3000] * 130, terminate=False)
    path = tmp_path / "many-tls.exe"
    path.write_bytes(pe.build())
    report = scan_pe(path)
    assert report.pe.tls.truncated is True
    assert report.pe.tls.callback_count == 128


def test_clr_directory_smaller_than_header_is_only_a_hint(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    text = pe.add_section(
        ".text", size=0x400, characteristics=_RX
    )
    pe.directories[14] = (pe.rva(text, 0x100), 8)  # 0 < size < 16 -> hint
    path = tmp_path / "clr-hint.exe"
    path.write_bytes(pe.build())
    report = scan_pe(path)
    assert report.pe.dotnet is True
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")
    assert finding.summary == "CLR directory hint"


def test_clr_header_pointing_at_bsjb_metadata_is_verified(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    text = pe.add_section(
        ".text", size=0x400, characteristics=_RX
    )
    meta_rva = pe.rva(text, 0x200)
    pe.write(text, 0x100, struct.pack("<IHH", 72, 2, 5) + struct.pack("<II", meta_rva, 0x100))
    pe.write(text, 0x200, b"BSJB\0\0\0\0")
    pe.directories[14] = (pe.rva(text, 0x100), 72)
    path = tmp_path / "clr-verified.exe"
    path.write_bytes(pe.build())
    report = scan_pe(path)
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")
    assert finding.summary == "CLR runtime header is present"
    assert finding.confidence == 0.99


def test_clr_header_with_unmappable_metadata_falls_back_to_hint(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    text = pe.add_section(
        ".text", size=0x400, characteristics=_RX
    )
    pe.write(text, 0x100, struct.pack("<IHH", 72, 2, 5) + struct.pack("<II", 0x7FFF0000, 0x100))
    pe.directories[14] = (pe.rva(text, 0x100), 72)
    path = tmp_path / "clr-bad-meta.exe"
    path.write_bytes(pe.build())
    report = scan_pe(path)
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")
    assert finding.summary == "CLR directory hint"


def test_clr_header_without_bsjb_signature_falls_back_to_hint(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    text = pe.add_section(
        ".text", size=0x400, characteristics=_RX
    )
    meta_rva = pe.rva(text, 0x200)
    pe.write(text, 0x100, struct.pack("<IHH", 72, 2, 5) + struct.pack("<II", meta_rva, 0x100))
    pe.write(text, 0x200, b"XXXX\0\0\0\0")  # mappable, but not the BSJB signature
    pe.directories[14] = (pe.rva(text, 0x100), 72)
    path = tmp_path / "clr-wrong-sig.exe"
    path.write_bytes(pe.build())
    report = scan_pe(path)
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")
    assert finding.summary == "CLR directory hint"


def test_upx_section_names_produce_a_packer_finding(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section("UPX0", size=0x400, characteristics=_RX)
    pe.add_section("UPX1", size=0x400, characteristics=_RX)
    path = tmp_path / "packed-upx.exe"
    path.write_bytes(pe.build())
    report = scan_pe(path)
    assert any(f.id == "builtin:packer:upx-sections" for f in report.findings)


# ---------------------------------------------------------------------------
# finding arms
# ---------------------------------------------------------------------------


def test_virtual_raw_gap_and_unusual_alignment_findings(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_RX)
    pe.add_section(".big", size=0x200, virtual_size=0x400000)  # huge virtual/raw gap
    data = bytearray(pe.build())
    struct.pack_into("<I", data, 0x98 + 32, 0x1500)  # SectionAlignment not a power of two
    path = tmp_path / "gap.exe"
    path.write_bytes(bytes(data))
    report = scan_pe(path)
    ids = {finding.id for finding in report.findings}
    assert "builtin:anomaly:virtual-raw-gap:.big" in ids
    assert "builtin:anomaly:unusual-alignment" in ids

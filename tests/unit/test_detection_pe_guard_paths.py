"""Guard, malformed-header, and helper-branch coverage for the PE scanner.

The structural happy paths live in ``test_detection_pe``; these drive the
fail-closed guards in ``_parse_layout`` / ``_validate_layout``, the deep
``_classify_clr`` honesty branches, the remaining ``_build_findings`` anomalies,
and the small RVA/string/alignment helpers directly.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.detection import PeFormatError, scan_pe
from headless_re_mcp.detection.pe import (
    _alignment_is_conventional,
    _entropy,
    _parse_layout,
    _read_c_string,
    _read_pe_bytes,
    _rva_raw_span,
    _slice,
)
from tests.unit.test_detection_pe import (
    _IMAGE_SCN_CODE,
    _IMAGE_SCN_MEM_EXECUTE,
    _IMAGE_SCN_MEM_READ,
    _sample,
    _SyntheticPe,
)

_EXEC = _IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_CODE

# x64 default header offsets (optional header size 0xF0).
_MACHINE = 0x84
_SECTION_COUNT = 0x86
_OPTIONAL_SIZE = 0x94
_MAGIC = 0x98
_IMAGE_BASE = 0x98 + 24
_FILE_ALIGN = 0x98 + 36
_IMAGE_SIZE = 0x98 + 56
_SIZE_OF_HEADERS = 0x98 + 60
_SECTION_TABLE = 0x98 + 0xF0


def _one_section() -> _SyntheticPe:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    return pe


def _patch(data: bytes, fmt: str, offset: int, *values: int) -> bytes:
    buffer = bytearray(data)
    struct.pack_into(fmt, buffer, offset, *values)
    return bytes(buffer)


def _scan_bytes(tmp_path: Path, data: bytes, name: str = "sample.exe") -> object:
    path = tmp_path / name
    path.write_bytes(data)
    return scan_pe(path)


# --------------------------------------------------------------------------- #
# _read_pe_bytes / scan_pe entry guards
# --------------------------------------------------------------------------- #
def test_read_pe_bytes_refuses_a_file_over_the_budget(tmp_path: Path) -> None:
    path = tmp_path / "oversized.bin"
    path.write_bytes(b"\x00" * 100)
    with pytest.raises(PeFormatError, match="scan limit"):
        _read_pe_bytes(path, max_file_size=10)


def test_scan_rejects_a_non_regular_file(tmp_path: Path) -> None:
    with pytest.raises(PeFormatError, match="not a regular file"):
        scan_pe(tmp_path)


# --------------------------------------------------------------------------- #
# _parse_layout malformed-header guards
# --------------------------------------------------------------------------- #
def test_parse_rejects_a_zero_section_count(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<H", _SECTION_COUNT, 0)
    with pytest.raises(PeFormatError, match="section count"):
        _scan_bytes(tmp_path, data)


def test_parse_rejects_a_truncated_optional_header(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<H", _OPTIONAL_SIZE, 0x8000)
    with pytest.raises(PeFormatError, match="optional header is truncated"):
        _scan_bytes(tmp_path, data)


def test_parse_rejects_a_magic_inconsistent_with_the_machine(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<H", _MAGIC, 0x10B)  # PE32 magic on x64
    with pytest.raises(PeFormatError, match="inconsistent with its machine type"):
        _scan_bytes(tmp_path, data)


def test_parse_rejects_a_truncated_data_directory_array(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.optional_size = 112  # no room past the directory table start
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    with pytest.raises(PeFormatError, match="data directory array is truncated"):
        _scan_bytes(tmp_path, pe.build())


def test_parse_rejects_an_unsupported_machine(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<H", _MACHINE, 0x1234)
    with pytest.raises(PeFormatError, match="unsupported PE machine"):
        _scan_bytes(tmp_path, data)


# --------------------------------------------------------------------------- #
# _validate_layout guards
# --------------------------------------------------------------------------- #
def test_validate_rejects_a_zero_image_base(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<Q", _IMAGE_BASE, 0)
    with pytest.raises(PeFormatError, match="image base and image size"):
        _scan_bytes(tmp_path, data)


def test_validate_rejects_a_zero_file_alignment(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<I", _FILE_ALIGN, 0)
    with pytest.raises(PeFormatError, match="alignments must be positive"):
        _scan_bytes(tmp_path, data)


def test_validate_rejects_a_zero_size_of_headers(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<I", _SIZE_OF_HEADERS, 0)
    with pytest.raises(PeFormatError, match="SizeOfHeaders is outside"):
        _scan_bytes(tmp_path, data)


def test_validate_rejects_headers_that_exceed_size_of_headers(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<I", _SIZE_OF_HEADERS, 0x10)
    with pytest.raises(PeFormatError, match="exceed SizeOfImage or SizeOfHeaders"):
        _scan_bytes(tmp_path, data)


def test_validate_rejects_section_raw_data_overlapping_headers(tmp_path: Path) -> None:
    data = _patch(_one_section().build(), "<I", _SECTION_TABLE + 20, 0x100)
    with pytest.raises(PeFormatError, match="overlaps PE headers"):
        _scan_bytes(tmp_path, data)


def test_validate_rejects_a_section_beyond_size_of_image(tmp_path: Path) -> None:
    data = _patch(_sample("x64"), "<I", _IMAGE_SIZE, 0x2000)
    with pytest.raises(PeFormatError, match="exceeds SizeOfImage"):
        _scan_bytes(tmp_path, data)


def test_validate_rejects_overlapping_virtual_ranges(tmp_path: Path) -> None:
    # Point the second section's VA at the first so the ranges collide.
    data = _patch(_sample("x64"), "<I", _SECTION_TABLE + 40 + 12, 0x1000)
    with pytest.raises(PeFormatError, match="overlapping virtual ranges"):
        _scan_bytes(tmp_path, data)


# --------------------------------------------------------------------------- #
# _classify_clr honesty branches
# --------------------------------------------------------------------------- #
def _clr_pe(*, meta_rva_offset: int | None, meta_sig: bytes, com_size: int = 72) -> bytes:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    rdata = pe.add_section(".rdata", size=0x400)
    cor20 = bytearray(72)
    if meta_rva_offset is None:
        meta_rva = 0xF00000  # unmapped -> _rva_to_offset raises
    else:
        meta_rva = pe.rva(rdata, meta_rva_offset)
        pe.write(rdata, meta_rva_offset, meta_sig)
    struct.pack_into("<II", cor20, 8, meta_rva, 4)
    pe.write(rdata, 0, bytes(cor20))
    pe.directories[14] = (pe.rva(rdata, 0), com_size)
    return pe.build()


def test_classify_clr_hint_for_a_tiny_com_directory(tmp_path: Path) -> None:
    report = _scan_bytes(tmp_path, _clr_pe(meta_rva_offset=0x100, meta_sig=b"BSJB", com_size=8))
    assert report.pe.dotnet  # type: ignore[attr-defined]
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")  # type: ignore[attr-defined]
    assert finding.summary == "CLR directory hint"


def test_classify_clr_verified_with_bsjb_metadata(tmp_path: Path) -> None:
    report = _scan_bytes(tmp_path, _clr_pe(meta_rva_offset=0x100, meta_sig=b"BSJB"))
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")  # type: ignore[attr-defined]
    assert finding.summary == "CLR runtime header is present"
    assert finding.confidence == 0.99


def test_classify_clr_hint_when_metadata_signature_is_wrong(tmp_path: Path) -> None:
    report = _scan_bytes(tmp_path, _clr_pe(meta_rva_offset=0x100, meta_sig=b"XXXX"))
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")  # type: ignore[attr-defined]
    assert finding.summary == "CLR directory hint"


def test_classify_clr_hint_when_metadata_rva_is_unmapped(tmp_path: Path) -> None:
    report = _scan_bytes(tmp_path, _clr_pe(meta_rva_offset=None, meta_sig=b""))
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")  # type: ignore[attr-defined]
    assert finding.summary == "CLR directory hint"


# --------------------------------------------------------------------------- #
# _build_findings anomalies
# --------------------------------------------------------------------------- #
def test_findings_flag_upx_section_names(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    pe.add_section("UPX0", size=0x400)
    report = _scan_bytes(tmp_path, pe.build())
    assert any(f.id == "builtin:packer:upx-sections" for f in report.findings)  # type: ignore[attr-defined]


def test_findings_flag_a_large_virtual_raw_gap(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    pe.add_section(".big", size=0x200, virtual_size=0x200 + 2 * 1024 * 1024)
    report = _scan_bytes(tmp_path, pe.build())
    assert any(f.id.startswith("builtin:anomaly:virtual-raw-gap") for f in report.findings)  # type: ignore[attr-defined]


def test_findings_flag_unusual_alignment(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.section_alignment = 0x200
    pe.file_alignment = 0x400  # file alignment exceeds section alignment
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    report = _scan_bytes(tmp_path, pe.build())
    assert any(f.id == "builtin:anomaly:unusual-alignment" for f in report.findings)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# RVA / string / alignment helpers (direct)
# --------------------------------------------------------------------------- #
def _layout() -> object:
    return _parse_layout(_sample("x64", imports=False, tls=False, dotnet=False))


def test_rva_raw_span_rejects_a_bad_request() -> None:
    with pytest.raises(PeFormatError, match="non-negative RVA and positive size"):
        _rva_raw_span(_layout(), -1, size=4)  # type: ignore[arg-type]


def test_rva_raw_span_maps_inside_the_headers() -> None:
    layout = _layout()
    offset, limit = _rva_raw_span(layout, 0x10, size=4)  # type: ignore[arg-type]
    assert offset == 0x10
    assert limit == layout.size_of_headers  # type: ignore[attr-defined]


def test_rva_raw_span_rejects_a_range_crossing_the_header_boundary() -> None:
    layout = _layout()
    soh = layout.size_of_headers  # type: ignore[attr-defined]
    with pytest.raises(PeFormatError, match="outside PE headers"):
        _rva_raw_span(layout, soh - 2, size=8)  # type: ignore[arg-type]


def test_rva_raw_span_rejects_an_unmapped_rva() -> None:
    with pytest.raises(PeFormatError, match="not mapped by the PE image"):
        _rva_raw_span(_layout(), 0x7000000, size=4)  # type: ignore[arg-type]


def test_rva_raw_span_rejects_a_range_past_section_raw_data() -> None:
    layout = _layout()
    section = layout.sections[0]  # type: ignore[attr-defined]
    rva = section.virtual_address + section.raw_size - 2
    with pytest.raises(PeFormatError, match="outside section raw data"):
        _rva_raw_span(layout, rva, size=8)  # type: ignore[arg-type]


def test_read_c_string_rejects_an_out_of_range_offset() -> None:
    with pytest.raises(PeFormatError, match="outside the input"):
        _read_c_string(b"abc", 5)


def test_read_c_string_rejects_a_limit_before_the_offset() -> None:
    with pytest.raises(PeFormatError, match="outside its PE section"):
        _read_c_string(b"abcdef", 3, limit=2)


def test_read_c_string_rejects_an_unterminated_string() -> None:
    with pytest.raises(PeFormatError, match="unterminated or exceeds"):
        _read_c_string(b"abcdef", 0)


def test_entropy_of_empty_data_is_zero() -> None:
    assert _entropy(b"") == 0.0


def test_alignment_is_conventional_rejects_bad_alignments() -> None:
    assert _alignment_is_conventional(0x1000, 0x300) is False  # file not power of two
    assert _alignment_is_conventional(0x1500, 0x200) is False  # section not power of two


def test_slice_rejects_a_truncated_span() -> None:
    with pytest.raises(PeFormatError, match="structure is truncated"):
        _slice(b"abc", 0, 5)


# --------------------------------------------------------------------------- #
# _validate_layout: a section that maps nothing
# --------------------------------------------------------------------------- #
def test_validate_accepts_a_section_with_zero_mapped_size(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    pe.add_section(".z", size=0x400)
    data = pe.build()
    data = _patch(data, "<I", _SECTION_TABLE + 40 + 8, 0)  # VirtualSize = 0
    data = _patch(data, "<I", _SECTION_TABLE + 40 + 16, 0)  # RawSize = 0
    report = _scan_bytes(tmp_path, data)
    assert {s.name for s in report.pe.sections} == {".text", ".z"}  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# _parse_imports edge and limit branches
# --------------------------------------------------------------------------- #
_ORDINAL_FLAG_64 = 1 << 63


def test_import_descriptor_without_a_thunk_table_is_rejected(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    idata = pe.add_section(".idata", size=0x400)
    name_rva = pe.rva(idata, 0x100)
    pe.write(idata, 0x100, b"A.dll\0")
    pe.write(idata, 0, struct.pack("<IIIII", 0, 0, 0, name_rva, 0))  # no OFT/FT
    pe.directories[1] = (pe.rva(idata, 0), 40)
    with pytest.raises(PeFormatError, match="no thunk table"):
        _scan_bytes(tmp_path, pe.build())


def test_import_library_count_is_bounded(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    idata = pe.add_section(".idata", size=0x2000)
    name_rva = pe.rva(idata, 0x1F00)
    pe.write(idata, 0x1F00, b"a\0")
    thunk_rva = pe.rva(idata, 0x1F10)  # a single null thunk -> zero functions
    pe.write(idata, 0x1F10, b"\0" * 8)
    descriptors = 257
    for index in range(descriptors):
        pe.write(idata, index * 20, struct.pack("<IIIII", thunk_rva, 0, 0, name_rva, thunk_rva))
    pe.directories[1] = (pe.rva(idata, 0), descriptors * 20)
    report = _scan_bytes(tmp_path, pe.build())
    assert report.pe.imports.truncated  # type: ignore[attr-defined]
    assert report.pe.imports.library_count == 256  # type: ignore[attr-defined]


def test_import_function_count_is_bounded(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    idata = pe.add_section(".idata", size=0x21000)
    name_rva = pe.rva(idata, 0x30)
    pe.write(idata, 0x30, b"K.dll\0")
    thunk_rva = pe.rva(idata, 0x100)
    thunks = b"".join(struct.pack("<Q", _ORDINAL_FLAG_64 | 1) for _ in range(16385)) + b"\0" * 8
    pe.write(idata, 0x100, thunks)
    pe.write(idata, 0, struct.pack("<IIIII", thunk_rva, 0, 0, name_rva, thunk_rva))
    pe.directories[1] = (pe.rva(idata, 0), 40)
    report = _scan_bytes(tmp_path, pe.build())
    assert report.pe.imports.truncated  # type: ignore[attr-defined]
    assert report.pe.imports.function_count == 16384  # type: ignore[attr-defined]


def test_import_thunk_table_without_a_null_terminator_is_bounded(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    idata = pe.add_section(".idata", size=0x40)
    name_rva = pe.rva(idata, 0x18)
    pe.write(idata, 0x18, b"a\0")
    thunk_rva = pe.rva(idata, 0x28)
    # Three ordinal thunks running to the raw boundary with no null terminator.
    for slot in range(3):
        pe.write(idata, 0x28 + slot * 8, struct.pack("<Q", _ORDINAL_FLAG_64 | 1))
    pe.write(idata, 0, struct.pack("<IIIII", thunk_rva, 0, 0, name_rva, thunk_rva))
    pe.directories[1] = (pe.rva(idata, 0), 20)
    report = _scan_bytes(tmp_path, pe.build())
    assert report.pe.imports.function_count == 3  # type: ignore[attr-defined]
    assert report.pe.imports.truncated  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# _parse_tls edge and limit branches
# --------------------------------------------------------------------------- #
def _tls_pe(directory: bytes, *, size: int = 40) -> tuple[_SyntheticPe, bytes]:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    tls = pe.add_section(".tls", size=0x800)
    pe.write(tls, 0, directory)
    pe.directories[9] = (pe.rva(tls, 0), size)
    return pe, pe.build()


def test_tls_directory_smaller_than_its_header_is_rejected(tmp_path: Path) -> None:
    _pe, data = _tls_pe(b"\0" * 40, size=10)
    with pytest.raises(PeFormatError, match="TLS directory is smaller"):
        _scan_bytes(tmp_path, data)


def test_tls_without_a_callback_array_reports_no_callbacks(tmp_path: Path) -> None:
    _pe, data = _tls_pe(struct.pack("<QQQQII", 0, 0, 0, 0, 0, 0))
    report = _scan_bytes(tmp_path, data)
    assert report.pe.tls.present  # type: ignore[attr-defined]
    assert report.pe.tls.callback_count == 0  # type: ignore[attr-defined]


def test_tls_callback_array_before_image_base_is_rejected(tmp_path: Path) -> None:
    _pe, data = _tls_pe(struct.pack("<QQQQII", 0, 0, 0, 1, 0, 0))  # VA below ImageBase
    with pytest.raises(PeFormatError, match="precedes ImageBase"):
        _scan_bytes(tmp_path, data)


def test_tls_callback_count_is_bounded(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(".text", size=0x400, characteristics=_EXEC)
    tls = pe.add_section(".tls", size=0x800)
    pe.add_tls(tls, list(range(1, 130)))  # 129 callbacks trips the 128 cap
    report = _scan_bytes(tmp_path, pe.build())
    assert report.pe.tls.truncated  # type: ignore[attr-defined]
    assert report.pe.tls.callback_count == 128  # type: ignore[attr-defined]

"""Deterministic coverage of the built-in PE parser without a native fixture.

``test_pe_hostile_input`` mutates a compiled ``console_fixture.exe``; the hosted
quality job has no native build step, so those cases skip and the parser's
structural guards go unexercised there. These tests instead craft PE bytes in
Python -- a valid PE32+ image plus targeted malformations and directory tables
-- so every layout guard, import/TLS/CLR reader, and finding heuristic runs on
every platform.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture
from headless_re_mcp.detection.models import SignatureSummary
from headless_re_mcp.detection.pe import (
    PeFormatError,
    _alignment_is_conventional,
    _architecture,
    _classify_clr,
    _directory,
    _entropy,
    _is_power_of_two,
    _Layout,
    _overlay,
    _parse_imports,
    _parse_tls,
    _read_c_string,
    _read_pe_bytes,
    _rva_raw_span,
    _rva_to_offset,
    _Section,
    _section_for_rva,
    _signature_summary,
    _slice,
    _validate_layout,
    scan_pe,
)

IMAGE_BASE = 0x140000000


# --------------------------------------------------------------------------
# byte / string / entropy primitives
# --------------------------------------------------------------------------


def test_slice_rejects_out_of_bounds() -> None:
    assert _slice(b"abcdef", 1, 3) == b"bcd"
    with pytest.raises(PeFormatError, match="truncated"):
        _slice(b"abc", 2, 4)
    with pytest.raises(PeFormatError):
        _slice(b"abc", -1, 1)


def test_read_c_string_bounds_and_termination() -> None:
    data = b"AB\0rest"
    assert _read_c_string(data, 0) == "AB"
    with pytest.raises(PeFormatError, match="outside the input"):
        _read_c_string(data, len(data))
    with pytest.raises(PeFormatError, match="outside its PE section"):
        _read_c_string(data, 2, limit=1)
    with pytest.raises(PeFormatError, match="unterminated"):
        _read_c_string(b"no-null-here", 0)


def test_entropy_empty_and_uniform() -> None:
    assert _entropy(b"") == 0.0
    assert _entropy(bytes(range(256))) == pytest.approx(8.0, abs=1e-6)


@pytest.mark.parametrize(
    ("section_alignment", "file_alignment", "expected"),
    [
        (0x1000, 0x200, True),
        (0x1000, 0x300, False),  # file alignment not a power of two
        (0x1000, 0x100, False),  # file alignment below the 0x200 floor
        (0x300, 0x200, False),  # section alignment not a power of two
        (0x200, 0x1000, False),  # section alignment below file alignment
    ],
)
def test_alignment_conventions(section_alignment: int, file_alignment: int, expected: bool) -> None:
    assert _alignment_is_conventional(section_alignment, file_alignment) is expected


def test_is_power_of_two() -> None:
    assert _is_power_of_two(0x1000) is True
    assert _is_power_of_two(0) is False
    assert _is_power_of_two(0x300) is False


def test_architecture_maps_known_and_rejects_unknown() -> None:
    assert _architecture(0x014C) is Architecture.X86
    assert _architecture(0x8664) is Architecture.X64
    with pytest.raises(PeFormatError, match="unsupported PE machine"):
        _architecture(0xFFFF)


def test_read_pe_bytes_refuses_input_over_budget(tmp_path: Path) -> None:
    target = tmp_path / "big.bin"
    target.write_bytes(b"x" * 4096)
    assert _read_pe_bytes(target, max_file_size=8192) == b"x" * 4096
    with pytest.raises(PeFormatError, match="built-in scan limit"):
        _read_pe_bytes(target, max_file_size=1024)


# --------------------------------------------------------------------------
# RVA mapping and directory lookup
# --------------------------------------------------------------------------


def _mk_layout(
    directories: list[tuple[int, int]] | None = None,
    *,
    section: _Section | None = None,
    size_of_headers: int = 0x200,
    image_base: int = IMAGE_BASE,
) -> _Layout:
    dirs = directories if directories is not None else [(0, 0)] * 16
    sec = section or _Section(
        name=".text",
        virtual_size=0x400,
        virtual_address=0x1000,
        raw_size=0x400,
        raw_offset=0x200,
        characteristics=0x60000020,
    )
    return _Layout(
        machine=0x8664,
        architecture=Architecture.X64,
        characteristics=0x22,
        subsystem=3,
        dll_characteristics=0,
        image_base=image_base,
        image_size=0x4000,
        entry_point_rva=0x1000,
        section_alignment=0x1000,
        file_alignment=0x200,
        linker_version="14.0",
        size_of_headers=size_of_headers,
        directories=tuple(dirs),
        sections=(sec,),
    )


def test_directory_lookup_beyond_table_is_empty() -> None:
    layout = _mk_layout([(0x10, 0x20)])
    assert _directory(layout, 0) == (0x10, 0x20)
    assert _directory(layout, 5) == (0, 0)


def test_section_for_rva_hit_and_miss() -> None:
    layout = _mk_layout()
    assert _section_for_rva(layout.sections, 0x1100) is layout.sections[0]
    assert _section_for_rva(layout.sections, 0x9999) is None


def test_rva_raw_span_maps_and_guards() -> None:
    layout = _mk_layout()
    offset, limit = _rva_raw_span(layout, 0x1000, size=8)
    assert (offset, limit) == (0x200, 0x600)
    # within the header window
    assert _rva_raw_span(layout, 0x10, size=8) == (0x10, 0x200)
    assert _rva_to_offset(layout, 0x1000, size=4) == 0x200

    with pytest.raises(PeFormatError, match="non-negative RVA"):
        _rva_raw_span(layout, -1, size=8)
    with pytest.raises(PeFormatError, match="non-negative RVA"):
        _rva_raw_span(layout, 0x1000, size=0)
    with pytest.raises(PeFormatError, match="outside PE headers"):
        _rva_raw_span(layout, 0x1F0, size=0x40)
    with pytest.raises(PeFormatError, match="not mapped"):
        _rva_raw_span(layout, 0x8000, size=8)
    with pytest.raises(PeFormatError, match="outside section raw data"):
        _rva_raw_span(layout, 0x1000, size=0x600)


# --------------------------------------------------------------------------
# _validate_layout guard matrix
# --------------------------------------------------------------------------


def _sec(**kw: object) -> _Section:
    base: dict[str, object] = {
        "name": ".text",
        "virtual_size": 0x100,
        "virtual_address": 0x1000,
        "raw_size": 0x200,
        "raw_offset": 0x400,
        "characteristics": 0,
    }
    base.update(kw)
    return _Section(**base)  # type: ignore[arg-type]


def test_validate_layout_accepts_zero_sized_and_ordered_sections() -> None:
    empty = _Section(
        name="pad",
        virtual_size=0,
        virtual_address=0,
        raw_size=0,
        raw_offset=0,
        characteristics=0,
    )
    real = _sec()
    _validate_layout(
        bytes(0x600),
        image_base=IMAGE_BASE,
        image_size=0x2000,
        section_alignment=0x1000,
        file_alignment=0x200,
        size_of_headers=0x400,
        section_table_end=0x200,
        sections=(empty, real),
    )


def _validate(**kw: object) -> None:
    params: dict[str, object] = {
        "image_base": IMAGE_BASE,
        "image_size": 0x2000,
        "section_alignment": 0x1000,
        "file_alignment": 0x200,
        "size_of_headers": 0x400,
        "section_table_end": 0x200,
        "sections": (_sec(),),
    }
    params.update(kw)
    data = params.pop("data", bytes(0x600))
    _validate_layout(data, **params)  # type: ignore[arg-type]


def test_validate_layout_rejects_nonpositive_base_or_size() -> None:
    with pytest.raises(PeFormatError, match="image base and image size"):
        _validate(image_base=0)
    with pytest.raises(PeFormatError, match="image base and image size"):
        _validate(image_size=0)


def test_validate_layout_rejects_nonpositive_alignments() -> None:
    with pytest.raises(PeFormatError, match="alignments must be positive"):
        _validate(section_alignment=0)
    with pytest.raises(PeFormatError, match="alignments must be positive"):
        _validate(file_alignment=0)


def test_validate_layout_rejects_bad_size_of_headers() -> None:
    with pytest.raises(PeFormatError, match="SizeOfHeaders is outside"):
        _validate(size_of_headers=0)
    with pytest.raises(PeFormatError, match="SizeOfHeaders is outside"):
        _validate(size_of_headers=0x99999)


def test_validate_layout_rejects_headers_exceeding_image() -> None:
    with pytest.raises(PeFormatError, match="exceed SizeOfImage"):
        _validate(image_size=0x100, size_of_headers=0x400)
    with pytest.raises(PeFormatError, match="exceed SizeOfImage"):
        _validate(section_table_end=0x500, size_of_headers=0x400)


def test_validate_layout_rejects_truncated_or_overlapping_sections() -> None:
    with pytest.raises(PeFormatError, match="raw data is truncated"):
        _validate(sections=(_sec(raw_offset=0x400, raw_size=0x400),), data=bytes(0x500))
    with pytest.raises(PeFormatError, match="overlaps PE headers"):
        _validate(sections=(_sec(raw_offset=0x100, raw_size=0x100),))
    with pytest.raises(PeFormatError, match="exceeds SizeOfImage"):
        _validate(
            sections=(_sec(virtual_address=0x1000, virtual_size=0x4000, raw_size=0),),
        )
    overlap = (
        _sec(virtual_address=0x1000, virtual_size=0x1000, raw_size=0, name="a"),
        _sec(virtual_address=0x1800, virtual_size=0x100, raw_size=0, name="b"),
    )
    with pytest.raises(PeFormatError, match="overlapping virtual ranges"):
        _validate(sections=overlap, image_size=0x4000)


# --------------------------------------------------------------------------
# import directory reader
# --------------------------------------------------------------------------


def _import_data(*, descriptor_terminated: bool) -> bytearray:
    data = bytearray(0x800)
    # descriptor at rva 0x1000 -> offset 0x200
    struct.pack_into("<IIIII", data, 0x200, 0x1200, 0, 0, 0x1100, 0x1200)
    if descriptor_terminated:
        struct.pack_into("<IIIII", data, 0x214, 0, 0, 0, 0, 0)
    data[0x300:0x30D] = b"KERNEL32.dll\0"  # name at rva 0x1100 -> offset 0x300
    # thunk table at rva 0x1200 -> offset 0x400
    struct.pack_into("<Q", data, 0x400, 0x1300)  # import by name
    struct.pack_into("<Q", data, 0x408, 1 << 63)  # ordinal import
    struct.pack_into("<Q", data, 0x410, 0)  # terminator
    data[0x500:0x502] = b"\0\0"  # hint
    data[0x502:0x50F] = b"VirtualAlloc\0"  # name at rva 0x1300 -> offset 0x500
    return data


def test_parse_imports_absent_directory() -> None:
    summary = _parse_imports(b"", _mk_layout())
    assert summary.library_count == 0
    assert summary.function_count == 0


def test_parse_imports_rejects_undersized_directory() -> None:
    layout = _mk_layout([(0, 0)] * 16)
    dirs = list(layout.directories)
    dirs[1] = (0x1000, 10)
    layout = _mk_layout(dirs)
    with pytest.raises(PeFormatError, match="smaller than one descriptor"):
        _parse_imports(bytes(0x800), layout)


def test_parse_imports_rejects_descriptor_without_thunk() -> None:
    data = bytearray(0x800)
    struct.pack_into("<IIIII", data, 0x200, 0, 0, 0, 0x1100, 0)
    data[0x300:0x30D] = b"KERNEL32.dll\0"
    dirs = [(0, 0)] * 16
    dirs[1] = (0x1000, 20)
    with pytest.raises(PeFormatError, match="no thunk table"):
        _parse_imports(bytes(data), _mk_layout(dirs))


def test_parse_imports_reads_named_and_ordinal_thunks() -> None:
    data = _import_data(descriptor_terminated=True)
    dirs = [(0, 0)] * 16
    dirs[1] = (0x1000, 40)
    summary = _parse_imports(bytes(data), _mk_layout(dirs))
    assert summary.library_count == 1
    assert summary.function_count == 2
    assert summary.ordinal_count == 1
    assert summary.libraries == ("KERNEL32.dll",)
    assert summary.suspicious_apis == ("VirtualAlloc",)
    assert summary.truncated is False


def test_parse_imports_marks_truncation_when_table_is_not_null_terminated() -> None:
    data = _import_data(descriptor_terminated=False)
    dirs = [(0, 0)] * 16
    dirs[1] = (0x1000, 20)
    summary = _parse_imports(bytes(data), _mk_layout(dirs))
    assert summary.library_count == 1
    assert summary.truncated is True


# --------------------------------------------------------------------------
# TLS directory reader
# --------------------------------------------------------------------------


def _tls_layout(callbacks_va: int, size: int = 40) -> tuple[bytes, _Layout]:
    data = bytearray(0x800)
    # callbacks pointer lives at tls_offset + 24 for PE32+ (tls_offset == 0x200)
    struct.pack_into("<Q", data, 0x218, callbacks_va)
    # callback array at rva 0x1200 -> offset 0x400
    struct.pack_into("<Q", data, 0x400, 0xDEADBEEF)
    struct.pack_into("<Q", data, 0x408, 0)
    dirs = [(0, 0)] * 16
    dirs[9] = (0x1000, size)
    return bytes(data), _mk_layout(dirs)


def test_parse_tls_absent_directory() -> None:
    summary = _parse_tls(bytes(0x800), _mk_layout())
    assert summary.present is False
    assert summary.callback_count == 0


def test_parse_tls_rejects_undersized_directory() -> None:
    _, layout = _tls_layout(0, size=10)
    with pytest.raises(PeFormatError, match="smaller than its architecture"):
        _parse_tls(bytes(0x800), layout)


def test_parse_tls_empty_callback_pointer_is_present_but_zero() -> None:
    data, layout = _tls_layout(0)
    summary = _parse_tls(data, layout)
    assert summary.present is True
    assert summary.callback_count == 0


def test_parse_tls_rejects_callback_va_before_image_base() -> None:
    data, layout = _tls_layout(IMAGE_BASE - 1)
    with pytest.raises(PeFormatError, match="precedes ImageBase"):
        _parse_tls(data, layout)


def test_parse_tls_reads_callback_array() -> None:
    data, layout = _tls_layout(IMAGE_BASE + 0x1200)
    summary = _parse_tls(data, layout)
    assert summary.present is True
    assert summary.callback_count == 1
    assert summary.callbacks == (0xDEADBEEF,)


def test_parse_tls_marks_truncation_without_null_terminator() -> None:
    data = bytearray(0x800)
    struct.pack_into("<Q", data, 0x218, IMAGE_BASE + 0x1200)
    # Fill the callback array's whole raw window (0x400..0x600) with non-null
    # pointers so the loop exits on its bound instead of a terminator.
    for offset in range(0x400, 0x600, 8):
        struct.pack_into("<Q", data, offset, 0xCAFE0000 + offset)
    dirs = [(0, 0)] * 16
    dirs[9] = (0x1000, 40)
    summary = _parse_tls(bytes(data), _mk_layout(dirs))
    assert summary.present is True
    assert summary.truncated is True


# --------------------------------------------------------------------------
# CLR / .NET classification
# --------------------------------------------------------------------------


def _clr_layout(rva: int, size: int) -> _Layout:
    dirs = [(0, 0)] * 16
    dirs[14] = (rva, size)
    return _mk_layout(dirs)


def test_classify_clr_absent() -> None:
    assert _classify_clr(bytes(0x800), _mk_layout()) is None


def test_classify_clr_small_directory_is_a_hint() -> None:
    assert _classify_clr(bytes(0x800), _clr_layout(0x1000, 8)) == "hint"


def test_classify_clr_unmapped_directory_is_a_hint() -> None:
    assert _classify_clr(bytes(0x800), _clr_layout(0x9000, 32)) == "hint"


def _clr_data(meta_sig: bytes, *, meta_rva: int = 0x1100) -> bytes:
    data = bytearray(0x800)
    # COR20 header at rva 0x1000 -> offset 0x200; MetaData directory at +8
    struct.pack_into("<II", data, 0x208, meta_rva, 16)  # meta rva, size 16
    data[0x300 : 0x300 + len(meta_sig)] = meta_sig  # rva 0x1100 -> offset 0x300
    return bytes(data)


def test_classify_clr_directory_without_bsjb_is_a_hint() -> None:
    assert _classify_clr(_clr_data(b"XXXX"), _clr_layout(0x1000, 72)) == "hint"


def test_classify_clr_null_metadata_pointer_is_a_hint() -> None:
    assert _classify_clr(_clr_data(b"BSJB", meta_rva=0), _clr_layout(0x1000, 72)) == "hint"


# --------------------------------------------------------------------------
# signature directory and overlay accounting
# --------------------------------------------------------------------------


def test_signature_summary_status_by_directory_shape() -> None:
    layout = _mk_layout()
    assert _signature_summary(bytes(0x40), layout).status == "absent"

    unaligned = _mk_layout([(0, 0)] * 4 + [(0x201, 0x10)] + [(0, 0)] * 11)
    assert _signature_summary(bytes(0x400), unaligned).status == "malformed"

    beyond_eof = _mk_layout([(0, 0)] * 4 + [(0x8, 0x100000)] + [(0, 0)] * 11)
    assert _signature_summary(bytes(0x400), beyond_eof).status == "malformed"

    present = _mk_layout([(0, 0)] * 4 + [(0x8, 0x10)] + [(0, 0)] * 11)
    summary = _signature_summary(bytes(0x400), present)
    assert summary.status == "present_unverified"
    assert summary.certificate_offset == 0x8


def test_overlay_extends_past_certificate_table() -> None:
    layout = _mk_layout()
    signature = SignatureSummary(
        status="present_unverified", certificate_offset=0x600, certificate_size=0x80
    )
    offset, size = _overlay(bytes(0x800), layout, signature)
    assert offset == 0x680
    assert size == 0x800 - 0x680


def test_classify_clr_with_bsjb_metadata_is_verified() -> None:
    assert _classify_clr(_clr_data(b"BSJB"), _clr_layout(0x1000, 72)) == "verified"


# --------------------------------------------------------------------------
# end-to-end scan_pe over crafted images
# --------------------------------------------------------------------------


def _valid_pe(
    *,
    section_name: bytes = b".text\0\0\0",
    characteristics: int = 0x60000020,
    virtual_size: int = 0x100,
    raw_size: int = 0x200,
    raw_offset: int = 0x400,
    size_of_image: int = 0x2000,
    size_of_headers: int = 0x400,
    file_alignment: int = 0x200,
    optional_size: int = 0xF0,
    machine: int = 0x8664,
    magic: int = 0x20B,
    n_sections: int = 1,
    total: int = 0x600,
    fill_entropy: bool = False,
) -> bytes:
    b = bytearray(total)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", b, 0x84, machine, n_sections, 0, 0, 0, optional_size, 0x22)
    struct.pack_into("<HBB", b, 0x98, magic, 14, 0)
    struct.pack_into("<I", b, 0xA8, 0x1000)  # entry point rva
    struct.pack_into("<Q", b, 0xB0, IMAGE_BASE)
    struct.pack_into("<II", b, 0xB8, 0x1000, file_alignment)
    struct.pack_into("<II", b, 0xD0, size_of_image, size_of_headers)
    struct.pack_into("<HH", b, 0xDC, 3, 0)
    struct.pack_into("<I", b, 0x104, 16)
    b[0x188:0x190] = section_name
    struct.pack_into("<IIII", b, 0x190, virtual_size, 0x1000, raw_size, raw_offset)
    struct.pack_into("<I", b, 0x1AC, characteristics)
    if fill_entropy:
        b[raw_offset : raw_offset + raw_size] = (bytes(range(256)) * ((raw_size // 256) + 1))[
            :raw_size
        ]
    return bytes(b)


def _scan_bytes(blob: bytes, tmp_path: Path) -> object:
    path = tmp_path / "crafted.exe"
    path.write_bytes(blob)
    return scan_pe(path)


def test_scan_valid_pe_reports_format_and_sparse_imports(tmp_path: Path) -> None:
    report = _scan_bytes(_valid_pe(), tmp_path)
    assert report.format == "PE"  # type: ignore[attr-defined]
    assert report.architecture == "x64"  # type: ignore[attr-defined]
    ids = {finding.id for finding in report.findings}  # type: ignore[attr-defined]
    assert "builtin:format:pe" in ids
    assert "builtin:anomaly:sparse-imports" in ids


def test_scan_pe_validates_max_file_size_argument(tmp_path: Path) -> None:
    path = tmp_path / "ok.exe"
    path.write_bytes(_valid_pe())
    with pytest.raises(TypeError, match="must be an integer"):
        scan_pe(path, max_file_size=True)
    with pytest.raises(ValueError, match="must not be negative"):
        scan_pe(path, max_file_size=-1)


@pytest.mark.parametrize(
    ("blob", "match"),
    [
        (b"", "valid DOS header"),
        (b"XX" + bytes(0x40), "valid DOS header"),
        (b"MZ" + bytes(0x3A) + struct.pack("<I", 0x7FFFFFFF) + bytes(2), "offset is outside"),
        (
            b"MZ" + bytes(0x3A) + struct.pack("<I", 0x80) + bytes(0x80) + b"XX\0\0" + bytes(0x40),
            "valid PE signature",
        ),
    ],
)
def test_scan_refuses_broken_dos_and_pe_headers(blob: bytes, match: str, tmp_path: Path) -> None:
    with pytest.raises(PeFormatError, match=match):
        _scan_bytes(blob, tmp_path)


def test_scan_refuses_zero_section_count(tmp_path: Path) -> None:
    with pytest.raises(PeFormatError, match="section count is outside"):
        _scan_bytes(_valid_pe(n_sections=0), tmp_path)


def test_scan_rejects_non_regular_file(tmp_path: Path) -> None:
    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(PeFormatError, match="not a regular file"):
        scan_pe(directory)


def test_scan_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "big.exe"
    path.write_bytes(_valid_pe())
    with pytest.raises(PeFormatError, match="built-in scan limit"):
        scan_pe(path, max_file_size=16)


@pytest.mark.parametrize(
    ("blob_kwargs", "match"),
    [
        ({"optional_size": 0xFFFF}, "optional header is truncated"),
        ({"magic": 0x10B}, "inconsistent with its machine type"),
        ({"optional_size": 112}, "data directory array is truncated"),
        ({"machine": 0x1FFF}, "unsupported PE machine"),
    ],
)
def test_scan_refuses_malformed_optional_header(
    blob_kwargs: dict[str, int], match: str, tmp_path: Path
) -> None:
    with pytest.raises(PeFormatError, match=match):
        _scan_bytes(_valid_pe(**blob_kwargs), tmp_path)  # type: ignore[arg-type]


def test_scan_flags_upx_rwx_entropy_and_virtual_gap(tmp_path: Path) -> None:
    blob = _valid_pe(
        section_name=b"UPX0\0\0\0\0",
        characteristics=0xE0000020,  # read | write | execute
        virtual_size=0x200000,
        raw_size=0x200,
        size_of_image=0x300000,
        fill_entropy=True,
    )
    report = _scan_bytes(blob, tmp_path)
    ids = {finding.id for finding in report.findings}  # type: ignore[attr-defined]
    assert "builtin:packer:upx-sections" in ids
    assert any(fid.startswith("builtin:anomaly:rwx-section") for fid in ids)
    assert any(fid.startswith("builtin:anomaly:high-entropy") for fid in ids)
    assert any(fid.startswith("builtin:anomaly:virtual-raw-gap") for fid in ids)


def test_scan_flags_unusual_alignment(tmp_path: Path) -> None:
    report = _scan_bytes(_valid_pe(file_alignment=0x300), tmp_path)
    ids = {finding.id for finding in report.findings}  # type: ignore[attr-defined]
    assert "builtin:anomaly:unusual-alignment" in ids


def test_scan_flags_non_executable_entry_point(tmp_path: Path) -> None:
    report = _scan_bytes(_valid_pe(characteristics=0x40000000), tmp_path)
    ids = {finding.id for finding in report.findings}  # type: ignore[attr-defined]
    assert "builtin:anomaly:entry-point-not-executable" in ids


def test_scan_flags_overlay_bytes(tmp_path: Path) -> None:
    report = _scan_bytes(_valid_pe(total=0x700), tmp_path)
    ids = {finding.id for finding in report.findings}  # type: ignore[attr-defined]
    assert "builtin:anomaly:overlay" in ids


def test_scan_refuses_truncated_section_table(tmp_path: Path) -> None:
    truncated = _valid_pe()[:0x1A0]  # header ends before the 40-byte section entry
    with pytest.raises(PeFormatError, match="section table is truncated"):
        _scan_bytes(truncated, tmp_path)


def _rich_pe() -> bytes:
    """A valid PE wiring import, TLS, CLR, and a malformed security directory.

    Every table maps inside the single section's raw window (rva 0x1000 == file
    offset 0x400), so one scan drives the loader-API, TLS-callback,
    .NET-verified, and malformed-certificate findings together.
    """
    b = bytearray(_valid_pe(virtual_size=0x600, raw_size=0x600, raw_offset=0x400, total=0xA00))
    directories = 0x108
    struct.pack_into("<II", b, directories + 1 * 8, 0x1000, 40)  # import
    struct.pack_into("<II", b, directories + 4 * 8, 0x901, 0x10)  # security (misaligned)
    struct.pack_into("<II", b, directories + 9 * 8, 0x1100, 40)  # tls
    struct.pack_into("<II", b, directories + 14 * 8, 0x1200, 72)  # com descriptor

    # import descriptor at rva 0x1000 -> offset 0x400, then a null terminator
    struct.pack_into("<IIIII", b, 0x400, 0x1300, 0, 0, 0x1280, 0x1300)
    b[0x680:0x68D] = b"KERNEL32.dll\0"  # name at rva 0x1280 -> offset 0x680
    struct.pack_into("<Q", b, 0x700, 0x1380)  # thunk -> suspicious import by name
    struct.pack_into("<Q", b, 0x708, 0x13A0)  # thunk -> benign import by name
    struct.pack_into("<Q", b, 0x710, 0)  # terminator
    b[0x782:0x78F] = b"VirtualAlloc\0"  # hint+name at rva 0x1380 -> offset 0x780
    b[0x7A2:0x7A9] = b"Benign\0"  # hint+name at rva 0x13A0 -> offset 0x7A0

    # tls directory at rva 0x1100 -> offset 0x500; callbacks pointer at +24
    struct.pack_into("<Q", b, 0x518, IMAGE_BASE + 0x1180)
    struct.pack_into("<Q", b, 0x580, IMAGE_BASE + 0x1000)  # one callback
    struct.pack_into("<Q", b, 0x588, 0)  # terminator

    # COR20 header at rva 0x1200 -> offset 0x600; MetaData directory at +8
    struct.pack_into("<II", b, 0x608, 0x1400, 16)  # meta rva 0x1400, size 16
    b[0x800:0x804] = b"BSJB"  # metadata magic at rva 0x1400 -> offset 0x800
    return bytes(b)


def test_scan_rich_pe_surfaces_dotnet_tls_loader_and_certificate_findings(
    tmp_path: Path,
) -> None:
    report = _scan_bytes(_rich_pe(), tmp_path)
    ids = {finding.id for finding in report.findings}  # type: ignore[attr-defined]
    assert report.pe.dotnet is True  # type: ignore[attr-defined]
    assert "builtin:runtime:dotnet" in ids
    assert "builtin:anomaly:loader-apis" in ids
    assert "builtin:anomaly:tls-callbacks" in ids
    assert "builtin:anomaly:malformed-certificate-directory" in ids
    imports = report.pe.imports  # type: ignore[attr-defined]
    assert imports.function_count == 2
    assert imports.suspicious_apis == ("VirtualAlloc",)

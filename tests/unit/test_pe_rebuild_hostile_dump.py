"""The rebuilder maps a dump whose contents the target process wrote.

Every length it computes comes out of headers the sample controls, and they are
used as allocation sizes. Two of them were unbounded: measured against a 15 KB
image, a FileAlignment of 0x40000000 had not returned after twenty seconds, and
a section declaring 0x7fffffff virtual bytes produced a 2 GB file.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from headless_re_mcp.unpack.pe_rebuild import (
    MAX_SECTIONS,
    PeRebuildError,
    parse_runtime_headers,
    remap_dump_to_file,
)

FIXTURE = Path(__file__).resolve().parents[2] / "artifacts" / "fixtures-x64" / "console_fixture.exe"

_needs_fixture = pytest.mark.skipif(not FIXTURE.is_file(), reason="fixture binary is not built")


def _offsets() -> tuple[int, int]:
    raw = FIXTURE.read_bytes()
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    coff = e_lfanew + 4
    optional = coff + 20
    return optional, optional + struct.unpack_from("<H", raw, coff + 16)[0]


def _with(offset: int, packed: bytes) -> bytes:
    raw = bytearray(FIXTURE.read_bytes())
    raw[offset : offset + len(packed)] = packed
    return bytes(raw)


@_needs_fixture
def test_an_alignment_the_format_does_not_allow_is_refused() -> None:
    """FileAlignment multiplies the headers and every section in turn.

    At 0x40000000 each of them rounds up to a gigabyte, and the rebuild had not
    finished after twenty seconds. The specification caps this at 64 KiB, so a
    dump claiming more is refused by name rather than acted on.
    """
    optional, _table = _offsets()
    dump = _with(optional + 36, struct.pack("<I", 0x40000000))

    started = time.perf_counter()
    with pytest.raises(PeRebuildError) as caught:
        remap_dump_to_file(dump)

    assert "FileAlignment" in str(caught.value)
    assert time.perf_counter() - started < 5.0, "and refused promptly, not after the work"


@_needs_fixture
def test_a_section_cannot_be_larger_than_the_dump_it_came_from() -> None:
    """A SizeOfImage dump holds the whole image, so no section inside it is bigger.

    The declared size was being used as an allocation: 0x7fffffff turned a 15 KB
    dump into a 2 GB file. Truncated to the dump instead, and said out loud,
    because a caller comparing sizes needs to know the section was not whole.
    """
    _optional, table = _offsets()
    dump = _with(table + 8, struct.pack("<I", 0x7FFFFFFF))

    rebuilt, report = remap_dump_to_file(dump)

    assert len(rebuilt) < 4 * len(dump), f"produced {len(rebuilt):,} bytes from {len(dump):,}"
    assert any("larger than" in warning for warning in report.warnings), report.warnings
    assert any("not trusted" in item for item in report.unfixed), report.unfixed


@_needs_fixture
def test_an_ordinary_dump_rebuilds_unchanged() -> None:
    """The bounds must not touch a dump that was telling the truth."""
    rebuilt, report = remap_dump_to_file(FIXTURE.read_bytes())

    assert len(rebuilt) > 0
    assert not [warning for warning in report.warnings if "larger than" in warning]


@pytest.mark.parametrize(
    ("label", "offset_kind", "value"),
    [
        ("zero file alignment", "file", 0),
        ("zero section alignment", "section", 0),
        ("64 KiB file alignment", "file", 0x10000),
    ],
)
@_needs_fixture
def test_alignments_within_the_format_are_still_accepted(
    label: str,
    offset_kind: str,
    value: int,
) -> None:
    """Only out-of-range values are refused; zero and the ceiling are not."""
    optional, _table = _offsets()
    offset = optional + (36 if offset_kind == "file" else 32)

    rebuilt, _report = remap_dump_to_file(_with(offset, struct.pack("<I", value)))

    assert len(rebuilt) > 0, label


@_needs_fixture
def test_the_import_rebuild_reads_the_same_headers_and_needs_the_same_bound() -> None:
    """The sibling call site, which pads the appended import section.

    Fixing remap_dump_to_file alone left this one behind: measured at a
    FileAlignment of 0x40000000, a 14 KB image produced a 2 GB output and
    peaked at 5 GB of heap on the way there, which is enough to take the
    machine with it.
    """
    from headless_re_mcp.unpack.pe_rebuild import rebuild_imports

    optional, _table = _offsets()
    entries = [
        {"kind": "api", "module": "kernel32.dll", "name": "GetProcAddress", "thunk_rva": 0x3000},
        {"kind": "api", "module": "kernel32.dll", "name": "LoadLibraryA", "thunk_rva": 0x3008},
    ]

    with pytest.raises(PeRebuildError) as caught:
        rebuild_imports(_with(optional + 36, struct.pack("<I", 0x40000000)), entries)
    assert "FileAlignment" in str(caught.value)

    within_the_format, _report = rebuild_imports(
        _with(optional + 36, struct.pack("<I", 0x10000)), entries
    )
    assert 0 < len(within_the_format) < 1_000_000, "the format's own ceiling still works"


def _craft_dump(
    *,
    sections: int,
    dump_size: int = 64 * 1024,
    overlap: bool = True,
) -> bytes:
    """A SizeOfImage-style dump whose section table the test controls.

    Overlapping sections each claim the whole dump at VA 0, which is what
    turns the count into an allocation multiplier: remap copies the dump
    once per section. Non-overlapping sections are a layout the loader
    could actually map.
    """
    pe_offset = 0x80
    optional_size = 0xE0
    file_header = pe_offset + 4
    optional = file_header + 20
    table = optional + optional_size
    section_span = 0x200
    if not overlap:
        dump_size = max(dump_size, sections * 0x1000 + section_span)
    dump_size = max(dump_size, table + sections * 40 + 0x200)
    data = bytearray(dump_size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, file_header, 0x14C)
    struct.pack_into("<H", data, file_header + 2, sections)
    struct.pack_into("<H", data, file_header + 16, optional_size)
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, dump_size)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 92, 16)
    for index in range(sections):
        off = table + index * 40
        va = 0 if overlap else index * 0x1000
        size = dump_size if overlap else section_span
        data[off : off + 8] = f".s{index}".encode()[:8].ljust(8, b"\0")
        struct.pack_into("<I", data, off + 8, size)
        struct.pack_into("<I", data, off + 12, va)
        struct.pack_into("<I", data, off + 16, size)
        struct.pack_into("<I", data, off + 20, 0)
    return bytes(data)


def _truncated_optional_header() -> bytes:
    """A valid MZ/PE up to the optional magic, then the buffer ends.

    SizeOfOptionalHeader is 2, so the optional-header truncation guard
    (optional + declared_size <= len) passes, yet parse_runtime_headers still
    reads fixed fields past it -- the entry point at optional+16, the data
    directory count at optional+92 -- which run off the end of this buffer.
    """
    pe_offset = 0x40
    file_header = pe_offset + 4
    optional = file_header + 20
    data = bytearray(optional + 2)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, file_header, 0x8664)
    struct.pack_into("<H", data, file_header + 2, 1)
    struct.pack_into("<H", data, file_header + 16, 2)
    struct.pack_into("<H", data, optional, 0x10B)
    return bytes(data)


def test_a_truncated_optional_header_is_a_pe_error_not_a_struct_error() -> None:
    """struct.error is not a ValueError, so an out-of-range unpack_from used to
    slip past the (ValueError, PeRebuildError) handlers both call sites use --
    stub_calls and service_dynamic_inspect.pe_headers_runtime -- and land on the
    outer ``except BaseException`` as an internal_error incident. A hostile
    SizeOfOptionalHeader lets a fixed-offset read run off a short buffer, so it
    must surface as the module's own PeRebuildError instead.
    """
    with pytest.raises(PeRebuildError) as caught:
        parse_runtime_headers(_truncated_optional_header())
    assert "past the end" in str(caught.value)


def test_a_well_formed_crafted_image_still_parses() -> None:
    """The read guard must not reject an image whose headers fit the buffer."""
    headers = parse_runtime_headers(_craft_dump(sections=2, overlap=False))
    assert len(headers["sections"]) == 2


def test_a_section_count_the_loader_will_not_map_is_refused() -> None:
    """NumberOfSections multiplies the dump: each section is copied out of it.

    The per-section size is already capped at the dump, so a count the loader
    will not accept was the remaining multiplier. Measured at 2000 sections on
    an 81 KB dump: 162 MB out, 496 MB peak heap, while the memory gate -- which
    only sees the dump -- estimated 0.32 MB and let it through. 400 sections on
    a 1 MB dump: 419 MB out, 842 MB peak. The loader's own ceiling is 96.
    """
    dump = _craft_dump(sections=200)

    started = time.perf_counter()
    with pytest.raises(PeRebuildError) as caught:
        remap_dump_to_file(dump)

    assert "NumberOfSections" in str(caught.value)
    assert str(MAX_SECTIONS) in str(caught.value)
    assert time.perf_counter() - started < 5.0, "and refused promptly, not after the copies"


def test_the_loader_ceiling_still_rebuilds() -> None:
    """96 non-overlapping sections is what the loader accepts; still rebuild."""
    dump = _craft_dump(sections=MAX_SECTIONS, overlap=False)

    rebuilt, _report = remap_dump_to_file(dump)

    assert len(rebuilt) > 0
    assert len(rebuilt) < 4 * len(dump)


def test_overlapping_sections_that_multiply_the_dump_are_refused() -> None:
    """The count cap left the loader's 96 as a multiplier.

    Measured at 96 overlapping sections on a 1 MB dump: 101 MB out, 213 MB
    peak heap, 0.092s. The memory gate -- dump * 4 -- estimated 4 MB and
    let it through.
    """
    dump = _craft_dump(sections=MAX_SECTIONS, dump_size=1024 * 1024)

    started = time.perf_counter()
    with pytest.raises(PeRebuildError) as caught:
        remap_dump_to_file(dump)

    assert "section table" in str(caught.value)
    assert time.perf_counter() - started < 5.0, "and refused before the copies"

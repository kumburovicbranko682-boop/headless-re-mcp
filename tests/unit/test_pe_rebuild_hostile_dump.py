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

from headless_re_mcp.unpack.pe_rebuild import PeRebuildError, remap_dump_to_file

FIXTURE = Path(__file__).resolve().parents[2] / "artifacts" / "fixtures-x64" / "console_fixture.exe"

pytestmark = pytest.mark.skipif(not FIXTURE.is_file(), reason="fixture binary is not built")


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

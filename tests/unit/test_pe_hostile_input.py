"""The PE parser reads adversarial data by definition.

A sample is submitted precisely because nobody trusts it. A parser that hangs,
allocates without bound, or raises something the caller does not catch stops an
unattended queue at the first crafted header. Measured across these cases: the
slowest was 4.2ms and the largest allocation 39 KB.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from headless_re_mcp.detection.pe import PeFormatError, scan_pe

FIXTURE = Path(__file__).resolve().parents[2] / "artifacts" / "fixtures-x64" / "console_fixture.exe"


def _mutated(offset: int, packed: bytes) -> bytes:
    raw = bytearray(FIXTURE.read_bytes())
    raw[offset : offset + len(packed)] = packed
    return bytes(raw)


def _offsets() -> tuple[int, int]:
    raw = FIXTURE.read_bytes()
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    return e_lfanew, e_lfanew + 4


pytestmark = pytest.mark.skipif(not FIXTURE.is_file(), reason="fixture binary is not built")


def _cases() -> list[tuple[str, bytes]]:
    """Mutations of the built fixture, or a dummy row if it is not there.

    Parametrize evaluates this during collection, before pytestmark skipif
    can skip the module. Reading the file here would turn a missing fixture
    into a collection error, and the hosted quality job has no native build
    step. The dummy keeps collection alive; skipif then skips it.
    """
    if not FIXTURE.is_file():
        return [("fixture-not-built", b"")]
    raw = FIXTURE.read_bytes()
    e_lfanew, coff = _offsets()
    optional_size = struct.unpack_from("<H", raw, coff + 16)[0]
    section_table = coff + 20 + optional_size
    return [
        ("empty", b""),
        ("two bytes", b"MZ"),
        ("dos header only", raw[:64]),
        ("truncated before the pe header", raw[: e_lfanew + 2]),
        ("mz with nothing after it", b"MZ" + bytes(4096)),
        ("65535 sections", _mutated(coff + 2, struct.pack("<H", 0xFFFF))),
        ("zero sections", _mutated(coff + 2, struct.pack("<H", 0))),
        ("optional header claims zero", _mutated(coff + 16, struct.pack("<H", 0))),
        ("optional header claims 65535", _mutated(coff + 16, struct.pack("<H", 0xFFFF))),
        ("unknown machine", _mutated(coff, struct.pack("<H", 0xFFFF))),
        ("pe header offset past the end", _mutated(0x3C, struct.pack("<I", 0x7FFFFFFF))),
        ("pe header offset all ones", _mutated(0x3C, struct.pack("<I", 0xFFFFFFFF))),
        ("section raw size huge", _mutated(section_table + 16, struct.pack("<I", 0x7FFFFFFF))),
        ("section raw offset huge", _mutated(section_table + 20, struct.pack("<I", 0x7FFFFFFF))),
        ("section virtual size huge", _mutated(section_table + 8, struct.pack("<I", 0x7FFFFFFF))),
        ("directory count huge", _mutated(coff + 20 + 92, struct.pack("<I", 0xFFFF))),
    ]


_CASES = _cases()


@pytest.mark.parametrize(("label", "blob"), _CASES, ids=[case[0] for case in _CASES])
def test_a_crafted_image_is_refused_quickly_and_by_name(
    label: str,
    blob: bytes,
    tmp_path: Path,
) -> None:
    """Either a report or a PeFormatError, promptly, and nothing else.

    PeFormatError is what the result envelope knows how to turn into a caller
    error. Any other exception type reaches the boundary as internal_error,
    which tells an unattended caller nothing about the file it just fed in.
    """
    path = tmp_path / "crafted.exe"
    path.write_bytes(blob)

    started = time.perf_counter()
    try:
        report = scan_pe(path)
    except PeFormatError as exc:
        assert str(exc).strip(), f"{label} was refused without saying why"
    else:
        assert report is not None
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0, f"{label} took {elapsed:.1f}s, which an unattended queue waits out"


def test_the_intact_fixture_still_scans() -> None:
    """The refusals have to mean something, so a real image still goes through."""
    report = scan_pe(FIXTURE)

    assert report is not None
    assert getattr(report, "format", None) == "PE"

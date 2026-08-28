"""``code_nonzero_ratio`` must say "not measured" instead of inventing a zero.

The rebuild gate reads this ratio as hard evidence: ``service_unpack`` turns
anything under 0.05 into ``code_not_decrypted``, clears ``rebuild_allowed``,
downgrades ``iat_recoverable`` to ``iat_insufficient``, and on one path refuses
the call outright with ``iat_rebuild_blocked``. ``assess_pause_quality`` does the
same and forces ``quality="code_not_ready"``.

So the difference between "the CODE section is full of zeros" and "no code
section landed inside the dump" decides whether a rebuild is allowed, and the
analyser used to report both as a measured ``0.0``. It also abandoned the whole
nonzero measurement at the first out-of-range section -- while the E8/FF scanner
walked past it -- so one bogus section header could produce ``code_bytes: 0``
alongside a nonzero ``e8_total``, which is self-contradictory output.

These pin the honest contract: ``None`` when nothing was read, a real ``0.0``
only when zeros were actually counted, and every in-range section measured
regardless of what precedes it in the header. The negative-RVA guards belong to
the same failure: ``code_section_ranges`` accepted ``virtual_address: -1`` where
its sibling ``vmp_like_section_ranges`` already rejected it, and a negative RVA
slices from the *end* of the dump, measuring unrelated bytes as if they were
code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.unpack import stub_calls
from headless_re_mcp.unpack.pause_quality import assess_pause_quality
from headless_re_mcp.unpack.stub_calls import (
    analyze_dump_stub_coupling,
    code_section_ranges,
    count_stub_vs_api_calls,
)

_EXEC = 0x60000020  # MEM_EXECUTE | CODE | MEM_READ
_DATA = 0xC0000040  # INITIALIZED_DATA | READ | WRITE (non-executable)


def _sec(name: str, rva: object, size: object, chars: int = _EXEC) -> dict[str, Any]:
    return {
        "name": name,
        "virtual_address": rva,
        "virtual_size": size,
        "characteristics": chars,
    }


def _headers(sections: list[Any], *, arch: str = "x86") -> dict[str, Any]:
    return {"image_base": 0x400000, "architecture": arch, "sections": sections}


def _dump(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# --------------------------------------------------------------------------- #
# "not measured" is None, "measured zeros" is 0.0                             #
# --------------------------------------------------------------------------- #
def test_no_code_section_reports_an_unmeasured_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The classifier and the fallback both find nothing, so nothing was read."""
    dump = _dump(tmp_path / "stub-only.bin", bytes(0x4000))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        # The only executable section is an exact protector tuple: the classifier
        # drops it and the fallback refuses to recover a stub as code.
        lambda _data: _headers([_sec(".vmp0", 0x1000, 0x2000)]),
    )

    result = analyze_dump_stub_coupling(dump)

    assert result["ok"] is True
    assert result["code_sections"] == []
    assert result["code_bytes"] == 0
    assert result["code_nonzero_ratio"] is None


def test_a_code_section_outside_the_dump_reports_an_unmeasured_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A truncated dump read zero code bytes; that is unknown, not all-zero."""
    dump = _dump(tmp_path / "truncated.bin", bytes(0x400))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0x8000, 0x400)]),
    )

    result = analyze_dump_stub_coupling(dump)

    assert result["ok"] is True
    assert result["code_bytes"] == 0
    assert result["code_nonzero_ratio"] is None


def test_an_empty_dump_reports_an_unmeasured_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = _dump(tmp_path / "empty.bin", b"")
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0, 0x100)]),
    )

    result = analyze_dump_stub_coupling(dump)

    assert result["ok"] is True
    assert result["scanned_bytes"] == 0
    assert result["code_bytes"] == 0
    assert result["code_nonzero_ratio"] is None


def test_a_genuinely_zero_filled_code_section_still_reports_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real "code is still encrypted" signal must survive the fix.

    The section is inside the dump and every byte of it is zero, so 0.0 is a
    measurement and the gate is right to act on it.
    """
    dump = _dump(tmp_path / "zeroed.bin", bytes(0x2000))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0x1000, 0x400)]),
    )

    result = analyze_dump_stub_coupling(dump)

    assert result["code_bytes"] == 0x400
    assert result["code_nonzero_ratio"] == 0.0


# --------------------------------------------------------------------------- #
# one out-of-range section must not abandon the rest of the measurement       #
# --------------------------------------------------------------------------- #
def test_a_later_in_range_section_is_measured_after_an_out_of_range_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise code_bytes says 0 while the E8 scanner reports calls it found.

    The scanner skips past the out-of-range section and keeps going, so the two
    loops over the same section list have to agree about what was reachable.
    """
    data = bytearray(0x2000)
    data[0x1000:0x1400] = b"\x90" * 0x400
    data[0x1000] = 0xE8
    data[0x1001:0x1005] = (0x40).to_bytes(4, "little", signed=True)
    dump = _dump(tmp_path / "unordered.bin", bytes(data))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers(
            [
                # Declared past the end of the dump.
                _sec(".text", 0x8000, 0x400),
                # Inside the dump, and where the E8 scanner finds its call.
                _sec(".text", 0x1000, 0x400),
            ]
        ),
    )

    result = analyze_dump_stub_coupling(dump)

    assert result["e8_total"] == 1
    assert result["code_bytes"] == 0x400, "the in-range section must still be measured"
    assert result["code_nonzero_ratio"] is not None
    assert result["code_nonzero_ratio"] > 0


def test_the_byte_budget_still_stops_the_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Skipping unreachable sections must not turn the budget into a no-op."""
    dump = _dump(tmp_path / "budget.bin", bytes(b"\x90" * 0x2000))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0x0, 0x400), _sec(".text", 0x1000, 0x400)]),
    )

    result = analyze_dump_stub_coupling(dump, max_scan_bytes=0x200)

    assert result["code_bytes"] == 0x200


# --------------------------------------------------------------------------- #
# a negative RVA must not slice from the end of the dump                      #
# --------------------------------------------------------------------------- #
def test_code_section_ranges_rejects_a_negative_rva() -> None:
    """vmp_like_section_ranges already treats rva < 0 as invalid geometry."""
    assert code_section_ranges([_sec(".text", -1, 0x100)]) == []


def test_the_code_fallback_rejects_a_negative_rva(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The largest-executable fallback shares the classifier's geometry rules."""
    dump = _dump(tmp_path / "negative.bin", bytes(b"\x90" * 0x2000))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        # Executable but negatively based, so neither classifier may keep it;
        # ".data" is non-executable, leaving the fallback with no candidate.
        lambda _data: _headers(
            [_sec("weird", -0x100, 0x80), _sec(".data", 0x400, 0x200, chars=_DATA)]
        ),
    )

    result = analyze_dump_stub_coupling(dump)

    assert result["code_sections"] == []
    assert result["code_bytes"] == 0
    assert result["code_nonzero_ratio"] is None


def test_the_scanner_skips_a_negative_range_instead_of_reading_the_tail() -> None:
    """image[-0x100:-0x80] is real data, and counting it would invent calls."""
    image = bytearray(0x200)
    image[0x100] = 0xE8
    image[0x101:0x105] = (0x10).to_bytes(4, "little", signed=True)

    counts = count_stub_vs_api_calls(
        bytes(image),
        image_base=0,
        code_ranges=[(-0x100, 0x80)],
        stub_ranges=[],
    )

    assert counts["scanned_bytes"] == 0
    assert counts["e8_total"] == 0


# --------------------------------------------------------------------------- #
# what the gate does with each answer                                         #
# --------------------------------------------------------------------------- #
def test_an_unmeasured_ratio_does_not_convict_the_dump() -> None:
    quality = assess_pause_quality(
        layout="normal",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        code_nonzero_ratio=None,
    )

    assert quality["iat_ready"] is True
    assert quality["quality"] == "iat_ready"
    assert not [r for r in quality["reasons"] if r.startswith("code_not_decrypted")]


def test_a_measured_zero_ratio_still_convicts_the_dump() -> None:
    quality = assess_pause_quality(
        layout="normal",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        code_nonzero_ratio=0.0,
    )

    assert quality["iat_ready"] is False
    assert quality["quality"] == "code_not_ready"
    assert "code_not_decrypted:nonzero_ratio=0.0000" in quality["reasons"]

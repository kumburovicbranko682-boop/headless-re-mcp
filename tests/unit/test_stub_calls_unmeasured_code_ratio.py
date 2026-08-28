"""Honesty coverage for the code-decryption ratio in ``unpack/stub_calls``.

``code_nonzero_ratio`` feeds the fail-closed IAT rebuild gate: a value below
``0.05`` is read as "code still encrypted" and blocks rebuild. These tests pin
three related bugs:

* a dump where no code section can be measured must report ``None`` ("not
  measured"), never ``0.0`` (which reads as a measured all-zero CODE section),
* a code section that falls outside the dump must not abandon the scan of later,
  in-bounds sections, and
* a negative section RVA must never slice bytes from the tail of the dump and
  forge call / nonzero counts.
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


# --- unmeasured code -> None (not 0.0) -----------------------------------


def test_code_section_outside_dump_reports_none_not_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "truncated.bin"
    dump.write_bytes(bytes(bytearray(0x1000)))
    # The only code section starts past the end of the (truncated) dump, so no
    # code byte can be measured.
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0x5000, 0x400)]),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["code_bytes"] == 0
    assert result["code_nonzero_ratio"] is None


def test_no_code_section_reports_none_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "stub-only.bin"
    dump.write_bytes(bytes(bytearray(0x4000)))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        # Only a non-executable section and an exact protector tuple: no code is
        # recoverable, so the ratio is unmeasured rather than measured-zero.
        lambda _data: _headers(
            [_sec(".data", 0x400, 0x200, chars=_DATA), _sec(".vmp0", 0x1000, 0x2000)]
        ),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["code_sections"] == []
    assert result["code_bytes"] == 0
    assert result["code_nonzero_ratio"] is None


def test_zero_filled_in_bounds_code_reports_measured_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "encrypted.bin"
    dump.write_bytes(bytes(bytearray(0x1000)))
    # A real, in-bounds, all-zero code section: this genuinely measures 0.0 and
    # must stay distinguishable from the unmeasured None case above.
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0x100, 0x80)]),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["code_bytes"] == 0x80
    assert result["code_nonzero_ratio"] == 0.0


# --- an out-of-bounds section must not abandon later ones -----------------


def test_out_of_bounds_section_does_not_skip_later_in_bounds_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = bytearray(0x1000)
    data[0x100:0x180] = b"\xcc" * 0x80  # nonzero payload in the in-bounds section
    dump = tmp_path / "mixed.bin"
    dump.write_bytes(bytes(data))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        # First code section is entirely past the dump; the second is inside it.
        # A ``break`` on the first would leave the ratio unmeasured; a ``continue``
        # still measures the second.
        lambda _data: _headers(
            [_sec(".text", 0x5000, 0x400), _sec(".text", 0x100, 0x80)]
        ),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["code_bytes"] == 0x80
    assert result["code_nonzero_ratio"] == 1.0


def test_ratio_measurement_stops_at_scan_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = bytearray(0x1000)
    data[0x100:0x140] = b"\xcc" * 0x40  # first section is fully nonzero
    data[0x200:0x240] = b"\x00" * 0x40  # second section would dilute the ratio
    dump = tmp_path / "budgeted.bin"
    dump.write_bytes(bytes(data))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0x100, 0x40), _sec(".text", 0x200, 0x40)]),
    )
    # Budget only covers the first section; the second must not be measured.
    result = analyze_dump_stub_coupling(dump, max_scan_bytes=0x40)
    assert result["ok"] is True
    assert result["code_bytes"] == 0x40
    assert result["code_nonzero_ratio"] == 1.0


# --- negative RVA guards -------------------------------------------------


def test_code_section_ranges_rejects_negative_rva() -> None:
    assert code_section_ranges([_sec(".text", -0x100, 0x200)]) == []


def test_fallback_rejects_negative_rva_executable_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "neg.bin"
    dump.write_bytes(bytes(bytearray(0x1000)))
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        # The lone executable section has a negative RVA: the primary classifier
        # drops it and the fallback must not recover it as code.
        lambda _data: _headers([_sec(".text", -0x100, 0x200)]),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["code_sections"] == []
    assert result["code_nonzero_ratio"] is None


def test_scanner_skips_negative_rva_range() -> None:
    image = bytearray(0x200)
    # An E8 call sits in the tail; a negative RVA range would slice from the end
    # and count it. The guard must skip the range entirely.
    image[0x1F0] = 0xE8
    image[0x1F1:0x1F5] = (0).to_bytes(4, "little", signed=True)
    counts = count_stub_vs_api_calls(
        bytes(image),
        image_base=0,
        code_ranges=[(-0x100, 0x200)],
        stub_ranges=[],
    )
    assert counts["scanned_bytes"] == 0
    assert counts["e8_total"] == 0


# --- downstream honesty: None abstains, 0.0 blocks -----------------------


def test_pause_quality_distinguishes_unmeasured_from_measured_zero() -> None:
    unmeasured = assess_pause_quality(code_nonzero_ratio=None)
    assert "code_not_decrypted:nonzero_ratio=0.0000" not in unmeasured["reasons"]
    assert unmeasured["quality"] != "code_not_ready"

    measured_zero = assess_pause_quality(code_nonzero_ratio=0.0)
    assert measured_zero["quality"] == "code_not_ready"
    assert any(r.startswith("code_not_decrypted") for r in measured_zero["reasons"])

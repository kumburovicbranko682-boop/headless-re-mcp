"""Edge coverage for stub-vs-API call scanning and section heuristics.

These exercise the fail-closed VM-coupling signal in ``unpack/stub_calls``:
the section classifiers reject malformed / geometry-invalid entries and skip
protector-overlapping code, the byte scanner classifies E8 relative calls into
stub / code / other buckets and decodes both 32-bit absolute and 64-bit
RIP-relative FF15/FF25 indirect calls, honours the scan-byte budget across
ranges, and the dump analyser handles empty dumps, unparseable headers, and the
fallback that recovers a code section when the primary classifier finds none.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.unpack import stub_calls
from headless_re_mcp.unpack.pe_rebuild import PeRebuildError
from headless_re_mcp.unpack.stub_calls import (
    analyze_dump_stub_coupling,
    code_section_ranges,
    count_stub_vs_api_calls,
    vmp_like_section_ranges,
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


# --- section heuristics --------------------------------------------------


def test_vmp_like_skips_non_dict_and_invalid_geometry() -> None:
    sections: list[Any] = [
        "not-a-dict",
        _sec(".text", -1, 0x100),
        _sec(".weird", 0x1000, 0),
        _sec(".vmp0", 0x2000, 0x100, chars=0),
    ]
    out = vmp_like_section_ranges(sections)
    assert [n for _, _, n in out] == [".vmp0"]


def test_vmp_like_flags_short_weird_executable_name() -> None:
    out = vmp_like_section_ranges([_sec(".xz", 0x1000, 0x400)])
    assert [n for _, _, n in out] == [".xz"]


def test_upx0_destination_is_not_a_stub_range_but_upx1_is() -> None:
    """UPX0 holds the unpacked code, so it must scan as code, not a protector stub.

    UPX names its sections UPX0, UPX1, ... The decompression stub and compressed
    payload live in UPX1+; UPX0 is the RWX region the stub decompresses the
    original code into -- the post-unpack code itself. A real UPX0 carries
    MEM_EXECUTE and is a 4-char unknown name, so the generic short-executable
    heuristic used to fold it into the VMP-like set. That dropped UPX0 from
    ``code_section_ranges`` (which excludes stub ranges), leaving a fully
    unpacked UPX dump with an empty code list. Only UPX1 is the stub.
    """
    sections: list[Any] = [
        _sec("UPX0", 0x1000, 0x3000),
        _sec("UPX1", 0x4000, 0x2000),
        _sec(".rsrc", 0x6000, 0x500, chars=_DATA),
    ]
    assert [n for _, _, n in vmp_like_section_ranges(sections)] == ["UPX1"]
    assert [n for _, _, n in code_section_ranges(sections)] == ["UPX0"]
    # The exclusion is narrow: other short executable unknown names stay stubs.
    assert [n for _, _, n in vmp_like_section_ranges([_sec(".xz", 0x1000, 0x400)])] == [
        ".xz"
    ]


def test_code_section_skips_non_dict_bad_geometry_and_vmp_overlap() -> None:
    sections: list[Any] = [
        "nope",
        _sec(".text", "bad", 0x100),
        _sec(".data", 0x400, 0x200, chars=_DATA),
        _sec(".vmp0", 0x2000, 0x2000),
        # Executable, not an exact vmp tuple, but overlaps the vmp range -> excluded.
        _sec(".text", 0x2500, 0x500),
        # Clean code section far from the protector range -> kept.
        _sec(".text", 0x8000, 0x400),
    ]
    out = code_section_ranges(sections)
    assert out == [(0x8000, 0x400, ".text")]


# --- E8 / FF call classification -----------------------------------------


def test_e8_classified_into_code_and_other_buckets() -> None:
    image = bytearray(0x3000)
    # E8 at RVA 0x1000 targeting code RVA 0x1100 (inside the code range).
    image[0x1000] = 0xE8
    image[0x1001:0x1005] = (0x1100 - 0x1005).to_bytes(4, "little", signed=True)
    # E8 at RVA 0x1010 targeting RVA 0x9000 (neither stub nor code).
    image[0x1010] = 0xE8
    image[0x1011:0x1015] = (0x9000 - 0x1015).to_bytes(4, "little", signed=True)

    counts = count_stub_vs_api_calls(
        bytes(image),
        image_base=0,
        code_ranges=[(0x1000, 0x1000)],
        stub_ranges=[(0x5000, 0x1000)],
    )
    assert counts["e8_total"] == 2
    assert counts["e8_to_code"] == 1
    assert counts["e8_other"] == 1
    assert counts["e8_to_stub"] == 0


def test_ff15_ff25_rip_relative_64bit_and_iat_hit() -> None:
    image = bytearray(0x2000)
    base = 0x140000000
    iat_va = 0x140002000
    # FF15 at RVA 0x1000: RIP-relative slot lands inside the IAT window.
    image[0x1000] = 0xFF
    image[0x1001] = 0x15
    rel_hit = iat_va - (base + 0x1000 + 0 + 6)
    image[0x1002:0x1006] = rel_hit.to_bytes(4, "little", signed=True)
    # FF25 at RVA 0x1010: RIP-relative slot lands outside the IAT window.
    image[0x1010] = 0xFF
    image[0x1011] = 0x25
    image[0x1012:0x1016] = (0x100).to_bytes(4, "little", signed=True)

    counts = count_stub_vs_api_calls(
        bytes(image),
        image_base=base,
        code_ranges=[(0x1000, 0x1000)],
        stub_ranges=[],
        iat_va=iat_va,
        iat_size=0x100,
        is_64bit=True,
    )
    assert counts["ff15_count"] == 1
    assert counts["ff25_count"] == 1
    assert counts["ff_indirect_count"] == 2
    assert counts["ff_to_iat_count"] == 1


def test_scan_skips_empty_range_and_clamps_past_image_end() -> None:
    image = bytearray(0x100)
    # First range is zero-sized (skipped); second extends past the image end.
    counts = count_stub_vs_api_calls(
        bytes(image),
        image_base=0,
        code_ranges=[(0x0, 0), (0xE0, 0x100)],
        stub_ranges=[],
        max_scan_bytes=0x1000,
    )
    # Only the clamped tail (0x100 - 0xE0 = 0x20 bytes) is scanned.
    assert counts["scanned_bytes"] == 0x20


def test_scan_stops_when_byte_budget_is_exhausted() -> None:
    image = bytearray(0x200)
    counts = count_stub_vs_api_calls(
        bytes(image),
        image_base=0,
        code_ranges=[(0x0, 0x40), (0x100, 0x40)],
        stub_ranges=[],
        max_scan_bytes=0x40,
    )
    assert counts["scanned_bytes"] == 0x40


# --- dump analyser -------------------------------------------------------


def _headers(sections: list[Any], *, arch: str = "x86") -> dict[str, Any]:
    return {"image_base": 0x400000, "architecture": arch, "sections": sections}


def test_empty_dump_scans_nothing_but_reports_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "empty.bin"
    dump.write_bytes(b"")
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers([_sec(".text", 0, 0x100)]),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["scanned_bytes"] == 0
    assert result["code_bytes"] == 0


def test_unparseable_headers_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "bad.bin"
    dump.write_bytes(b"garbage" * 64)

    def _raise(_data: object) -> dict[str, Any]:
        raise PeRebuildError("no PE header")

    monkeypatch.setattr(stub_calls, "parse_runtime_headers", _raise)
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is False
    assert "no PE header" in result["error"]
    assert result["still_vm_stub_count"] is None
    assert result["claims_universal_unpack"] is False


def test_code_fallback_recovers_largest_non_stub_executable_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "vmp.bin"
    data = bytearray(0x4000)
    data[0x1500:0x1520] = b"\x90" * 0x20
    dump.write_bytes(bytes(data))
    sections: list[Any] = [
        # Non-executable section -> skipped by the fallback executable filter.
        _sec(".data", 0x400, 0x200, chars=_DATA),
        # Executable but geometry-invalid -> skipped by the fallback.
        _sec(".bad", "x", 0x100),
        # Exact protector tuple -> excluded from both classifier and fallback.
        _sec(".vmp0", 0x1000, 0x2000),
        # Three overlapping executables: fallback keeps the largest.
        _sec(".text", 0x1100, 0x400),
        _sec(".text", 0x1500, 0x800),
        _sec(".text", 0x1A00, 0x200),
    ]
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers(sections, arch="x64"),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["architecture"] == "x64"
    # Primary classifier drops the overlapping .text ranges; fallback keeps the largest.
    assert result["code_sections"] == [{"rva": 0x1500, "size": 0x800, "name": ".text"}]
    assert result["code_bytes"] == 0x800
    assert result["code_nonzero_ratio"] > 0


def test_code_fallback_finds_nothing_leaves_code_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "stub-only.bin"
    dump.write_bytes(bytes(bytearray(0x4000)))
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
    assert result["e8_total"] == 0


def test_upx_dump_scans_unpacked_code_in_upx0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fully unpacked UPX dump keeps its code (UPX0) analysable, not empty.

    Before the UPX0 exclusion, both UPX0 and UPX1 landed in the VMP-like stub
    set, so the classifier and the fallback both refused UPX0 as code: the tool
    reported ``code_sections == []`` and ``code_bytes == 0`` for a dump whose
    real code sits in UPX0. Now UPX0 is scanned as code and UPX1 stays the stub.
    """
    dump = tmp_path / "upx.bin"
    data = bytearray(0x7000)
    data[0x1500:0x1520] = b"\x90" * 0x20  # non-zero bytes inside UPX0
    dump.write_bytes(bytes(data))
    sections: list[Any] = [
        _sec("UPX0", 0x1000, 0x3000),
        _sec("UPX1", 0x4000, 0x2000),
        _sec(".rsrc", 0x6000, 0x500, chars=_DATA),
    ]
    monkeypatch.setattr(
        stub_calls,
        "parse_runtime_headers",
        lambda _data: _headers(sections),
    )
    result = analyze_dump_stub_coupling(dump)
    assert result["ok"] is True
    assert result["code_sections"] == [{"rva": 0x1000, "size": 0x3000, "name": "UPX0"}]
    assert result["stub_sections"] == [{"rva": 0x4000, "size": 0x2000, "name": "UPX1"}]
    assert result["code_bytes"] == 0x3000
    assert result["code_nonzero_ratio"] > 0

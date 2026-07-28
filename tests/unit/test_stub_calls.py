from __future__ import annotations

from headless_re_mcp.unpack.iat_rank import gate_iat_rebuild, analyze_import_entries
from headless_re_mcp.unpack.stub_calls import (
    code_section_ranges,
    count_stub_vs_api_calls,
    vmp_like_section_ranges,
)


def test_vmp_like_and_code_section_split() -> None:
    sections = [
        {"name": "CODE", "virtual_address": 0x1000, "virtual_size": 0x4000, "characteristics": 0x60000020},
        {"name": ".fkF", "virtual_address": 0x5000, "virtual_size": 0x8000, "characteristics": 0x60000020},
        {"name": ".''FL", "virtual_address": 0xD000, "virtual_size": 0x2000, "characteristics": 0x60000020},
        {"name": "DATA", "virtual_address": 0xF000, "virtual_size": 0x1000, "characteristics": 0xC0000040},
    ]
    # Use .'FL style name like Acid evidence
    sections[2]["name"] = ".'FL"
    stub = vmp_like_section_ranges(sections)
    names = {n for _, _, n in stub}
    assert ".fkF" in names
    assert ".'FL" in names
    assert "CODE" not in names
    code = code_section_ranges(sections)
    assert any(n == "CODE" for _, _, n in code)


def test_count_e8_to_stub_vs_ff15() -> None:
    # Minimal fake image: CODE at RVA 0x1000, stub at 0x5000, image_base 0x400000
    image = bytearray(0x6000)
    # At CODE+0: E8 rel32 targeting stub RVA 0x5000
    # next_ip = 0x401005; target = 0x405000 => rel = 0x405000 - 0x401005 = 0x3FFB
    image[0x1000] = 0xE8
    image[0x1001:0x1005] = (0x3FFB).to_bytes(4, "little", signed=True)
    # At CODE+0x10: FF15 absolute IAT slot 0x431678
    image[0x1010] = 0xFF
    image[0x1011] = 0x15
    image[0x1012:0x1016] = (0x431678).to_bytes(4, "little")
    counts = count_stub_vs_api_calls(
        bytes(image),
        image_base=0x400000,
        code_ranges=[(0x1000, 0x100)],
        stub_ranges=[(0x5000, 0x1000)],
        iat_va=0x431678,
        iat_size=0x40,
        is_64bit=False,
    )
    assert counts["e8_to_stub"] == 1
    assert counts["ff15_count"] == 1
    assert counts["ff_to_iat_count"] == 1
    assert counts["still_vm_stub_count"] == 1


def test_gate_blocks_when_stub_dominates() -> None:
    entries = [
        {"kind": "api", "module": "kernel32.dll", "name": f"Api{i}"} for i in range(12)
    ]
    analysis = analyze_import_entries(entries)
    gate = gate_iat_rebuild(analysis, still_vm_stub_count=40)
    assert gate["rebuild_allowed"] is False
    assert gate["recoverability"] == "vm_coupled_dump_only"
from __future__ import annotations

from headless_re_mcp.unpack.iat_rank import (
    analyze_import_entries,
    gate_iat_rebuild,
    rank_iat_candidates,
)


def test_half_sparse_layout_and_gate() -> None:
    entries = []
    for _ in range(10):
        entries.append({"kind": "api", "module": "kernel32.dll", "name": "CreateFileA"})
        entries.append({"kind": "null"})
    analysis = analyze_import_entries(entries)
    assert analysis["layout"] == "half_sparse"
    assert analysis["api_null_pairs"] == 10
    assert analysis["rebuild_allowed"] is True
    gate = gate_iat_rebuild(analysis)
    assert gate["rebuild_allowed"] is True
    assert gate["recoverability"] == "iat_recoverable"


def test_ime_dominated_blocks_rebuild() -> None:
    entries = [
        {"kind": "api", "module": "imm32.dll", "name": "ImmGetContext"} for _ in range(11)
    ]
    analysis = analyze_import_entries(entries)
    assert analysis["ime_dominated"] is True
    assert analysis["rebuild_allowed"] is False
    gate = gate_iat_rebuild(analysis)
    assert gate["rebuild_allowed"] is False


def test_junk_layout_with_high_unresolved() -> None:
    entries = [{"kind": "unresolved", "value": i} for i in range(20)]
    entries[0] = {"kind": "api", "module": "kernel32.dll", "name": "HeapFree"}
    analysis = analyze_import_entries(entries)
    assert analysis["layout"] == "junk"
    assert analysis["rebuild_allowed"] is False


def test_rank_dedupes_overlap_and_penalizes_high_rva_ime() -> None:
    ranked = rank_iat_candidates(
        [
            {
                "iat_va": 0x431678,
                "iat_rva": 0x31678,
                "size": 44,
                "matched_count": 11,
                "slot_count": 11,
                "kind": "consecutive",
                "confidence": 1.0,
                "sample_apis": [
                    {"module": "imm32.dll", "name": "ImmGetContext"},
                    {"module": "imm32.dll", "name": "ImmReleaseContext"},
                ],
            },
            {
                "iat_va": 0x431678,
                "iat_rva": 0x31678,
                "size": 44,
                "matched_count": 11,
                "slot_count": 11,
                "kind": "sparse",
                "confidence": 1.0,
                "sample_apis": [
                    {"module": "imm32.dll", "name": "ImmGetContext"},
                ],
            },
            {
                "iat_va": 0xF82000,
                "iat_rva": 0xB82000,
                "size": 120,
                "matched_count": 17,
                "slot_count": 30,
                "kind": "sparse",
                "confidence": 0.66,
                "sample_apis": [
                    {"module": "kernel32.dll", "name": "LoadLibraryA"},
                    {"module": "user32.dll", "name": "GetKeyboardType"},
                ],
            },
            {
                "iat_va": 0x45C0F0,
                "iat_rva": 0x5C0F0,
                "size": 148,
                "matched_count": 6,
                "slot_count": 37,
                "kind": "call_site",
                "confidence": 0.2,
                "sample_apis": [
                    {"module": "kernel32.dll", "name": "TlsGetValue"},
                ],
            },
        ],
        module_base=0x400000,
        module_size=0x2000000,
        max_candidates=8,
    )
    assert ranked["candidate_count"] == 3
    assert ranked["raw_candidate_count"] == 4
    # No cap hit: the deduped set is returned whole, not a slice.
    assert ranked["merged_total"] == 3
    assert ranked["candidates_truncated"] is False
    assert ranked["max_candidates"] == 8
    # Overlapping 0x431678 collapsed; alt_kinds present.
    ime = next(c for c in ranked["candidates"] if c["iat_va"] == 0x431678)
    assert "alt_kinds" in ime
    assert "ime_dominated" in (ime.get("noise_tags") or [])


def test_rank_discloses_truncated_candidate_tail() -> None:
    # Ten distinct, non-overlapping candidates; a small cap must drop the tail
    # and say so rather than presenting the slice as the whole set.
    candidates = [
        {
            "iat_va": 0x400000 + i * 0x1000,
            "iat_rva": i * 0x1000,
            "size": 64,
            "matched_count": 16 - i,
            "slot_count": 16,
            "kind": "consecutive",
            "confidence": 1.0 - i * 0.05,
            "sample_apis": [{"module": "kernel32.dll", "name": f"Api{i}"}],
        }
        for i in range(10)
    ]
    ranked = rank_iat_candidates(
        candidates,
        module_base=0x400000,
        module_size=0x2000000,
        max_candidates=3,
    )
    assert ranked["candidate_count"] == 3
    assert ranked["merged_total"] == 10
    assert ranked["candidates_truncated"] is True
    assert ranked["max_candidates"] == 3
    assert len(ranked["candidates"]) == 3
    assert "slice, not the full set" in ranked["note"]


def test_rank_untruncated_when_cap_covers_all() -> None:
    candidates = [
        {
            "iat_va": 0x400000 + i * 0x1000,
            "iat_rva": i * 0x1000,
            "size": 64,
            "matched_count": 16,
            "slot_count": 16,
            "kind": "consecutive",
            "confidence": 1.0,
            "sample_apis": [{"module": "kernel32.dll", "name": f"Api{i}"}],
        }
        for i in range(3)
    ]
    ranked = rank_iat_candidates(
        candidates,
        module_base=0x400000,
        module_size=0x2000000,
        max_candidates=8,
    )
    assert ranked["candidates_truncated"] is False
    assert ranked["merged_total"] == 3
    assert ranked["candidate_count"] == 3
    assert "slice, not the full set" not in ranked["note"]


def test_stub_ratio_forces_vm_coupled() -> None:
    entries = [
        {"kind": "api", "module": "kernel32.dll", "name": f"Api{i}"} for i in range(10)
    ]
    analysis = analyze_import_entries(entries)
    gate = gate_iat_rebuild(analysis, still_vm_stub_count=40)
    assert gate["rebuild_allowed"] is False
    assert gate["recoverability"] == "vm_coupled_dump_only"
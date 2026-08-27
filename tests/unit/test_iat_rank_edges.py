"""Edge/guard coverage for IAT candidate ranking and rebuild gating.

``test_iat_rank.py`` covers the main layouts and dedup happy path. This file
pins the pure guard branches: input validation, layout classification arms,
candidate skips (non-dict / invalid geometry / out-of-module / derived RVA /
truncation), overlap-merge sample handling (missing samples, non-list
samples, combined IME dominance), and gate reason de-duplication.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.unpack.iat_rank import (
    analyze_import_entries,
    gate_iat_rebuild,
    rank_iat_candidates,
)


def test_analyze_rejects_bad_pointer_size() -> None:
    with pytest.raises(ValueError, match="pointer_size"):
        analyze_import_entries([], pointer_size=3)


def test_analyze_empty_entries_is_empty_layout() -> None:
    analysis = analyze_import_entries([])
    assert analysis["layout"] == "empty"
    assert analysis["slot_count"] == 0
    assert analysis["rebuild_block_reason"] == "layout_empty"


def test_analyze_skips_non_dict_empty_module_and_unknown_kind() -> None:
    entries: list[Any] = [
        "not-a-dict",
        {"kind": "api"},
        {"kind": "call_site"},
        {"kind": "api", "module": "kernel32.dll"},
        {"kind": "null"},
        {"kind": "unresolved"},
    ]
    analysis = analyze_import_entries(entries)
    assert analysis["api_count"] == 2
    assert analysis["null_count"] == 1
    assert analysis["unresolved_count"] == 1
    assert analysis["modules"] == {"kernel32.dll": 1}


def test_analyze_fragmented_layout() -> None:
    entries: list[Any] = [
        {"kind": "api", "module": "kernel32.dll", "name": f"A{i}"} for i in range(3)
    ]
    entries += [{"kind": "null"} for _ in range(7)]
    analysis = analyze_import_entries(entries)
    assert analysis["layout"] == "fragmented"
    assert analysis["rebuild_allowed"] is False
    assert analysis["rebuild_block_reason"] == "layout_fragmented"


def test_analyze_dense_but_low_api_blocks_rebuild() -> None:
    entries: list[Any] = [
        {"kind": "api", "module": "kernel32.dll", "name": f"A{i}"} for i in range(5)
    ]
    entries.append({"kind": "null"})
    analysis = analyze_import_entries(entries)
    assert analysis["layout"] == "dense"
    assert analysis["rebuild_allowed"] is False
    assert analysis["rebuild_block_reason"] == "api_count_below_8:5"


def test_rank_skips_invalid_derives_rva_and_truncates() -> None:
    candidates: list[Any] = [
        "not-a-dict",
        {"iat_va": 0x401000, "size": 40, "matched_count": 20, "confidence": 0.9},
        {"iat_va": "bad", "size": 40},
        {"iat_va": 0x401000, "size": 0},
        {"iat_va": 0x300000, "size": 40},
        {"iat_va": 0x402000, "size": 40, "matched_count": 10, "confidence": 0.5},
    ]
    ranked = rank_iat_candidates(
        candidates,
        module_base=0x400000,
        module_size=0x100000,
        max_candidates=1,
    )
    assert ranked["raw_candidate_count"] == 2
    assert ranked["candidate_count"] == 1
    best = ranked["best"]
    assert best is not None
    assert best["iat_rva"] == best["iat_va"] - 0x400000


def test_rank_ignores_non_dict_samples() -> None:
    candidates: list[Any] = [
        {
            "iat_va": 0x401000,
            "size": 40,
            "matched_count": 10,
            "confidence": 0.8,
            "sample_apis": [
                {"module": "kernel32.dll", "name": "LoadLibraryA"},
                "junk",
                5,
            ],
        }
    ]
    ranked = rank_iat_candidates(candidates, module_base=0x400000, module_size=0x100000)
    assert ranked["candidate_count"] == 1
    assert "ime_dominated" not in (ranked["candidates"][0].get("noise_tags") or [])


def test_merge_overlap_without_samples_unions_kinds() -> None:
    candidates: list[Any] = [
        {
            "iat_va": 0x401000,
            "size": 40,
            "matched_count": 10,
            "confidence": 0.9,
            "kind": "consecutive",
        },
        {
            "iat_va": 0x401010,
            "size": 40,
            "matched_count": 8,
            "confidence": 0.5,
            "kind": "sparse",
        },
    ]
    ranked = rank_iat_candidates(candidates, module_base=0x400000, module_size=0x100000)
    assert ranked["candidate_count"] == 1
    winner = ranked["candidates"][0]
    assert winner["alt_kinds"] == ["consecutive", "sparse"]
    assert "sample_apis" not in winner


def test_merge_overlap_flags_combined_ime_dominance() -> None:
    candidates: list[Any] = [
        {
            "iat_va": 0x401000,
            "size": 40,
            "matched_count": 10,
            "confidence": 0.9,
            "kind": "consecutive",
            "sample_apis": [
                {"module": "kernel32.dll", "name": "LoadLibraryA"},
                {"module": "user32.dll", "name": "GetKeyboardType"},
                {"module": "imm32.dll", "name": "ImmGetContext"},
            ],
        },
        {
            "iat_va": 0x401010,
            "size": 40,
            "matched_count": 8,
            "confidence": 0.5,
            "kind": "sparse",
            "sample_apis": [
                {"module": "kernel32.dll", "name": "HeapAlloc"},
                {"module": "user32.dll", "name": "GetDC"},
                {"module": "imm32.dll", "name": "ImmReleaseContext"},
            ],
        },
    ]
    ranked = rank_iat_candidates(candidates, module_base=0x400000, module_size=0x100000)
    assert ranked["candidate_count"] == 1
    winner = ranked["candidates"][0]
    assert "ime_dominated" in winner["noise_tags"]


def test_merge_overlap_with_non_ime_samples_keeps_clean() -> None:
    candidates: list[Any] = [
        {
            "iat_va": 0x401000,
            "size": 40,
            "matched_count": 10,
            "confidence": 0.9,
            "kind": "consecutive",
            "sample_apis": [{"module": "kernel32.dll", "name": "LoadLibraryA"}],
        },
        {
            "iat_va": 0x401010,
            "size": 40,
            "matched_count": 8,
            "confidence": 0.5,
            "kind": "sparse",
            "sample_apis": [{"module": "user32.dll", "name": "GetDC"}],
        },
    ]
    ranked = rank_iat_candidates(candidates, module_base=0x400000, module_size=0x100000)
    assert ranked["candidate_count"] == 1
    winner = ranked["candidates"][0]
    assert "ime_dominated" not in (winner.get("noise_tags") or [])
    assert winner["sample_apis"]


def test_gate_within_stub_ratio_still_blocks_on_low_api() -> None:
    analysis = analyze_import_entries(
        [{"kind": "api", "module": "kernel32.dll", "name": f"A{i}"} for i in range(5)]
    )
    gate = gate_iat_rebuild(analysis, still_vm_stub_count=1)
    assert gate["rebuild_allowed"] is False
    assert gate["still_vm_stub_ratio"] is not None
    assert any("api_count=" in reason for reason in gate["reasons"])


def test_gate_appends_layout_reason_for_junk() -> None:
    analysis = analyze_import_entries([{"kind": "unresolved", "value": i} for i in range(20)])
    assert analysis["layout"] == "junk"
    gate = gate_iat_rebuild(analysis)
    assert gate["rebuild_allowed"] is False
    assert "layout=junk" in gate["reasons"]


def test_gate_does_not_duplicate_preexisting_layout_reason() -> None:
    analysis = {
        "layout": "junk",
        "api_count": 10,
        "ime_dominated": False,
        "rebuild_allowed": False,
        "rebuild_block_reason": "layout=junk",
    }
    gate = gate_iat_rebuild(analysis)
    assert gate["rebuild_allowed"] is False
    assert gate["reasons"].count("layout=junk") == 1

"""Regression for alt_kinds loss when 3+ IAT candidates overlap one range.

``_merge_overlaps`` folds overlapping scan hits into the highest-scoring
survivor and records the other candidates' kinds under ``alt_kinds``. When a
third candidate overlaps a range that already absorbed two, the union must keep
the kind recorded by the earlier merge instead of rebuilding ``alt_kinds`` from
only the two candidates currently being compared.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.unpack.iat_rank import _merge_overlaps, rank_iat_candidates


def _cand(iat_va: int, size: int, kind: str, *, confidence: float, matched: int) -> dict[str, Any]:
    return {
        "iat_va": iat_va,
        "size": size,
        "kind": kind,
        "confidence": confidence,
        "matched_count": matched,
    }


def test_three_overlapping_candidates_union_all_kinds() -> None:
    # All three overlap [0x1000, 0x1400); A outscores B and C, so it wins every
    # merge and must accumulate both other kinds.
    candidates = [
        _cand(0x1000, 0x400, "scan_hit", confidence=0.9, matched=30),
        _cand(0x1100, 0x100, "call_site", confidence=0.5, matched=10),
        _cand(0x1200, 0x100, "thunk", confidence=0.3, matched=5),
    ]
    result = rank_iat_candidates(candidates)
    assert result["candidate_count"] == 1
    best = result["best"]
    assert best["kind"] == "scan_hit"
    assert set(best["alt_kinds"]) == {"scan_hit", "call_site", "thunk"}


def test_four_overlapping_candidates_union_all_kinds() -> None:
    candidates = [
        _cand(0x2000, 0x800, "scan_hit", confidence=0.95, matched=40),
        _cand(0x2100, 0x100, "call_site", confidence=0.6, matched=12),
        _cand(0x2300, 0x100, "thunk", confidence=0.4, matched=6),
        _cand(0x2500, 0x100, "ordinal", confidence=0.35, matched=4),
    ]
    result = rank_iat_candidates(candidates)
    assert result["candidate_count"] == 1
    assert set(result["best"]["alt_kinds"]) == {
        "scan_hit",
        "call_site",
        "thunk",
        "ordinal",
    }


def test_union_is_independent_of_input_order() -> None:
    base = [
        _cand(0x3000, 0x400, "scan_hit", confidence=0.9, matched=30),
        _cand(0x3100, 0x100, "call_site", confidence=0.5, matched=10),
        _cand(0x3200, 0x100, "thunk", confidence=0.3, matched=5),
    ]
    expected = {"scan_hit", "call_site", "thunk"}
    for order in ([0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]):
        candidates = [dict(base[i]) for i in order]
        result = rank_iat_candidates(candidates)
        assert result["candidate_count"] == 1
        assert set(result["best"]["alt_kinds"]) == expected


def test_repeated_kinds_collapse_in_union() -> None:
    candidates = [
        _cand(0x4000, 0x400, "scan_hit", confidence=0.9, matched=30),
        _cand(0x4100, 0x100, "scan_hit", confidence=0.5, matched=10),
        _cand(0x4200, 0x100, "call_site", confidence=0.3, matched=5),
    ]
    result = rank_iat_candidates(candidates)
    assert set(result["best"]["alt_kinds"]) == {"scan_hit", "call_site"}


def test_non_overlapping_candidates_have_no_alt_kinds() -> None:
    candidates = [
        _cand(0x5000, 0x100, "scan_hit", confidence=0.9, matched=30),
        _cand(0x6000, 0x100, "call_site", confidence=0.8, matched=20),
    ]
    result = rank_iat_candidates(candidates)
    assert result["candidate_count"] == 2
    for candidate in result["candidates"]:
        assert "alt_kinds" not in candidate


def test_merge_overlaps_directly_carries_prior_alt_kinds() -> None:
    # Pre-sorted by score; C overlaps the range that already absorbed B.
    candidates = [
        {"iat_va": 0x1000, "size": 0x400, "kind": "scan_hit", "rank_score": 0.9},
        {"iat_va": 0x1100, "size": 0x100, "kind": "call_site", "rank_score": 0.5},
        {"iat_va": 0x1200, "size": 0x100, "kind": "thunk", "rank_score": 0.3},
    ]
    merged = _merge_overlaps(candidates)
    assert len(merged) == 1
    assert set(merged[0]["alt_kinds"]) == {"scan_hit", "call_site", "thunk"}

"""``_merge_overlaps`` promises to union kinds; it used to lose them past two.

``alt_kinds`` records which detectors independently pointed at the same IAT
range, which is the corroboration a caller weighs before confirming a candidate
via imports.read. The merge rebuilt that set from just the two dicts in hand, so
folding a third overlapping candidate into a range that had already been merged
overwrote the earlier union and silently dropped a kind -- under-reporting the
evidence while the docstring says "union kinds".

test_iat_rank_edges pins the two-way merge, which was always correct, so these
drive three and four overlapping candidates and the order-independence that a
real union implies.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.unpack.iat_rank import rank_iat_candidates

_BASE = 0x400000
_SIZE = 0x100000


def _candidate(va: int, kind: str, confidence: float, matched: int = 10) -> dict[str, Any]:
    return {
        "iat_va": va,
        "size": 40,
        "matched_count": matched,
        "confidence": confidence,
        "kind": kind,
    }


def _ranked(candidates: list[Any]) -> dict[str, Any]:
    result = rank_iat_candidates(candidates, module_base=_BASE, module_size=_SIZE)
    assert result["candidate_count"] == 1, result["candidates"]
    return dict(result["candidates"][0])


def test_three_overlapping_candidates_keep_every_kind() -> None:
    """The middle kind is the one the old rebuild-from-scratch merge lost."""
    winner = _ranked(
        [
            _candidate(0x401000, "consecutive", 0.9),
            _candidate(0x401010, "sparse", 0.5),
            _candidate(0x401014, "call_site", 0.4),
        ]
    )

    assert winner["alt_kinds"] == ["call_site", "consecutive", "sparse"]


def test_four_overlapping_candidates_keep_every_kind() -> None:
    winner = _ranked(
        [
            _candidate(0x401000, "consecutive", 0.9),
            _candidate(0x401008, "sparse", 0.6),
            _candidate(0x401010, "call_site", 0.5),
            _candidate(0x401018, "delay_import", 0.4),
        ]
    )

    assert winner["alt_kinds"] == [
        "call_site",
        "consecutive",
        "delay_import",
        "sparse",
    ]


def test_the_union_does_not_depend_on_which_candidate_wins() -> None:
    """Whether the highest score arrives first or last, the evidence is the same.

    Score order decides which candidate's geometry survives, not how much of the
    corroboration is reported.
    """
    highest_first = _ranked(
        [
            _candidate(0x401000, "consecutive", 0.9),
            _candidate(0x401010, "sparse", 0.5),
            _candidate(0x401014, "call_site", 0.4),
        ]
    )
    highest_last = _ranked(
        [
            _candidate(0x401000, "call_site", 0.4),
            _candidate(0x401010, "sparse", 0.5),
            _candidate(0x401014, "consecutive", 0.9),
        ]
    )

    assert highest_first["alt_kinds"] == highest_last["alt_kinds"]


def test_repeated_kinds_collapse_instead_of_accumulating() -> None:
    """A union, not a tally: three "sparse" hits are still one kind."""
    winner = _ranked(
        [
            _candidate(0x401000, "sparse", 0.9),
            _candidate(0x401010, "sparse", 0.5),
            _candidate(0x401014, "sparse", 0.4),
        ]
    )

    assert winner["alt_kinds"] == ["sparse"]


def test_an_unmerged_candidate_reports_no_alt_kinds() -> None:
    """alt_kinds only appears where corroboration actually happened."""
    result = rank_iat_candidates(
        [_candidate(0x401000, "consecutive", 0.9), _candidate(0x402000, "sparse", 0.5)],
        module_base=_BASE,
        module_size=_SIZE,
    )

    assert result["candidate_count"] == 2
    assert all("alt_kinds" not in candidate for candidate in result["candidates"])

"""Coverage for OEP candidate multi-signal scoring heuristics.

These exercise ``unpack/oep.score_oep_candidates`` and its helpers: input
validation, how runtime observations are normalised to RVAs (oep_rva / address
/ rip forms, including out-of-range and non-integer rejection), role hints
(packed_ep / first_native_handoff / explicit confirmed clamp), the down-weight
applied when a "left stub" or "rip in code" signal still lands inside a
protector stub range, and the score-ordered truncation to ``max_candidates``.
Heuristic candidates are never authoritative.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.unpack.oep import score_oep_candidates

_BASE = 0x400000
_SIZE = 0x10000


def _score(observations: list[Any], **kwargs: Any) -> list[dict[str, Any]]:
    return score_oep_candidates(
        module_base=_BASE,
        module_size=_SIZE,
        observations=observations,
        **kwargs,
    )


def test_rejects_invalid_module_geometry_and_budget() -> None:
    with pytest.raises(ValueError, match="module_base"):
        score_oep_candidates(module_base=0, module_size=_SIZE, observations=[])
    with pytest.raises(ValueError, match="module_size"):
        score_oep_candidates(module_base=_BASE, module_size=0, observations=[])
    with pytest.raises(ValueError, match="max_candidates"):
        score_oep_candidates(
            module_base=_BASE, module_size=_SIZE, observations=[], max_candidates=0
        )


def test_skips_malformed_and_out_of_range_observations() -> None:
    observations: list[Any] = [
        "not-a-dict",
        {"kind": "imports_resolved", "oep_rva": -1},
        {"kind": "imports_resolved", "address": "bad"},
        {"kind": "imports_resolved", "rip": "bad"},
        {"kind": "imports_resolved", "rip": 0x100},
        {"kind": "imports_resolved"},
        {"kind": "imports_resolved", "oep_rva": _SIZE + 0x10},
        {"kind": "bogus_kind", "oep_rva": 0x1000},
    ]
    assert _score(observations) == []


def test_address_below_module_base_is_treated_as_rva() -> None:
    observations: list[Any] = [
        {"kind": "imports_resolved", "address": 0x500, "weight": 0.5},
        {"kind": "new_executable_region", "address": 0x500},
    ]
    out = _score(observations)
    assert len(out) == 1
    candidate = out[0]
    assert candidate["oep_rva"] == 0x500
    assert candidate["oep_va"] == _BASE + 0x500
    # Two distinct signal kinds -> not the single-signal 0.45 clamp.
    assert candidate["score"] == pytest.approx(0.7)
    assert candidate["authoritative"] is False


def test_address_at_or_above_module_base_is_rebased() -> None:
    observations: list[Any] = [
        {"kind": "write_to_execute", "address": _BASE + 0x2000},
    ]
    out = _score(observations)
    assert out[0]["oep_rva"] == 0x2000
    assert out[0]["oep_va"] == _BASE + 0x2000


def test_rip_at_or_above_module_base_is_rebased() -> None:
    observations: list[Any] = [
        {"kind": "rip_in_main_module_code", "rip": _BASE + 0x3000},
    ]
    out = _score(observations)
    assert out[0]["oep_rva"] == 0x3000


def test_role_hints_and_confirmed_is_clamped() -> None:
    observations: list[Any] = [
        {"kind": "packed_ep", "oep_rva": 0x1000},
        {"kind": "first_native_handoff", "oep_rva": 0x2000},
        {"kind": "imports_resolved", "oep_rva": 0x3000, "role": "confirmed"},
    ]
    out = _score(observations)
    roles = {candidate["oep_rva"]: candidate["role"] for candidate in out}
    assert roles[0x1000] == "packed_ep"
    assert roles[0x2000] == "first_native_handoff"
    # Heuristic scoring must never emit a "confirmed" role.
    assert roles[0x3000] == "first_native_handoff"
    assert all(candidate["authoritative"] is False for candidate in out)


def test_stub_region_signals_are_down_weighted() -> None:
    stub = [(0x5000, 0x1000)]
    observations: list[Any] = [
        {"kind": "left_stub_region", "oep_rva": 0x5500},
        {"kind": "rip_in_main_module_code", "oep_rva": 0x5800},
    ]
    out = _score(observations, stub_rva_ranges=stub)
    by_rva = {candidate["oep_rva"]: candidate for candidate in out}

    left = by_rva[0x5500]["signals"][0]
    assert left["weight"] == pytest.approx(0.05)
    assert "still inside stub range" in left["description"]

    rip = by_rva[0x5800]
    rip_signal = rip["signals"][0]
    assert rip_signal["weight"] == pytest.approx(0.07)
    assert rip_signal["details"]["in_stub_section"] is True
    # A rip still inside the protector stub is only a packed entry, not a handoff.
    assert rip["role"] == "packed_ep"


def test_truncates_to_max_candidates_by_score() -> None:
    observations: list[Any] = [
        {"kind": "write_to_execute", "oep_rva": 0x1000},
        {"kind": "rip_in_main_module_code", "oep_rva": 0x2000},
        {"kind": "imports_resolved", "oep_rva": 0x3000},
    ]
    out = _score(observations, max_candidates=2)
    assert len(out) == 2
    # Highest single-signal score first (0.35), then 0.30; 0.25 is dropped.
    assert [candidate["oep_rva"] for candidate in out] == [0x2000, 0x1000]
    # Single-signal candidates stay low-confidence (<= 0.45).
    assert all(candidate["score"] <= 0.45 for candidate in out)

"""profile_from_candidates must not discard an applicable x64 profile.

Armadillo is an x86-only ScyllaHide profile. On x64, if an Armadillo candidate
outscores an otherwise-applicable one (e.g. Themida), the mapper must fall back
to the best *applicable* profile detected on the same sample rather than the
generic ``basic`` -- and only reach ``basic`` when Armadillo was the sole match.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.x64dbg.stealth import profile_from_candidates
from headless_re_mcp.core.models import Architecture


def _cand(name: str, confidence: float, *, category: str = "protector") -> dict[str, Any]:
    return {"category": category, "name": name, "confidence": confidence}


def test_x64_recovers_applicable_profile_when_armadillo_outscores_it() -> None:
    candidates = [
        _cand("Armadillo", 0.95),
        _cand("Themida", 0.5),
    ]
    assert profile_from_candidates(candidates, architecture=Architecture.X64) == "themida"


def test_x64_recovers_applicable_profile_within_a_single_candidate() -> None:
    # One candidate names both, Armadillo listed first / higher-scoring token.
    candidates = [
        _cand("Armadillo protector", 0.9),
        _cand("VMProtect packer", 0.4, category="packer"),
    ]
    assert profile_from_candidates(candidates, architecture=Architecture.X64) == "vmp"


def test_x64_armadillo_only_falls_back_to_basic() -> None:
    candidates = [_cand("Armadillo", 0.9)]
    assert profile_from_candidates(candidates, architecture=Architecture.X64) == "basic"


def test_x64_non_forbidden_winner_returned_directly() -> None:
    candidates = [_cand("Themida", 0.9)]
    assert profile_from_candidates(candidates, architecture=Architecture.X64) == "themida"


def test_x86_keeps_armadillo() -> None:
    candidates = [
        _cand("Armadillo", 0.95),
        _cand("Themida", 0.5),
    ]
    assert profile_from_candidates(candidates, architecture=Architecture.X86) == "armadillo"


def test_no_architecture_keeps_armadillo() -> None:
    candidates = [_cand("Armadillo", 0.9)]
    assert profile_from_candidates(candidates) == "armadillo"


def test_no_packer_candidates_returns_none() -> None:
    candidates = [_cand("Armadillo", 0.9, category="compiler")]
    assert profile_from_candidates(candidates, architecture=Architecture.X64) is None

"""A forbidden top match on x64 must not bury a usable profile.

``profile_from_candidates`` scores every packer/protector hint and, on x64,
refuses armadillo -- an x86-only ScyllaHide profile. It used to do that by
picking the highest-scoring profile and, if that turned out to be armadillo,
returning the generic "basic". But the score is (token length, confidence), and
armadillo's token is nine characters, so on a sample that DIE tags both
"Armadillo" and, say, "Themida" (matched via the shorter "themida" token),
armadillo won the score and the real, applicable Themida profile was thrown away
in favour of basic.

The fix tracks the best *applicable* profile alongside the best overall, so a
forbidden winner steps aside for any other detected profile and only falls back
to basic when it was the sole match. These pin that recovery and, as controls,
the unchanged behaviour: armadillo-only on x64 still yields basic, armadillo is
untouched on x86, and a non-forbidden winner is returned directly.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.x64dbg.stealth import profile_from_candidates
from headless_re_mcp.core.models import Architecture


def _protector(name: str, *, confidence: float = 0.7, summary: str = "") -> dict[str, Any]:
    return {
        "category": "protector",
        "name": name,
        "summary": summary,
        "confidence": confidence,
    }


def test_x64_recovers_a_real_profile_when_armadillo_outscored_it() -> None:
    """Armadillo (token len 9) outscores the shorter "themida" token, but on x64
    it cannot apply, so the applicable Themida match must win instead of basic."""
    result = profile_from_candidates(
        [
            _protector("Armadillo", confidence=0.9),
            _protector("Themida", confidence=0.9),
        ],
        architecture=Architecture.X64,
    )
    assert result == "themida"


def test_x64_recovers_the_applicable_profile_across_two_candidates() -> None:
    result = profile_from_candidates(
        [
            _protector("Obsidium", confidence=0.6),
            _protector("Armadillo", confidence=0.95),
        ],
        architecture=Architecture.X64,
    )
    assert result == "obsidium"


def test_x64_armadillo_only_still_falls_back_to_basic() -> None:
    """The sole-match fallback is unchanged: nothing else applicable was seen."""
    result = profile_from_candidates(
        [_protector("Armadillo", confidence=0.7)],
        architecture=Architecture.X64,
    )
    assert result == "basic"


def test_x86_keeps_armadillo_even_when_it_is_the_top_match() -> None:
    """Armadillo is valid on x86, so it is not forbidden and not downgraded."""
    result = profile_from_candidates(
        [
            _protector("Armadillo", confidence=0.9),
            _protector("Themida", confidence=0.5),
        ],
        architecture=Architecture.X86,
    )
    assert result == "armadillo"


def test_a_non_forbidden_winner_is_returned_directly_on_x64() -> None:
    """When the top match already applies, the applicable-tracking is a no-op."""
    result = profile_from_candidates(
        [
            _protector("VMProtect", confidence=0.9),
            _protector("Armadillo", confidence=0.2),
        ],
        architecture=Architecture.X64,
    )
    assert result == "vmp"


def test_armadillo_only_without_an_architecture_is_returned_as_is() -> None:
    """No architecture means no forbidden set, so armadillo is not downgraded."""
    result = profile_from_candidates([_protector("Armadillo", confidence=0.7)])
    assert result == "armadillo"

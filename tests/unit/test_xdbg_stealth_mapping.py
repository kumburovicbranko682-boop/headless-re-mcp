"""Pure-function edges of the ScyllaHide profile whitelist and packer mapping.

test_xdbg_stealth.py drives the whole feature through the service; these pin the
mapping helpers on their own -- the word-boundary that stops a short token like
``vmp`` matching inside another word, the per-architecture allowlist, the
section round-trip, and the fail-closed rejection paths -- so a regression shows
up here rather than as a wrong debugger profile at launch.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.x64dbg.stealth import (
    PROFILE_SECTIONS,
    X64_FORBIDDEN_PROFILES,
    StealthError,
    allowed_profiles,
    canonical_profile_id,
    profile_from_candidates,
    profile_id_for_section,
    section_for_profile,
    stealth_hint_profile,
)
from headless_re_mcp.core.models import Architecture


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("vmp", "vmp"),
        ("VMProtect", "vmp"),
        ("vmprotect", "vmp"),
        ("tmd", "themida"),
        ("winlicense", "themida"),
        ("winlic", "themida"),
        ("Oreans", "themida"),
        ("Themida x86/x64", "themida"),
        ("disabled", "off"),
        ("none", "off"),
        ("  BASIC  ", "basic"),
    ],
)
def test_canonical_profile_id_maps_aliases_and_sections(raw: str, expected: str) -> None:
    assert canonical_profile_id(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", "titanhide", "vmprotectx"])
def test_canonical_profile_id_rejects_unknown_or_empty(bad: str) -> None:
    with pytest.raises(StealthError) as caught:
        canonical_profile_id(bad)
    assert caught.value.code == "invalid_params"
    # The refusal names what is allowed so a caller can correct it.
    assert caught.value.details["allowed"] == sorted(PROFILE_SECTIONS)


def test_a_short_token_only_matches_on_a_word_boundary() -> None:
    """``vmp``/``tmd`` are 3 chars, so they must not match inside another word."""
    buried = profile_from_candidates(
        [{"category": "protector", "name": "Xvmpx", "confidence": 0.9}]
    )
    assert buried is None

    standalone = profile_from_candidates(
        [{"category": "protector", "name": "VMP", "confidence": 0.9}]
    )
    assert standalone == "vmp"


def test_a_non_packer_category_is_ignored_even_if_the_name_matches() -> None:
    assert (
        profile_from_candidates(
            [{"category": "compiler", "name": "Themida", "confidence": 1.0}]
        )
        is None
    )


def test_the_longer_detection_token_wins_over_a_shorter_one() -> None:
    """``vmprotect`` must beat the bare ``vmp`` abbreviation in the same blob."""
    assert (
        profile_from_candidates(
            [{"category": "protector", "name": "VMProtect vmp", "confidence": 0.5}]
        )
        == "vmp"
    )
    # Themida's tokens are longer than vmp, so a blob naming both resolves to it.
    assert (
        profile_from_candidates(
            [{"category": "protector", "name": "Themida over vmp", "confidence": 0.5}]
        )
        == "themida"
    )


def test_allowed_profiles_drop_x86_only_entries_on_x64() -> None:
    x64 = allowed_profiles(architecture=Architecture.X64)
    x86 = allowed_profiles(architecture=Architecture.X86)

    assert set(X64_FORBIDDEN_PROFILES).isdisjoint(x64)
    assert set(X64_FORBIDDEN_PROFILES).issubset(x86)
    # The always-available floor is present on both.
    for base in ("off", "basic", "vmp"):
        assert base in x64
        assert base in x86


def test_section_for_profile_is_arch_aware_and_round_trips() -> None:
    # Armadillo is fine on x86 and resolves to its section...
    section = section_for_profile("armadillo", architecture=Architecture.X86)
    assert section == "Armadillo x86"
    assert profile_id_for_section(section) == "armadillo"
    # ...but is refused on x64.
    with pytest.raises(StealthError) as caught:
        section_for_profile("armadillo", architecture=Architecture.X64)
    assert caught.value.code == "invalid_params"

    # Every profile section maps back to its id.
    for profile_id, section_name in PROFILE_SECTIONS.items():
        assert profile_id_for_section(section_name) == profile_id
    assert profile_id_for_section("Not A Section") is None


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"stealth_hint": "not-a-dict"},
        {"stealth_hint": {"profile": ""}},
        {"stealth_hint": {"profile": "titanhide"}},
        {"stealth_hint": {}},
    ],
)
def test_stealth_hint_profile_is_none_for_missing_or_invalid_metadata(
    metadata: dict,
) -> None:
    assert stealth_hint_profile(metadata) is None


def test_stealth_hint_profile_canonicalizes_a_stored_alias() -> None:
    assert stealth_hint_profile({"stealth_hint": {"profile": "WinLicense"}}) == "themida"

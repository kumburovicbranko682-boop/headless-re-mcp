"""apk.strings scan_capped must mean "more unique strings may exist", not "a duplicate arrived".

get_strings() yields distinct string constants, but strings.strings() dedups
into a set *after* truncating each to _MAX_STRING_LEN, so two distinct long
strings that share a prefix collapse to one value. The old scan-cap check sat at
the top of the loop and fired whenever the set was already full -- including on
such a truncation duplicate (or an exact repeat) -- so a DEX whose unique strings
were in fact all collected reported scan_capped=True. That contradicts both the
tool docstring ("scan_capped is true when more unique strings may exist") and the
sibling xrefs, which only flags has_more "once something was actually left out".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeParsed:
    def __init__(self, values: list[str]) -> None:
        self.analysis = self
        self._values = values

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(value) for value in self._values]


def _client_over(values: list[str]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign, assignment, return-value]
    return client


def test_exact_duplicate_after_cap_does_not_flag_scan_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repeat of an already-seen value after the cap fills leaves the set complete.

    Cap three uniques, then feed a fourth item equal to the first. The unique
    set is {a, b, c} either way; the fourth adds nothing, so nothing was left
    out and scan_capped must stay False -- the old top-of-loop check reported
    True here.
    """
    monkeypatch.setattr(apk_client, "_MAX_STRINGS_COLLECT", 3)
    client = _client_over(["a", "b", "c", "a"])

    payload = client.strings(Path("dummy.apk"))

    assert payload["scan_capped"] is False
    assert payload["total"] == 3
    assert payload["strings"] == ["a", "b", "c"]


def test_truncation_collision_after_cap_does_not_flag_scan_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real trigger: two distinct long strings collapse under _MAX_STRING_LEN.

    get_strings yields distinct constants, so an exact repeat cannot occur in
    practice -- but the collector truncates to _MAX_STRING_LEN before adding to
    the set. With the length capped at two, "aaZZZ" truncates to "aa" and
    collides with the already-collected "aa". The unique (truncated) set is
    still complete, so scan_capped must be False.
    """
    monkeypatch.setattr(apk_client, "_MAX_STRINGS_COLLECT", 3)
    monkeypatch.setattr(apk_client, "_MAX_STRING_LEN", 2)
    client = _client_over(["aa", "bb", "cc", "aaZZZ"])

    payload = client.strings(Path("dummy.apk"))

    assert payload["scan_capped"] is False
    assert payload["total"] == 3
    assert payload["strings"] == ["aa", "bb", "cc"]


def test_a_new_unique_beyond_the_cap_still_flags_scan_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flag must still fire when a genuinely new string is dropped.

    Cap three uniques, then feed a distinct fourth value: it cannot be
    collected, so the caller is told the scan was capped and more uniques exist.
    """
    monkeypatch.setattr(apk_client, "_MAX_STRINGS_COLLECT", 3)
    client = _client_over(["a", "b", "c", "d"])

    payload = client.strings(Path("dummy.apk"))

    assert payload["scan_capped"] is True
    assert payload["total"] == 3
    assert "d" not in payload["strings"]


def test_scan_capped_false_when_everything_fits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Below the cap with no duplicates, nothing is dropped and the flag is False."""
    monkeypatch.setattr(apk_client, "_MAX_STRINGS_COLLECT", 5)
    client = _client_over(["a", "b", "c"])

    payload = client.strings(Path("dummy.apk"))

    assert payload["scan_capped"] is False
    assert payload["total"] == 3

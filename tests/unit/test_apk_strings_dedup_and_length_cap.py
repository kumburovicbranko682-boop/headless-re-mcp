"""``apk.strings`` returns a *deduplicated, length-bounded, sorted* set of DEX strings.

The DEX string pool is not a tidy list of distinct short values: the same string
literal is referenced thousands of times, and a pool can hold a multi-megabyte
blob (an embedded certificate, a minified asset). ``strings`` folds all of that
into a bounded, stable page::

    seen: set[str] = set()
    for item in parsed.analysis.get_strings():
        if len(seen) >= _MAX_STRINGS_COLLECT:      # cap on DISTINCT strings
            scan_more = True; break
        seen.add(str(item.get_value())[:_MAX_STRING_LEN])   # clip THEN dedup
    values = sorted(seen)                           # stable order for paging

The existing ``strings`` test feeds 25 already-distinct short values
(``s0``..``s24``), so every one of those behaviours is inert -- with no
duplicates the ``set`` is indistinguishable from a list, nothing is long enough
to clip, the 5 000 scan cap is never neared, and ``s0``..``s24`` are close enough
to sorted that ordering is never actually asserted. Four things a distinct-short
fixture cannot show:

* **Duplicates collapse to one.** ``seen`` is a set, so a value repeated N times
  counts once; ``total`` is the number of *distinct* strings, not raw
  occurrences. Turn the set into a list and one heavily-referenced literal
  inflates the table with thousands of identical rows.

* **Each value is clipped to ``_MAX_STRING_LEN`` before it is deduped.** A
  3 000-char string is stored at 2 000, and -- because the clip happens first --
  two strings that share the same 2 000-char prefix collapse into one entry.
  Drop the clip and a single huge pool string is inlined whole and the prefix
  collapse stops happening.

* **The scan cap counts distinct strings, not occurrences.** Because the guard
  reads ``len(seen)``, a flood of the *same* value never trips it -- only that
  many genuinely distinct strings do. With a list the flood would hit the cap
  early and report ``scan_capped`` on a pool that held one string.

* **The page is sorted.** Pagination across calls needs a stable order;
  ``sorted(seen)`` provides it, since a set has none of its own.

These drive ``strings`` through a fake parsed APK -- no androguard, no DEX --
and shrink ``_MAX_STRINGS_COLLECT`` where the 5 000 default would be unwieldy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import _MAX_STRING_LEN, ApkClient


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeParsed:
    def __init__(self, values: list[str]) -> None:
        self._values = values
        self.analysis = self

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(value) for value in self._values]


def _client(values: list[str]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign]
    return client


def test_duplicate_strings_collapse_to_one_distinct_entry() -> None:
    """A value repeated many times is one row; ``total`` counts distinct strings.

    The DEX pool references the same literal over and over; the caller wants the
    set of strings, not the multiset. ``total`` here is 2 (``a`` and ``dup``),
    not 4.
    """
    payload = _client(["dup", "dup", "dup", "a"]).strings(Path("x.apk"), offset=0, limit=100)
    assert payload["strings"] == ["a", "dup"]
    assert payload["total"] == 2
    assert payload["count"] == 2


def test_a_long_string_is_clipped_before_it_is_deduped() -> None:
    """Clipping happens first, so a 2 000-char shared prefix collapses two strings.

    Both values exceed ``_MAX_STRING_LEN`` and agree on their first 2 000 chars;
    stored at 2 000 they are identical, so the set holds one. The stored value is
    exactly the cap, never the original 2 003 chars.
    """
    prefix = "X" * _MAX_STRING_LEN
    payload = _client([prefix + "AAA", prefix + "BBB"]).strings(
        Path("x.apk"), offset=0, limit=100
    )
    assert payload["total"] == 1
    assert len(payload["strings"][0]) == _MAX_STRING_LEN
    assert payload["strings"][0] == prefix


def test_a_distinct_string_below_the_cap_is_kept_whole() -> None:
    """A value at or under the cap is stored verbatim -- the clip is a ceiling."""
    exact = "Y" * _MAX_STRING_LEN
    payload = _client([exact]).strings(Path("x.apk"), offset=0, limit=100)
    assert payload["strings"] == [exact]
    assert payload["total"] == 1


def test_the_scan_cap_counts_distinct_strings_not_raw_occurrences(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flood of one value never trips the collection cap; only distinct ones do.

    The guard reads ``len(seen)``, so a hundred copies of ``same`` leave the set
    at size one and ``scan_capped`` False, while five genuinely distinct values
    against a cap of three stop the scan and set the flag.
    """
    monkeypatch.setattr(apk_client, "_MAX_STRINGS_COLLECT", 3)

    flood = _client(["same"] * 100).strings(Path("x.apk"), offset=0, limit=100)
    assert flood["total"] == 1
    assert flood["scan_capped"] is False

    distinct = _client(["a", "b", "c", "d", "e"]).strings(Path("x.apk"), offset=0, limit=100)
    assert distinct["total"] == 3
    assert distinct["scan_capped"] is True


def test_strings_come_back_sorted() -> None:
    """The page is a slice of ``sorted(seen)``, so it comes out ordered.

    A set has no order of its own; pagination across calls depends on this being
    stable and sorted.
    """
    payload = _client(["cherry", "apple", "banana"]).strings(
        Path("x.apk"), offset=0, limit=100
    )
    assert payload["strings"] == ["apple", "banana", "cherry"]
    assert payload["strings"] == sorted(payload["strings"])


def test_dedup_is_reflected_in_pagination_totals() -> None:
    """Paging is over distinct values: five occurrences of two strings page as two.

    A limit of 1 over a pool that is really two distinct strings returns one now
    and flags more, and the total stays 2 -- the raw five occurrences never leak
    into the page math.
    """
    values = ["beta", "alpha", "beta", "alpha", "beta"]
    first = _client(values).strings(Path("x.apk"), offset=0, limit=1)
    assert first["total"] == 2
    assert first["count"] == 1
    assert first["strings"] == ["alpha"]
    assert first["has_more"] is True

    second = _client(values).strings(Path("x.apk"), offset=1, limit=1)
    assert second["strings"] == ["beta"]
    assert second["has_more"] is False

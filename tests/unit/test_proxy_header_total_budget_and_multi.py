"""``_bounded_headers`` bounds *total* header bytes and handles real mitmproxy Headers.

``flow.get`` inlines a captured flow's headers, so a hostile or chatty server
could otherwise stuff megabytes of them into the tool response. ``_bounded_headers``
defends on three independent axes and reads the headers the mitmproxy way::

    try:
        items = list(headers.items(multi=True))   # all pairs, repeats included
    except TypeError:
        items = list(headers.items())
    except Exception:
        return {}, True                            # unreadable -> honest empty
    ...
    for key, value in items:
        name = str(key)
        if name not in out and len(out) >= _MAX_FLOW_HEADERS:   # count: distinct names
            truncated = True; break
        text, cut = _bounded_metadata(value, _MAX_HEADER_VALUE_BYTES)   # per-value
        entry_bytes = len(name...) + len(text...)
        if total + entry_bytes > _MAX_FLOW_HEADERS_TOTAL_BYTES:  # total bytes
            truncated = True; break
        total += entry_bytes
        out[name] = text                            # duplicate names -> last wins

The existing tests use plain ``dict`` fixtures, which pin the count cap (150
one-byte headers) and the per-value cap (one 16 KiB value), and the no-headers
case. Three things a ``dict`` cannot express are therefore unpinned:

* **The total-bytes budget is its own cap.** Headers can be individually small
  (under the per-value cap) and few (under the count cap) yet sum to megabytes.
  The count test's values are one byte and the per-value test has a single
  header, so neither approaches ``_MAX_FLOW_HEADERS_TOTAL_BYTES``. Remove the
  running-total check and forty 3 KiB headers -- legal on both other axes --
  inline ~120 KiB. This pins the ~64 KiB ceiling on the sum.

* **Duplicate names collapse to the last value, and repeats are free.** A real
  ``Headers`` returns every ``Set-Cookie`` from ``items(multi=True)``; the map
  keeps the last, and the ``name not in out`` clause means a repeat of an
  already-seen name does not spend the distinct-name budget. A ``dict`` has no
  duplicates, so neither behaviour is exercised: with the collapse broken a
  repeat could win as the first value, and without ``name not in out`` a burst
  of repeats past the 100th distinct name would spuriously truncate.

* **Unreadable headers are an honest empty-and-truncated, not a crash.** If
  ``items`` raises (a broken or half-parsed header block), the guard returns
  ``({}, True)`` so the reader sees "there were headers we could not show", not
  a dropped response or an exception escaping the addon.

These drive a mitmproxy-shaped ``Headers`` (supports ``items(multi=True)``) so
the real read path -- the one a plain ``dict`` skips -- is what runs.
"""

from __future__ import annotations

from types import SimpleNamespace

from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOW_HEADERS,
    _MAX_FLOW_HEADERS_TOTAL_BYTES,
    _MAX_HEADER_VALUE_BYTES,
    _bounded_headers,
)


class _MultiHeaders:
    """A mitmproxy-like Headers: ordered pairs, ``items(multi=True)`` returns repeats."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        if multi:
            return list(self._pairs)
        collapsed: dict[str, str] = {}
        for key, value in self._pairs:
            collapsed[key] = value
        return list(collapsed.items())


def _part(headers: object) -> SimpleNamespace:
    return SimpleNamespace(headers=headers)


def test_the_total_byte_budget_caps_headers_small_and_few_enough_to_pass_the_others() -> None:
    """Forty 3 KiB headers pass count and per-value but blow the total budget.

    Each value (3 KiB) is under the 4 KiB per-value cap and there are only 40
    (under the 100 count cap), so only the running-total guard can stop them.
    The kept sum must stay within ~64 KiB and the map must be flagged truncated.
    """
    value = "x" * 3000
    pairs = [(f"h{index}", value) for index in range(40)]
    out, truncated = _bounded_headers(_part(_MultiHeaders(pairs)))

    assert truncated is True
    assert len(out) < 40  # the budget cut the list short
    total = sum(len(k.encode("utf-8")) + len(v.encode("utf-8")) for k, v in out.items())
    assert total <= _MAX_FLOW_HEADERS_TOTAL_BYTES
    # Every kept value is intact (the per-value cap did not fire at 3 KiB).
    assert all(len(v) == 3000 for v in out.values())


def test_duplicate_header_names_collapse_to_the_last_value() -> None:
    """Three Set-Cookie values collapse to the last, matching dict(headers).

    A real Headers yields every repeat from items(multi=True); the map keeps the
    last write, so a reader sees the final value, not the first.
    """
    pairs = [("set-cookie", "first"), ("set-cookie", "second"), ("set-cookie", "third")]
    out, truncated = _bounded_headers(_part(_MultiHeaders(pairs)))

    assert out == {"set-cookie": "third"}
    assert truncated is False


def test_repeats_of_a_seen_name_do_not_spend_the_distinct_name_budget() -> None:
    """100 distinct names plus a burst of repeats stays exactly 100, untruncated.

    The count cap is on *distinct* names: once ``_MAX_FLOW_HEADERS`` names are in
    the map, a repeat of one already there overwrites in place rather than
    tripping the cap. The map holds the full 100 with the repeat's last value,
    and nothing is flagged dropped.
    """
    distinct = [(f"d{index}", "v") for index in range(_MAX_FLOW_HEADERS)]
    repeats = [("d0", "again")] * 50
    out, truncated = _bounded_headers(_part(_MultiHeaders(distinct + repeats)))

    assert len(out) == _MAX_FLOW_HEADERS
    assert out["d0"] == "again"
    assert truncated is False


def test_a_101st_distinct_name_does_trip_the_count_cap() -> None:
    """The distinct-name cap still bites: the 101st new name truncates.

    Contrast with the repeats above -- a genuinely new name past the ceiling is
    dropped and the map is flagged, so "repeats are free" is not "the cap is
    gone".
    """
    distinct = [(f"d{index}", "v") for index in range(_MAX_FLOW_HEADERS + 5)]
    out, truncated = _bounded_headers(_part(_MultiHeaders(distinct)))

    assert len(out) == _MAX_FLOW_HEADERS
    assert truncated is True


def test_a_single_repeated_name_over_the_per_value_cap_is_still_clipped() -> None:
    """The per-value cap applies to the value that wins the collapse too."""
    huge = "z" * (_MAX_HEADER_VALUE_BYTES * 3)
    pairs = [("x-big", "small"), ("x-big", huge)]
    out, truncated = _bounded_headers(_part(_MultiHeaders(pairs)))

    assert len(out["x-big"].encode("utf-8")) == _MAX_HEADER_VALUE_BYTES
    assert truncated is True


class _BoomHeaders:
    """A Headers whose iteration raises -- a broken or half-parsed block."""

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        raise RuntimeError("header block is corrupt")


def test_unreadable_headers_are_empty_and_flagged_truncated() -> None:
    """A Headers that cannot be iterated yields ({}, True), not a crash.

    The reader must be able to tell "there were headers we could not show" from
    "there were no headers" -- the empty map with truncated True says the
    former; an exception escaping the addon would drop the whole flow response.
    """
    out, truncated = _bounded_headers(_part(_BoomHeaders()))
    assert out == {}
    assert truncated is True

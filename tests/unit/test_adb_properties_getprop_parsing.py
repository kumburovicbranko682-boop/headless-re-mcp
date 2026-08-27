"""``device.properties`` parses real ``getprop`` output: empty values, junk, and whitespace.

``getprop`` prints one property per line as ``[key]: [value]``, and ``properties``
turns that into a bounded dict::

    for line in text.splitlines():
        match = re.match(r"^\\[(.+?)\\]:\\s*\\[(.*)\\]$", line.strip());
        if not match:
            continue;                               # not a [k]: [v] line -> skip
        if len(props) >= capped:
            has_more = True; break;                 # cap counts *properties*, after the match
        props[match.group(1)] = match.group(2);     # value group is (.*) -> may be empty

The existing ``properties`` tests all feed clean, non-empty, homogeneous lines
(``[ro.build.version.sdk]: [34]``, ``[ro.item0]: [0]`` …) -- one value per key,
never blank, never interleaved with junk, always exactly one space after the
colon. So four behaviours real ``getprop`` output exercises are unpinned:

* **An empty value is a real property, not a dropped one.** ``getprop`` prints
  ``[persist.sys.locale]: []`` for set-but-empty keys constantly; the value group
  is ``(.*)`` precisely so the key survives with ``""``. Tighten it to ``(.+)`` and
  every empty-valued property silently vanishes from the map.

* **Lines that are not ``[k]: [v]`` pairs are skipped, not fatal.** Blank lines,
  a stray banner, or a ``key=value`` fragment do not match; the ``continue`` steps
  over them. Turn that into a ``break`` and the first non-pair line truncates the
  whole property set.

* **Junk between pairs does not consume the cap budget.** The cap is checked
  *after* the regex match, against the count of real properties -- so junk lines
  interleaved with two valid props, at ``limit=2``, still yield both with
  ``has_more`` False. A fixture of only valid lines cannot tell the cap counts
  properties rather than raw lines.

* **Surrounding and post-colon whitespace is tolerated.** The line is
  ``.strip()``-ed and the pattern allows ``\\s*`` after ``]:``, so
  ``  [ro.x]:   [val]  `` still parses. Drop either and a slightly-spaced line
  (which ``getprop`` does emit) is discarded.

These drive ``AdbBackend.properties`` through a fake device whose shell returns a
canned dump -- no adbutils, no emulator.
"""

from __future__ import annotations

from headless_re_mcp.backends.adb.client import AdbBackend


class _ShellDev:
    """A device whose ``shell`` returns one canned ``getprop`` dump."""

    def __init__(self, output: str) -> None:
        self._output = output

    def shell(self, cmd: object, timeout: float | None = None) -> str:
        del cmd, timeout
        return self._output


def _properties(output: str, **kwargs: object) -> dict:
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = object()
    backend._device = lambda serial: _ShellDev(output)  # type: ignore[method-assign]
    return backend.properties("emulator-5554", **kwargs)  # type: ignore[arg-type]


def test_an_empty_value_property_is_kept_not_dropped() -> None:
    """``[key]: []`` yields ``key -> ""``, not a missing key.

    ``getprop`` emits set-but-empty properties routinely; the ``(.*)`` value group
    keeps them. A ``(.+)`` would drop the key entirely, hiding a real property.
    """
    payload = _properties("[persist.sys.locale]: []\n[ro.product.name]: [Pixel]")

    assert payload["properties"] == {"persist.sys.locale": "", "ro.product.name": "Pixel"}
    assert payload["count"] == 2


def test_lines_that_are_not_property_pairs_are_skipped() -> None:
    """Blank, banner, and ``key=value`` lines are skipped; valid pairs still parse.

    The ``continue`` on a non-match steps over junk. Were it a ``break``, the first
    non-pair line (here a leading banner) would truncate the whole set to empty.
    """
    dump = "\n".join(
        [
            "# a banner line, not a property",
            "[ro.a]: [1]",
            "",
            "   ",
            "ro.b=not-bracketed",
            "[ro.c]: [3]",
        ]
    )
    payload = _properties(dump)

    assert payload["properties"] == {"ro.a": "1", "ro.c": "3"}
    assert payload["count"] == 2


def test_junk_lines_do_not_consume_the_cap_budget() -> None:
    """Two valid props with junk between them, at limit 2, both survive.

    The cap is checked after the regex match, so it counts real properties, not
    raw lines. Junk interleaved with the pairs neither fills the budget nor sets
    ``has_more``.
    """
    dump = "\n".join(
        [
            "junk-1",
            "[ro.a]: [1]",
            "junk-2",
            "junk-3",
            "[ro.b]: [2]",
        ]
    )
    payload = _properties(dump, limit=2)

    assert payload["properties"] == {"ro.a": "1", "ro.b": "2"}
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_surrounding_and_post_colon_whitespace_is_tolerated() -> None:
    """A leading/trailing- and extra-space line still parses to key and value.

    ``getprop`` output is ``.strip()``-ed and the pattern allows ``\\s*`` after the
    colon, so ``  [ro.x]:   [val]  `` resolves to ``ro.x -> val``.
    """
    payload = _properties("  [ro.x]:   [val]  ")

    assert payload["properties"] == {"ro.x": "val"}
    assert payload["count"] == 1

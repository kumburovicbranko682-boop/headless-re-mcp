"""apk.export_sources must return a deterministic, alphabetical-first listing.

jadx writes a tree and the client lists the .java files, capped. rglob yields in
arbitrary filesystem order, so capping before sorting returned an arbitrary
``cap``-sized subset (then sorted among itself) for any tree with more than
``cap`` files -- a different set on a different machine or run, and never the
alphabetical head. These pin the sort-before-cap contract with a deliberately
reversed rglob so the guard holds regardless of the real filesystem's order.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx import client as jadx_client
from headless_re_mcp.backends.jadx.client import _capped_java_listing


def _reverse_rglob(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Path.rglob yield in reverse-sorted order for the test's scope."""
    real_rglob = Path.rglob

    def reversed_rglob(self: Path, pattern: str) -> Iterator[Path]:
        found = sorted(real_rglob(self, pattern), key=str)
        return iter(reversed(found))

    monkeypatch.setattr(Path, "rglob", reversed_rglob)


def _make_tree(root: Path, names: list[str]) -> None:
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class X {}", encoding="utf-8")


def test_listing_returns_the_alphabetical_head_not_an_arbitrary_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "out"
    root.mkdir()
    files = [f"pkg/C{index:03d}.java" for index in range(10)]
    _make_tree(root, files)
    _reverse_rglob(monkeypatch)

    names, total, has_more = _capped_java_listing(root, cap=3)

    # Regardless of rglob order, the first cap must be the alphabetical head.
    # Under the old cap-before-sort code this returned the last three
    # (C007/C008/C009 sorted), never the C000/C001/C002 a caller expects.
    assert names == ["pkg/C000.java", "pkg/C001.java", "pkg/C002.java"]
    assert total == 10
    assert has_more is True


def test_a_full_listing_under_the_cap_is_sorted_and_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "out"
    root.mkdir()
    _make_tree(root, ["b.java", "a.java", "c.java"])
    _reverse_rglob(monkeypatch)

    names, total, has_more = _capped_java_listing(root, cap=100)

    assert names == ["a.java", "b.java", "c.java"]
    assert total == 3
    assert has_more is False


def test_counting_stops_at_the_ceiling_and_flags_more(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_client, "_MAX_COUNTED_FILES", 5)
    root = tmp_path / "out"
    root.mkdir()
    _make_tree(root, [f"f{index:02d}.java" for index in range(8)])

    names, total, has_more = _capped_java_listing(root, cap=100)

    # The ceiling bounds both the count and the collected set; has_more says the
    # tree held more than we counted.
    assert total == 5
    assert len(names) == 5
    assert has_more is True


def test_export_sources_listing_is_deterministic_across_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "out"
    root.mkdir()
    _make_tree(root, [f"a/b/C{index:02d}.java" for index in range(20)])
    _reverse_rglob(monkeypatch)

    first, _, _ = _capped_java_listing(root, cap=5)
    second, _, _ = _capped_java_listing(root, cap=5)

    assert first == second
    assert first == [f"a/b/C{index:02d}.java" for index in range(5)]

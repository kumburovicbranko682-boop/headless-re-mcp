"""_capped_java_listing bounds the decompiled source tree jadx reports.

Like the jsre unpack listing, the java-source listing is capped on two axes --
the returned name count (``cap``) and the total files walked
(``_MAX_COUNTED_FILES``) -- and, matching that sibling, the two truncations are
reported by distinct signals: ``has_more`` says the returned names are a clipped
page, while ``listing_truncated`` says the walk hit its ceiling so the count is a
floor rather than an exact total. It also globs ``*.java``, so a directory that
happens to be named ``*.java`` must not be counted as a source file. None of
these branches had a unit test; they are pinned here with tmp trees, no jadx
binary required.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import _capped_java_listing


def test_java_listing_returns_sorted_names_within_the_cap(tmp_path: Path) -> None:
    for name in ("B.java", "A.java", "C.java"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    names, total, has_more, listing_truncated = _capped_java_listing(tmp_path, cap=10)
    assert names == ["A.java", "B.java", "C.java"]
    assert total == 3
    assert has_more is False
    assert listing_truncated is False


def test_java_listing_caps_names_but_counts_all_and_flags_has_more(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"C{index}.java").write_text("x", encoding="utf-8")
    names, total, has_more, listing_truncated = _capped_java_listing(tmp_path, cap=2)
    assert len(names) == 2
    assert names == sorted(names)
    assert total == 5
    assert has_more is True
    # The page is clipped, but every file was walked, so the count is exact --
    # only the walk ceiling makes it a floor.
    assert listing_truncated is False


def test_java_listing_capped_page_is_the_alphabetical_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A capped java_files page must be the alphabetically first names, not an
    arbitrary rglob-order slice that was merely sorted among itself.

    rglob order is filesystem-dependent, so the walk is handed the names in
    reverse and the cap-3 page is required to still be C000..C002. With the old
    cap-then-sort the three kept would be C009/C008/C007 (the first walked),
    sorted to C007..C009 -- and a class that sorts early but is walked late would
    drop out of the middle of a page that looked ordered, which a caller scanning
    the listing reads as "not decompiled". total still counts every walked file.
    """
    files = [tmp_path / f"C{index:03d}.java" for index in range(10)]
    for source in files:
        source.write_text("x", encoding="utf-8")
    walk_order = list(reversed(files))
    monkeypatch.setattr(Path, "rglob", lambda self, pattern: iter(walk_order))
    names, total, has_more, listing_truncated = _capped_java_listing(tmp_path, cap=3)
    assert total == 10
    assert has_more is True
    assert listing_truncated is False
    assert names == ["C000.java", "C001.java", "C002.java"]


def test_java_listing_of_a_non_directory_is_empty(tmp_path: Path) -> None:
    regular = tmp_path / "Main.java"
    regular.write_text("x", encoding="utf-8")
    assert _capped_java_listing(regular, cap=10) == ([], 0, False, False)


def test_java_listing_ignores_a_directory_named_like_a_source(tmp_path: Path) -> None:
    """rglob('*.java') also matches a directory named ``pkg.java``; the is_file
    filter must keep it out of the count so it is not reported as a source."""
    (tmp_path / "pkg.java").mkdir()
    (tmp_path / "Real.java").write_text("x", encoding="utf-8")
    names, total, has_more, listing_truncated = _capped_java_listing(tmp_path, cap=10)
    assert total == 1
    assert names == ["Real.java"]
    assert has_more is False
    assert listing_truncated is False


def test_java_listing_reports_nested_relative_paths(tmp_path: Path) -> None:
    (tmp_path / "com" / "example").mkdir(parents=True)
    (tmp_path / "com" / "example" / "Main.java").write_text("x", encoding="utf-8")
    (tmp_path / "Top.java").write_text("x", encoding="utf-8")
    names, total, has_more, listing_truncated = _capped_java_listing(tmp_path, cap=10)
    assert total == 2
    assert set(names) == {"Top.java", str(Path("com/example/Main.java"))}
    assert has_more is False
    assert listing_truncated is False


def test_java_listing_flags_listing_truncated_at_the_walk_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At the walk ceiling the count is a floor, so listing_truncated is set --
    the signal that distinguishes it from a tree of exactly ceiling files, which
    a bare has_more (also True here) cannot. cap exceeds the ceiling so the two
    axes are exercised independently: nothing is clipped by the page cap, only by
    the walk.
    """
    monkeypatch.setattr("headless_re_mcp.backends.jadx.client._MAX_COUNTED_FILES", 2)
    for index in range(4):
        (tmp_path / f"F{index}.java").write_text("x", encoding="utf-8")
    names, total, has_more, listing_truncated = _capped_java_listing(tmp_path, cap=10)
    assert total == 2
    assert len(names) == 2
    assert has_more is True
    assert listing_truncated is True

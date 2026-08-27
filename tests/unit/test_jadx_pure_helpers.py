"""_capped_java_listing bounds the decompiled source tree jadx reports.

Like the jsre unpack listing, the java-source listing is capped on two axes --
the returned name count (``cap``) and the total files walked
(``_MAX_COUNTED_FILES``) -- and ``has_more`` is the only signal a caller has
that the tree it was shown is a clipped view. It also globs ``*.java``, so a
directory that happens to be named ``*.java`` must not be counted as a source
file. None of these branches had a unit test; they are pinned here with tmp
trees, no jadx binary required.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import _capped_java_listing


def test_java_listing_returns_sorted_names_within_the_cap(tmp_path: Path) -> None:
    for name in ("B.java", "A.java", "C.java"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert names == ["A.java", "B.java", "C.java"]
    assert total == 3
    assert has_more is False


def test_java_listing_caps_names_but_counts_all_and_flags_has_more(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"C{index}.java").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(tmp_path, cap=2)
    assert len(names) == 2
    assert names == sorted(names)
    assert total == 5
    assert has_more is True


def test_java_listing_of_a_non_directory_is_empty(tmp_path: Path) -> None:
    regular = tmp_path / "Main.java"
    regular.write_text("x", encoding="utf-8")
    assert _capped_java_listing(regular, cap=10) == ([], 0, False)


def test_java_listing_ignores_a_directory_named_like_a_source(tmp_path: Path) -> None:
    """rglob('*.java') also matches a directory named ``pkg.java``; the is_file
    filter must keep it out of the count so it is not reported as a source."""
    (tmp_path / "pkg.java").mkdir()
    (tmp_path / "Real.java").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert total == 1
    assert names == ["Real.java"]
    assert has_more is False


def test_java_listing_reports_nested_relative_paths(tmp_path: Path) -> None:
    (tmp_path / "com" / "example").mkdir(parents=True)
    (tmp_path / "com" / "example" / "Main.java").write_text("x", encoding="utf-8")
    (tmp_path / "Top.java").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert total == 2
    assert set(names) == {"Top.java", str(Path("com/example/Main.java"))}
    assert has_more is False


def test_java_listing_stops_and_flags_has_more_at_the_walk_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jadx.client._MAX_COUNTED_FILES", 2)
    for index in range(4):
        (tmp_path / f"F{index}.java").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert total == 2
    assert has_more is True

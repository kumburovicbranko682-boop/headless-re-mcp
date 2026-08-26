"""capped_file_size refuses a single oversized capture on the spot.

prune_capped_dir keeps the newest entry even past the byte budget, so one huge
screenshot or pull would otherwise sit on disk for the life of the process.
capped_file_size is the counterpart the writer calls to delete that newest file
when it alone blows the cap. prune_capped_dir has direct tests; this primitive
was only reached through a screenshot test that monkeypatches the ceiling.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.limits import capped_file_size


def test_a_file_over_the_cap_is_reported_and_deleted(tmp_path: Path) -> None:
    path = tmp_path / "huge.png"
    path.write_bytes(b"x" * 100)

    size, over = capped_file_size(path, cap=10)

    assert (size, over) == (100, True)
    assert not path.exists(), "the point is to remove the file that just blew the cap"


def test_a_file_at_or_under_the_cap_is_kept(tmp_path: Path) -> None:
    under = tmp_path / "small.png"
    under.write_bytes(b"x" * 5)
    assert capped_file_size(under, cap=10) == (5, False)
    assert under.exists()

    # The boundary is strict: size == cap is not "over".
    exact = tmp_path / "exact.png"
    exact.write_bytes(b"x" * 10)
    assert capped_file_size(exact, cap=10) == (10, False)
    assert exact.exists()


def test_a_missing_file_is_zero_bytes_and_not_over(tmp_path: Path) -> None:
    """A capture that never landed must not read as an over-cap failure."""
    assert capped_file_size(tmp_path / "never_written.png", cap=10) == (0, False)

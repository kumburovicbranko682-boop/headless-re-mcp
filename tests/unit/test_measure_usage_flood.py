"""measure_usage must bound its walk by entries, not just files.

A files-only ceiling never trips on a tree of empty directories -- a shape a
decode/unpack step or a hostile archive can produce -- so the artifact walk that
the readiness/usage probe runs would traverse the whole tree, which is the stall
this cap exists to prevent. The fix counts every entry rglob yields (files and
directories) toward the limit while still reporting only files in ``files``.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.retention import measure_usage


def test_a_directory_flood_still_trips_the_walk_ceiling(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    # An empty-directory flood: no files at all, so a files-only counter never
    # advances. Far more directories than the ceiling below.
    for index in range(60):
        (root / f"d{index:03d}").mkdir()

    usage = measure_usage(root, file_limit=10)

    assert usage.truncated is True, (
        "an all-directory tree must trip the entry ceiling; a files-only bound "
        "would walk it to the end"
    )
    assert usage.files == 0, "there are no files, so the files count stays zero"
    assert usage.bytes == 0


def test_a_small_tree_is_not_labelled_truncated(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    (root / "sub").mkdir(parents=True)
    (root / "a.bin").write_bytes(b"x" * 16)
    (root / "sub" / "b.bin").write_bytes(b"y" * 32)

    usage = measure_usage(root, file_limit=1000)

    assert usage.truncated is False
    assert usage.files == 2
    assert usage.bytes == 48

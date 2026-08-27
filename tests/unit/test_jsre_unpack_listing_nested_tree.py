"""``js.unpack_bundle`` lists a nested webcrack tree, not just a flat directory.

``unpack_bundle`` hands its output directory to ``_capped_file_listing``, which
walks it recursively, skips anything that is not a regular file, and reports each
file by its path relative to the output root::

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        ...
        names.append(str(path.relative_to(root)))
    names.sort()

webcrack does not write a flat directory: a real unpack produces
``deobfuscated.js`` at the top plus an ``unpacked/`` tree of modules, often
nested several levels deep, alongside intermediate directories. Three behaviours
here are load-bearing, and every existing ``unpack_bundle`` test writes only
flat top-level files (``out_dir / f"mod-{i}.js"``), so none of them is
exercised:

* **The walk recurses.** ``rglob`` reaches modules under ``unpacked/…``. Swap it
  for a non-recursive ``glob`` and everything below the top level vanishes from
  both the file list and the counts -- ``file_count`` then reads as a near-empty
  bundle when webcrack in fact emitted a deep tree.

* **Directories are not files.** ``rglob("*")`` yields the intermediate
  directories too; the ``is_file()`` skip keeps them out of the listing and the
  count. Drop it and every ``unpacked/`` / ``vendor/`` directory (and any empty
  one) is counted as if it were a module and shows up as a bare directory name in
  ``files``.

* **Names are relative to the root.** ``relative_to(root)`` preserves the tree
  shape (``unpacked/vendor/lib.js``). Collapse it to ``path.name`` and two
  modules that share a basename in different directories collide into one name,
  and the caller loses the path it needs to open the file back.

A flat fixture cannot tell any of these from their broken forms: with no
subdirectories, ``rglob`` and ``glob`` return the same set, there is no directory
to skip, and ``relative_to`` equals ``name``. These use a genuine nested tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient


def _tree_run(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
    """Fake webcrack: emit a nested tree (files + intermediate/empty dirs)."""
    del timeout, maximum
    out_dir = Path(cmd[cmd.index("-o") + 1])
    if not any(out_dir.iterdir()):
        (out_dir / "deobfuscated.js").write_text("top", encoding="utf-8")
        unpacked = out_dir / "unpacked"
        (unpacked / "vendor").mkdir(parents=True)
        (unpacked / "0.js").write_text("m0", encoding="utf-8")
        (unpacked / "vendor" / "lib.js").write_text("lib", encoding="utf-8")
        # An empty directory webcrack sometimes leaves behind: a dir, not a file.
        (unpacked / "empty").mkdir()
    return "", "", 0


def _unpack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    monkeypatch.setattr(jsre_client, "_run", _tree_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    return client.unpack_bundle(bundle, tmp_path / "out", offset=0, limit=100)


_EXPECTED_FILES = [
    "deobfuscated.js",
    "unpacked/0.js",
    "unpacked/vendor/lib.js",
]


def test_nested_modules_are_listed_by_relative_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Files below the top level appear, named by their path under the root.

    ``unpacked/0.js`` and ``unpacked/vendor/lib.js`` must both be present with
    their directory prefixes. A non-recursive walk would drop them; ``path.name``
    would strip the prefixes.
    """
    result = _unpack(tmp_path, monkeypatch)
    assert result["files"] == _EXPECTED_FILES
    assert "unpacked/0.js" in result["files"]
    assert "unpacked/vendor/lib.js" in result["files"]
    # The relative paths carry the tree shape, not just basenames.
    assert any("/" in name for name in result["files"])


def test_directories_are_neither_counted_nor_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the three regular files count; the dirs (incl. empty) are skipped.

    ``unpacked``, ``unpacked/vendor`` and ``unpacked/empty`` are directories.
    Counting them would inflate ``file_count``/``total`` and leak bare directory
    names into ``files``.
    """
    result = _unpack(tmp_path, monkeypatch)
    assert result["file_count"] == 3
    assert result["total"] == 3
    assert result["count"] == 3
    for directory in ("unpacked", "unpacked/vendor", "unpacked/empty"):
        assert directory not in result["files"]


def test_the_listing_is_sorted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pagination leans on a stable order, so the listing comes out sorted."""
    result = _unpack(tmp_path, monkeypatch)
    assert result["files"] == sorted(result["files"])

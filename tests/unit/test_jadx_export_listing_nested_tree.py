"""jadx export_sources: how _capped_java_listing walks a real source tree.

The existing listing test lays 6 ``.java`` files flat and only checks the
counts (file_count 6, page 4, has_more True). A real jadx tree is nothing like
that -- every class sits at ``sources/<package path>/Name.java`` -- and the flat
fixture leaves the load-bearing parts of

    for path in root.rglob("*.java"):
        if not path.is_file():
            continue
        total += 1
        if len(names) < cap:
            names.append(str(path.relative_to(root)))
        ...
        if total >= _MAX_COUNTED_FILES:
            has_more = True
            break
    names.sort()

unexercised. It never proves the walk recurses more than one level, never proves
each entry keeps its package-relative path (rather than a bare filename an agent
cannot locate), never proves the is_file guard keeps a directory that happens to
end in ``.java`` out of the list, and never trips the count cap that stops a
runaway tree. An agent reads java_files to decide which class to open next, so a
collapsed path or a phantom entry is a wrong open.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx import client as jadx_client
from headless_re_mcp.backends.jadx.client import JadxClient


def _client(tmp_path: Path) -> JadxClient:
    tool = tmp_path / "jadx.bat"
    tool.write_text("x", encoding="utf-8")
    client = JadxClient(tool)
    client._run = lambda *a, **k: ("", "", 0)  # type: ignore[method-assign]
    return client


def test_the_walk_recurses_and_keeps_package_relative_paths_sorted(
    tmp_path: Path,
) -> None:
    """A multi-level tree, written out of order, must come back as sorted paths
    relative to the output dir -- ``sources/com/foo/A.java``, not ``A.java``.
    A non-recursive glob would see none of these (they are all nested), and a
    ``.name`` would strip the package an agent needs to find the class.
    """
    client = _client(tmp_path)
    out = tmp_path / "out"
    sources = out / "sources"
    (sources / "com" / "foo").mkdir(parents=True)
    (sources / "com" / "bar" / "baz").mkdir(parents=True)
    (sources / "com" / "bar" / "baz" / "B.java").write_text("class B{}", encoding="utf-8")
    (sources / "com" / "foo" / "A.java").write_text("class A{}", encoding="utf-8")
    (sources / "com" / "foo" / "Zeta.java").write_text("class Z{}", encoding="utf-8")

    payload = client.export_sources(tmp_path / "app.apk", out)

    assert payload["java_files"] == [
        "sources/com/bar/baz/B.java",
        "sources/com/foo/A.java",
        "sources/com/foo/Zeta.java",
    ]
    assert payload["java_file_count"] == 3
    assert payload["has_more"] is False


def test_a_directory_named_like_a_java_file_is_neither_counted_nor_listed(
    tmp_path: Path,
) -> None:
    """rglob("*.java") matches by name, so a directory ending in .java would slip
    in without the is_file guard -- and it is not a file an agent can open. Only
    the two real classes must count.
    """
    client = _client(tmp_path)
    out = tmp_path / "out"
    sources = out / "sources"
    sources.mkdir(parents=True)
    (sources / "Real.java").write_text("class Real{}", encoding="utf-8")
    (sources / "Also.java").write_text("class Also{}", encoding="utf-8")
    (sources / "NotAClass.java").mkdir()  # a directory that matches the glob

    payload = client.export_sources(tmp_path / "app.apk", out)

    assert payload["java_files"] == ["sources/Also.java", "sources/Real.java"]
    assert payload["java_file_count"] == 2
    assert "sources/NotAClass.java" not in payload["java_files"]


def test_the_count_cap_stops_a_runaway_tree_and_flags_has_more(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Beyond _MAX_COUNTED_FILES the walk must stop counting (not just stop
    listing) and flag has_more, so a pathological tree cannot spin the scan over
    tens of thousands of files. With the page cap left high, has_more can only
    come from the count cap -- isolating that branch.
    """
    monkeypatch.setattr(jadx_client, "_MAX_COUNTED_FILES", 5)
    client = _client(tmp_path)
    out = tmp_path / "out"
    sources = out / "sources"
    sources.mkdir(parents=True)
    for index in range(8):
        (sources / f"C{index}.java").write_text("x", encoding="utf-8")

    payload = client.export_sources(tmp_path / "app.apk", out)

    assert payload["java_file_count"] == 5
    assert len(payload["java_files"]) == 5
    assert payload["has_more"] is True

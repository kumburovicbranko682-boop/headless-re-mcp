"""js.unpack_bundle writes trees retention cannot see."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.core.service_jsre import (
    _MAX_JSRE_UNPACK_DIRS,
    JsReAnalysisMixin,
    prune_jsre_unpack_dirs,
)


def _fill_unpack(directory: Path, *, files: int = 100, size: int = 10 * 1024) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for index in range(files):
        (directory / f"mod-{index}.js").write_bytes(b"x" * size)


def test_prune_keeps_only_the_newest_unpack_trees(tmp_path: Path) -> None:
    root = tmp_path / "jsre"
    root.mkdir()
    for index in range(20):
        directory = root / f"unpack-{index:03d}"
        _fill_unpack(directory)
        os.utime(directory, (index + 1, index + 1))

    prune_jsre_unpack_dirs(root, keep=8)

    left = sorted(path.name for path in root.iterdir())
    assert left == [f"unpack-{index:03d}" for index in range(12, 20)]
    total = sum(path.stat().st_size for path in root.rglob("*.js"))
    assert total == 8 * 100 * 10 * 1024


class _FakeJs:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, object]:
        del path, timeout, offset, limit
        _fill_unpack(out_dir)
        return {"output_dir": str(out_dir), "file_count": 100, "files": []}


class _Harness(JsReAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, webcrack=None)


def test_an_unpack_loop_cannot_grow_jsre_without_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """20 unpacks of 100 x 10 KiB left 19.5 MiB. Retention never saw them."""
    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _FakeJs)
    harness = _Harness(tmp_path)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    for _ in range(20):
        result = harness.js_unpack_bundle(str(bundle))
        assert result.ok is True

    root = tmp_path / "jsre"
    dirs = [path for path in root.iterdir() if path.is_dir()]
    assert len(dirs) == _MAX_JSRE_UNPACK_DIRS
    total = sum(path.stat().st_size for path in root.rglob("*.js"))
    assert total == _MAX_JSRE_UNPACK_DIRS * 100 * 10 * 1024


def test_unpack_file_list_is_paged_and_says_what_it_left_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """files[:2000] with no has_more hid every name past the cap.

    2 000 typical paths encoded to 90 KiB; a page of 100 is 4.6 KiB.
    """
    from headless_re_mcp.backends.jsre import client as jsre_client
    from headless_re_mcp.backends.jsre.client import JsClient

    def fake_run(
        cmd: list[str], *, timeout: float, maximum: float = 0.0
    ) -> tuple[str, str, int]:
        del timeout, maximum
        out_dir = Path(cmd[cmd.index("-o") + 1])
        # webcrack creates its own -o directory and refuses a pre-existing one,
        # so unpack_bundle must hand it a leaf that does not yet exist.
        assert not out_dir.exists(), "unpack_bundle pre-created webcrack's -o dir"
        out_dir.mkdir(parents=True)
        for index in range(250):
            (out_dir / f"mod-{index:03d}.js").write_text("x", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    # Distinct fresh leaves per call: the same 250 deterministic names are
    # written each time, so the paged windows stay comparable without reusing a
    # directory webcrack would have refused.
    page = client.unpack_bundle(bundle, tmp_path / "out-a", offset=0, limit=10)
    assert page["count"] == 10
    assert page["total"] == 250
    assert page["file_count"] == 250
    assert page["has_more"] is True
    tail = client.unpack_bundle(bundle, tmp_path / "out-b", offset=240, limit=20)
    assert tail["count"] == 10
    assert tail["has_more"] is False
    assert set(page["files"]) & set(tail["files"]) == set()


def test_unpack_hands_webcrack_a_dir_it_can_create_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """webcrack 2.x exits 1 with "output directory already exists" if -o exists.

    unpack_bundle used to pre-create out_dir with ``mkdir(exist_ok=True)`` before
    handing that same path to ``webcrack -o``. Against webcrack 2.x every unpack
    then bailed before writing a file and surfaced as a ``backend_error`` with an
    empty tree. This fake stands in for webcrack -- refusing a pre-existing -o and
    otherwise creating it -- so the contract is pinned against the real CLI. The
    nested leaf also proves unpack_bundle makes the *parent* (webcrack needs it)
    without making the *leaf* (webcrack refuses it).
    """
    from headless_re_mcp.backends.jsre import client as jsre_client
    from headless_re_mcp.backends.jsre.client import JsClient

    def fake_webcrack(
        cmd: list[str], *, timeout: float, maximum: float = 0.0
    ) -> tuple[str, str, int]:
        del timeout, maximum
        out_dir = Path(cmd[cmd.index("-o") + 1])
        if out_dir.exists():
            return "", "output directory already exists", 1
        out_dir.mkdir(parents=True)
        (out_dir / "deobfuscated.js").write_text("x", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_webcrack)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    out = tmp_path / "jsre" / "unpack-deadbeef"
    result = client.unpack_bundle(bundle, out, offset=0, limit=10)

    assert result["file_count"] == 1
    assert result["files"] == ["deobfuscated.js"]
    assert "tool_failed" not in result
    assert "exit_code" not in result


@pytest.mark.parametrize(
    ("files_written", "listing_truncated"),
    [(5, False), (6, True)],
)
def test_bounded_unpack_listing_finishes_at_the_last_readable_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    files_written: int,
    listing_truncated: bool,
) -> None:
    from headless_re_mcp.backends.jsre import client as jsre_client
    from headless_re_mcp.backends.jsre.client import JsClient

    monkeypatch.setattr(jsre_client, "_MAX_COUNTED_FILES", 5)

    def fake_run(
        cmd: list[str], *, timeout: float, maximum: float = 0.0
    ) -> tuple[str, str, int]:
        del timeout, maximum
        out_dir = Path(cmd[cmd.index("-o") + 1])
        assert not out_dir.exists(), "unpack_bundle pre-created webcrack's -o dir"
        out_dir.mkdir(parents=True)
        for index in range(files_written):
            (out_dir / f"mod-{index}.js").write_text("x", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))

    tail = client.unpack_bundle(bundle, tmp_path / "out", offset=5, limit=10)

    assert tail["total"] == 5
    assert tail["count"] == 0
    assert tail["has_more"] is False
    assert tail["listing_truncated"] is listing_truncated

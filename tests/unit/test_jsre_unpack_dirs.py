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
        # webcrack creates the output directory itself; the client only ensures
        # the parent exists. Mirror the real CLI so the stub creates the leaf.
        out_dir.mkdir(parents=True, exist_ok=True)
        if not any(out_dir.iterdir()):
            for index in range(250):
                (out_dir / f"mod-{index:03d}.js").write_text("x", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    out = tmp_path / "out"
    client = JsClient(executable=Path("/bin/true"))
    page = client.unpack_bundle(bundle, out, offset=0, limit=10)
    assert page["count"] == 10
    assert page["total"] == 250
    assert page["file_count"] == 250
    assert page["has_more"] is True
    tail = client.unpack_bundle(bundle, out, offset=240, limit=20)
    assert tail["count"] == 10
    assert tail["has_more"] is False
    assert set(page["files"]) & set(tail["files"]) == set()


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
        # webcrack creates the output directory itself; the client only ensures
        # the parent exists. Mirror the real CLI so the stub creates the leaf.
        out_dir.mkdir(parents=True, exist_ok=True)
        if not any(out_dir.iterdir()):
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

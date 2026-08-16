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
        self, path: Path, out_dir: Path, *, timeout: float = 300.0
    ) -> dict[str, object]:
        del path, timeout
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

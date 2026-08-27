"""File listings must be bounded by encoded size, not only by a count cap.

``jadx.export_sources`` (java_files) and ``jsre.unpack_bundle`` (files) return up
to 2000 relative paths. Each path is short, but a deep tree's paths can sum past
the result budget, and the transport then discards the *whole* result -- the
paths plus output_dir and the counts -- for a ~16 KiB summary. The count cap
alone cannot prevent that because the per-path size is what varies. These pin
that both clients trim the list to the encoded budget and keep ``has_more`` (and
jsre's ``listing_truncated``) honest, with the module budget shrunk so a small
mocked tree is forced to overflow -- no real jadx/webcrack needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.common import json_budget
from headless_re_mcp.backends.jadx.client import JadxClient
from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient


def _shrink_budget(monkeypatch: pytest.MonkeyPatch) -> int:
    """Force a tiny listing to overflow; return the encoded target to assert on."""
    monkeypatch.setattr(json_budget, "RESULT_BUDGET_BYTES", 1024)
    monkeypatch.setattr(json_budget, "_FIELD_RESERVE_BYTES", 256)
    return 1024 - 256


def _write_many_java(root: Path, count: int) -> None:
    for i in range(count):
        pkg = root / "sources" / "com" / "example" / f"pkg{i:04d}"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / f"GeneratedClass{i:04d}.java").write_text("class X {}", encoding="utf-8")


def _write_many_files(root: Path, count: int) -> None:
    for i in range(count):
        d = root / "modules" / f"chunk{i:04d}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"module{i:04d}.js").write_text("x", encoding="utf-8")


def test_export_sources_trims_java_files_to_the_encoded_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _shrink_budget(monkeypatch)
    client = JadxClient(tmp_path / "jadx")
    out = tmp_path / "out"

    def fake_run(
        apk: Path, extra: list[str], out_dir: Path, *, timeout: float
    ) -> tuple[str, str, int]:
        _write_many_java(out_dir, 60)
        return "", "", 0

    monkeypatch.setattr(client, "_run", fake_run)
    result = client.export_sources(tmp_path / "app.apk", out)

    # The full count is still reported, but the returned list is shorter and
    # has_more says so -- rather than the whole export being nuked to a summary.
    assert result["java_file_count"] == 60
    assert 0 < len(result["java_files"]) < 60
    assert result["has_more"] is True
    encoded = len(json.dumps(result["java_files"], ensure_ascii=False).encode("utf-8"))
    assert encoded <= target


def test_export_sources_small_tree_lists_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    out = tmp_path / "out"

    def fake_run(
        apk: Path, extra: list[str], out_dir: Path, *, timeout: float
    ) -> tuple[str, str, int]:
        _write_many_java(out_dir, 3)
        return "", "", 0

    monkeypatch.setattr(client, "_run", fake_run)
    result = client.export_sources(tmp_path / "app.apk", out)
    assert result["java_file_count"] == 3
    assert len(result["java_files"]) == 3
    assert result["has_more"] is False


def test_unpack_bundle_trims_files_to_the_encoded_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _shrink_budget(monkeypatch)

    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        out_dir = Path(cmd[cmd.index("-o") + 1])
        _write_many_files(out_dir, 60)
        return "", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    client = JsClient(executable=Path("/bin/true"))
    src = tmp_path / "bundle.js"
    src.write_text("payload", encoding="utf-8")
    # Ask for the whole listing; the count cap would allow all 60, so only the
    # encoded bound can force the trim.
    result = client.unpack_bundle(src, tmp_path / "out", limit=2000)

    assert result["file_count"] == 60
    assert 0 < len(result["files"]) < 60
    assert result["count"] == len(result["files"])
    # A budget-trimmed window means there is more to fetch, and paging must work.
    assert result["has_more"] is True
    assert result["listing_truncated"] is True
    encoded = len(json.dumps(result["files"], ensure_ascii=False).encode("utf-8"))
    assert encoded <= target

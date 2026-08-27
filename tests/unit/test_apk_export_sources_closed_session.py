"""A retained CLOSED session must not start jadx export_sources."""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _TrackingJadx:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.exports: list[Path] = []

    def export_sources(
        self,
        apk: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        no_imports: bool = False,
        offset: int = 0,
        limit: int | None = None,
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        marker = out_dir / "jadx-export-started"
        marker.write_text("started", encoding="utf-8")
        self.exports.append(marker)
        return {
            "output_dir": str(out_dir),
            "sources_dir": str(out_dir / "sources"),
            "java_file_count": 1,
            "java_files": ["A.java"],
            "count": 1,
            "offset": offset,
        }


def test_apk_export_sources_on_a_closed_session_does_not_start_jadx(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A retained CLOSED session still resolved, so a late export wrote a tree.

    Measured: after close_session, apk.export_sources returned ok=True, jadx
    ran once, and artifact_root/jadx/<id>/jadx-export-started was written.
    close_all left that tree in place because close already ran
    _forget_session_work_dirs. The model then treats the dead session as
    exported.
    """
    tracker = _TrackingJadx()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.JadxClient",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.exports == []
        tree = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not tree.exists()
    finally:
        service.close_all()


def test_apk_export_sources_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close mid-export used to keep the tree after _forget_session_work_dirs."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")

    class _CloseThenExport(_TrackingJadx):
        def export_sources(
            self,
            apk: Path,
            out_dir: Path,
            *,
            timeout: float = 300.0,
            no_imports: bool = False,
            offset: int = 0,
            limit: int | None = None,
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return super().export_sources(
                apk, out_dir, timeout=timeout, no_imports=no_imports, offset=offset, limit=limit
            )

    tracker = _CloseThenExport()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.JadxClient",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        tree = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not tree.exists()
    finally:
        service.close_all()

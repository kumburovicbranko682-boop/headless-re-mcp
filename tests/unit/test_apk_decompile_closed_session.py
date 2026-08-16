"""A retained CLOSED session must not start jadx decompile."""

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
        self.decompile_calls: list[Path] = []

    def decompile(
        self,
        binary: Path,
        out_dir: Path,
        class_name: str,
        *,
        timeout: float = 300.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        marker = out_dir / "jadx-started"
        marker.write_text("started", encoding="utf-8")
        self.decompile_calls.append(marker)
        return {
            "class_name": class_name,
            "path": str(marker),
            "source": "class X {}",
        }


def test_apk_decompile_on_a_closed_session_does_not_start_jadx(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A retained CLOSED session still resolved, so a late decompile started jadx.

    Measured: after close_session, apk.decompile returned ok=True, decompile
    ran once, and artifact_root/jadx/<id>/jadx-started was written. session.close
    cannot reap a jadx run that started after it returned. The model then treats
    the dead session as decompiled and pays apk.export_sources another import.
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

        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.decompile_calls == []
        project = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not project.exists()
    finally:
        service.close_all()


def test_apk_decompile_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close mid-decompile used to keep the tree after _forget_session_work_dirs."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")

    class _CloseThenDecompile(_TrackingJadx):
        def decompile(  # type: ignore[override]
            self,
            binary: Path,
            out_dir: Path,
            class_name: str,
            *,
            timeout: float = 300.0,
            **kwargs: object,
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return super().decompile(
                binary, out_dir, class_name, timeout=timeout, **kwargs
            )

    tracker = _CloseThenDecompile()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.JadxClient",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        project = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not project.exists()
    finally:
        service.close_all()

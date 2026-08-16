"""A retained CLOSED session must not parse an APK as if it were still open."""

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


class _TrackingApk:
    def __init__(self) -> None:
        self.opens = 0

    def open(self, path: Path) -> dict[str, Any]:
        del path
        self.opens += 1
        return {"package": "a.b", "opened": True}


def test_apk_open_on_a_closed_session_does_not_parse(tmp_path: Path, monkeypatch: Any) -> None:
    """A retained CLOSED session still resolved, so a late open parsed the APK.

    Measured: after close_session, apk.open returned ok=True and ApkClient.open
    ran once. The model then treats the dead session as bound to androguard
    and follows with apk.classes / apk.decompile.
    """
    tracker = _TrackingApk()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.ApkClient",
        lambda: tracker,
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

        result = service.apk_open(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.opens == 0
    finally:
        service.close_all()


def test_apk_open_does_not_report_success_if_the_session_closes_during_parse(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close mid-parse used to record androguard on a session that cannot use it."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")

    class _CloseThenOpen(_TrackingApk):
        def open(self, path: Path) -> dict[str, Any]:
            service.close_session(session_id)
            return super().open(path)

    tracker = _CloseThenOpen()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.ApkClient",
        lambda: tracker,
    )
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_open(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()